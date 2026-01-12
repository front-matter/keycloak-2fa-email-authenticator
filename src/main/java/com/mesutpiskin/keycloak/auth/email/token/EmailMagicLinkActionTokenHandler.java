package com.mesutpiskin.keycloak.auth.email.token;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.util.ResolveRelative;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Handles the email magic link action token.
 * <p>
 * This handler processes the action token, validates it, and completes
 * the authentication flow by logging the user in and redirecting to
 * the appropriate location.
 * </p>
 *
 * @author Mesut Pişkin
 * @version 26.1.0
 * @since 26.1.0
 */
public class EmailMagicLinkActionTokenHandler
    extends AbstractActionTokenHandler<EmailMagicLinkActionToken> {

  private static final Logger logger = Logger.getLogger(EmailMagicLinkActionTokenHandler.class);

  public EmailMagicLinkActionTokenHandler() {
    super(
        EmailMagicLinkActionToken.TOKEN_TYPE,
        EmailMagicLinkActionToken.class,
        Messages.INVALID_REQUEST,
        EventType.EXECUTE_ACTION_TOKEN,
        Errors.INVALID_REQUEST);
  }

  @Override
  public AuthenticationSessionModel startFreshAuthenticationSession(
      EmailMagicLinkActionToken token,
      ActionTokenContext<EmailMagicLinkActionToken> tokenContext) {
    return tokenContext.createAuthenticationSessionForClient(token.getIssuedFor());
  }

  @Override
  public Response handleToken(
      EmailMagicLinkActionToken token,
      ActionTokenContext<EmailMagicLinkActionToken> tokenContext) {
    logger.debugf("handleToken for client:%s, user:%s", token.getIssuedFor(), token.getUserId());

    UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
    final AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
    final ClientModel client = authSession.getClient();

    // Resolve redirect URI
    final String redirectUri = token.getRedirectUri() != null
        ? token.getRedirectUri()
        : ResolveRelative.resolveRelativeUri(
            tokenContext.getSession(), client.getRootUrl(), client.getBaseUrl());
    logger.debugf("Using redirect_uri %s", redirectUri);

    // Validate redirect URI
    String redirect = RedirectUtils.verifyRedirectUri(
        tokenContext.getSession(), redirectUri, client);
    if (redirect != null) {
      authSession.setAuthNote(
          AuthenticationManager.SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS, "true");
      authSession.setRedirectUri(redirect);
      authSession.setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, redirectUri);

      // Set OAuth2/OIDC parameters
      if (token.getState() != null) {
        authSession.setClientNote(OIDCLoginProtocol.STATE_PARAM, token.getState());
      }
      if (token.getNonce() != null) {
        authSession.setClientNote(OIDCLoginProtocol.NONCE_PARAM, token.getNonce());
      }
      if (token.getScope() != null) {
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, token.getScope());
      }
      if (token.getCodeChallenge() != null) {
        authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM, token.getCodeChallenge());
      }
      if (token.getCodeChallengeMethod() != null) {
        authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM,
            token.getCodeChallengeMethod());
      }
      if (token.getResponseMode() != null) {
        authSession.setClientNote(OIDCLoginProtocol.RESPONSE_MODE_PARAM, token.getResponseMode());
      }
    }

    // Set email as verified since user clicked link in email
    user.setEmailVerified(true);

    // Proceed with authentication flow
    String nextAction = AuthenticationManager.nextRequiredAction(
        tokenContext.getSession(),
        authSession,
        tokenContext.getRequest(),
        tokenContext.getEvent());

    return AuthenticationManager.redirectToRequiredActions(
        tokenContext.getSession(),
        tokenContext.getRealm(),
        authSession,
        tokenContext.getUriInfo(),
        nextAction);
  }
}

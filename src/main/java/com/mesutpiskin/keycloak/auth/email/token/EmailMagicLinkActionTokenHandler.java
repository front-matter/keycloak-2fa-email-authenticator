package com.mesutpiskin.keycloak.auth.email.token;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
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
    AuthenticationSessionModel authSession = tokenContext.createAuthenticationSessionForClient(token.getIssuedFor());

    // Set essential OIDC protocol parameters immediately
    if (token.getRedirectUri() != null) {
      authSession.setRedirectUri(token.getRedirectUri());
      authSession.setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, token.getRedirectUri());
    }

    // Set response_type to "code" for OIDC authorization code flow
    authSession.setClientNote(OIDCLoginProtocol.RESPONSE_TYPE_PARAM, "code");

    if (token.getScope() != null) {
      authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, token.getScope());
    }

    if (token.getState() != null) {
      authSession.setClientNote(OIDCLoginProtocol.STATE_PARAM, token.getState());
    }

    if (token.getNonce() != null) {
      authSession.setClientNote(OIDCLoginProtocol.NONCE_PARAM, token.getNonce());
    }

    if (token.getCodeChallenge() != null) {
      authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM, token.getCodeChallenge());
    }

    if (token.getCodeChallengeMethod() != null) {
      authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM, token.getCodeChallengeMethod());
    }

    if (token.getResponseMode() != null) {
      authSession.setClientNote(OIDCLoginProtocol.RESPONSE_MODE_PARAM, token.getResponseMode());
    }

    logger.infof("Created fresh auth session for client:%s with redirect_uri:%s",
        token.getIssuedFor(), token.getRedirectUri());

    return authSession;
  }

  @Override
  public Response handleToken(
      EmailMagicLinkActionToken token,
      ActionTokenContext<EmailMagicLinkActionToken> tokenContext) {
    logger.infof("handleToken for client:%s, user:%s", token.getIssuedFor(), token.getUserId());

    final AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
    final ClientModel client = authSession.getClient();

    // Get user from token and set as authenticated
    UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
    if (user == null) {
      logger.infof("User not set in auth session, loading from token userId: %s", token.getUserId());
      user = tokenContext.getSession().users().getUserById(tokenContext.getRealm(), token.getUserId());
      if (user == null) {
        logger.errorf("User not found: %s", token.getUserId());
        return tokenContext.getSession().getProvider(LoginFormsProvider.class)
            .setError(Messages.INVALID_USER)
            .createErrorPage(Response.Status.BAD_REQUEST);
      }
      authSession.setAuthenticatedUser(user);
    }

    // Set email as verified since user clicked link in email
    user.setEmailVerified(true);

    logger.infof("Email verified for user: %s, proceeding with authentication", user.getUsername());

    // OAuth2/OIDC parameters should already be set in
    // startFreshAuthenticationSession
    // but we'll ensure they're present
    if (token.getRedirectUri() != null && authSession.getRedirectUri() == null) {
      String redirect = RedirectUtils.verifyRedirectUri(
          tokenContext.getSession(), token.getRedirectUri(), client);
      if (redirect == null) {
        logger.errorf("Invalid redirect URI: %s", token.getRedirectUri());
        return tokenContext.getSession().getProvider(LoginFormsProvider.class)
            .setError(Messages.INVALID_REDIRECT_URI)
            .createErrorPage(Response.Status.BAD_REQUEST);
      }
      authSession.setRedirectUri(redirect);
      authSession.setAuthNote(AuthenticationManager.SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS, "true");
    }

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

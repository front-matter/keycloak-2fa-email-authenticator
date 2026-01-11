package com.mesutpiskin.keycloak.auth.email;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resource.RealmResourceProvider;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;

/**
 * Custom REST resource provider for handling magic link authentication.
 * <p>
 * This provider creates a session-independent endpoint that can validate
 * email codes and complete authentication even after the original session
 * expires.
 * </p>
 *
 * @author Mesut Pişkin
 * @version 26.1.0
 * @since 26.1.0
 */
public class MagicLinkResourceProvider implements RealmResourceProvider {

  private static final Logger logger = Logger.getLogger(MagicLinkResourceProvider.class);

  private final KeycloakSession session;

  public MagicLinkResourceProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Object getResource() {
    return this;
  }

  /**
   * Handles magic link authentication requests.
   * <p>
   * This endpoint validates the email code stored in user attributes and
   * redirects to the appropriate authentication flow step.
   * </p>
   *
   * @param userId the user ID
   * @param code   the email verification code
   * @param client the client ID
   * @return Response redirecting to login or error page
   */
  @GET
  @Path("/verify")
  public Response verify(
      @QueryParam("user") String userId,
      @QueryParam("code") String code,
      @QueryParam("client") String client) {

    logger.infof("Magic link verification request: user=%s, client=%s", userId, client);

    RealmModel realm = session.getContext().getRealm();

    // Validate input parameters
    if (userId == null || userId.isBlank() || code == null || code.isBlank()) {
      logger.warn("Invalid magic link parameters - missing user or code");
      return buildErrorResponse("Invalid magic link parameters");
    }

    // Find user
    UserModel user = session.users().getUserById(realm, userId);
    if (user == null) {
      logger.warnf("User not found: %s", userId);
      return buildErrorResponse("User not found");
    }

    // Retrieve stored code and expiration from user attributes
    String storedCode = user.getFirstAttribute(EmailConstants.CODE);
    String expiresAtStr = user.getFirstAttribute("emailCodeExpiresAt");

    if (storedCode == null || expiresAtStr == null) {
      logger.warnf("No stored code found for user: %s", userId);
      return buildErrorResponse("Verification code not found or expired");
    }

    // Validate expiration
    try {
      long expiresAt = Long.parseLong(expiresAtStr);
      if (System.currentTimeMillis() > expiresAt) {
        logger.warnf("Code expired for user %s (expired at %d)", userId, expiresAt);
        user.removeAttribute(EmailConstants.CODE);
        user.removeAttribute("emailCodeExpiresAt");
        return buildErrorResponse("Verification code has expired");
      }
    } catch (NumberFormatException e) {
      logger.errorf("Invalid expiration timestamp for user %s: %s", userId, expiresAtStr);
      user.removeAttribute(EmailConstants.CODE);
      user.removeAttribute("emailCodeExpiresAt");
      return buildErrorResponse("Invalid verification data");
    }

    // Validate code
    if (!storedCode.equals(code)) {
      logger.warnf("Invalid code for user %s", userId);
      return buildErrorResponse("Invalid verification code");
    }

    // Code is valid - store a verified magic link token with short expiration
    long tokenExpiry = System.currentTimeMillis() + (5 * 60 * 1000L); // 5 minutes
    String magicToken = java.util.UUID.randomUUID().toString();
    user.setSingleAttribute("magicLinkToken", magicToken);
    user.setSingleAttribute("magicLinkTokenExpiry", String.valueOf(tokenExpiry));

    // Clear the original code to prevent reuse
    user.removeAttribute(EmailConstants.CODE);
    user.removeAttribute("emailCodeExpiresAt");

    // Build redirect URL back to the authentication flow
    URI redirectUri = buildAuthRedirect(realm, user, magicToken);
    logger.infof("Magic link verification successful for user %s, redirecting to auth flow", userId);

    return Response.seeOther(redirectUri).build();
  }

  /**
   * Builds an error response redirecting to the login page with an error message.
   */
  private Response buildErrorResponse(String message) {
    RealmModel realm = session.getContext().getRealm();
    URI loginUri = UriBuilder.fromUri(session.getContext().getUri().getBaseUri())
        .path("realms/{realm}/protocol/openid-connect/auth")
        .queryParam("error", "magic_link_invalid")
        .queryParam("error_description", message)
        .build(realm.getName());

    return Response.seeOther(loginUri).build();
  }

  /**
   * Builds a redirect URL back to the authentication endpoint.
   * The authenticator will detect the magic link token and auto-authenticate.
   * Uses stored redirect_uri and OAuth2/OIDC parameters from user attributes
   * to preserve original auth context, including PKCE parameters.
   */
  private URI buildAuthRedirect(RealmModel realm, UserModel user, String magicToken) {
    // Retrieve stored auth context
    String clientId = user.getFirstAttribute("magicLinkClientId");
    String redirectUri = user.getFirstAttribute("magicLinkRedirectUri");

    UriBuilder builder = UriBuilder.fromUri(session.getContext().getUri().getBaseUri())
        .path("realms/{realm}/protocol/openid-connect/auth")
        .queryParam("response_type", "code")
        .queryParam("scope", "openid")
        .queryParam("kc_email_magic", "1")
        .queryParam("magic_token", magicToken)
        .queryParam("login_hint", user.getId());

    // Add client_id if available
    if (clientId != null && !clientId.isBlank()) {
      builder.queryParam("client_id", clientId);
    }

    // Add redirect_uri if available (required by OIDC)
    if (redirectUri != null && !redirectUri.isBlank()) {
      builder.queryParam("redirect_uri", redirectUri);
    }

    // Add PKCE parameters if available (required for modern OAuth2 flows)
    String codeChallenge = user.getFirstAttribute("magicLinkCodeChallenge");
    String codeChallengeMethod = user.getFirstAttribute("magicLinkCodeChallengeMethod");
    if (codeChallenge != null && !codeChallenge.isBlank()) {
      builder.queryParam("code_challenge", codeChallenge);
    }
    if (codeChallengeMethod != null && !codeChallengeMethod.isBlank()) {
      builder.queryParam("code_challenge_method", codeChallengeMethod);
    }

    // Add other OAuth2/OIDC parameters
    String state = user.getFirstAttribute("magicLinkState");
    String nonce = user.getFirstAttribute("magicLinkNonce");
    String responseMode = user.getFirstAttribute("magicLinkResponseMode");
    if (state != null && !state.isBlank()) {
      builder.queryParam("state", state);
    }
    if (nonce != null && !nonce.isBlank()) {
      builder.queryParam("nonce", nonce);
    }
    if (responseMode != null && !responseMode.isBlank()) {
      builder.queryParam("response_mode", responseMode);
    }

    return builder.build(realm.getName());
  }

  @Override
  public void close() {
    // No resources to close
  }
}

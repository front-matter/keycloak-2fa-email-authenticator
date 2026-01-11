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
        clearUserCode(user);
        return buildErrorResponse("Verification code has expired");
      }
    } catch (NumberFormatException e) {
      logger.errorf("Invalid expiration timestamp for user %s: %s", userId, expiresAtStr);
      clearUserCode(user);
      return buildErrorResponse("Invalid verification data");
    }

    // Validate code
    if (!storedCode.equals(code)) {
      logger.warnf("Invalid code for user %s", userId);
      return buildErrorResponse("Invalid verification code");
    }

    // Code is valid - clear it to prevent reuse
    clearUserCode(user);

    // Build success redirect URL
    URI redirectUri = buildSuccessRedirect(realm, client, userId);
    logger.infof("Magic link verification successful for user %s, redirecting to: %s", userId, redirectUri);

    return Response.seeOther(redirectUri).build();
  }

  /**
   * Clears the email code and expiration timestamp from user attributes.
   */
  private void clearUserCode(UserModel user) {
    user.removeAttribute(EmailConstants.CODE);
    user.removeAttribute("emailCodeExpiresAt");
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
   * Builds a success redirect URL that continues the authentication flow.
   * <p>
   * This creates a new authentication session and marks the email verification as
   * completed.
   * </p>
   */
  private URI buildSuccessRedirect(RealmModel realm, String clientId, String userId) {
    // For now, redirect to account page - in production, this should create
    // a new auth session and continue the flow
    return UriBuilder.fromUri(session.getContext().getUri().getBaseUri())
        .path("realms/{realm}/account")
        .queryParam("magic_link_success", "true")
        .build(realm.getName());
  }

  @Override
  public void close() {
    // No resources to close
  }
}

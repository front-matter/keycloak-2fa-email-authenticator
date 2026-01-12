package com.mesutpiskin.keycloak.auth.email.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import org.keycloak.authentication.actiontoken.DefaultActionToken;

/**
 * Action token for email-based magic link authentication.
 * <p>
 * This token encodes all necessary OAuth2/OIDC parameters to complete
 * the authentication flow after clicking the magic link.
 * </p>
 *
 * @author Mesut Pişkin
 * @version 26.1.0
 * @since 26.1.0
 */
@JsonTypeName(EmailMagicLinkActionToken.TOKEN_TYPE)
public class EmailMagicLinkActionToken extends DefaultActionToken {

  public static final String TOKEN_TYPE = "email-magic-link";

  private static final String JSON_FIELD_REDIRECT_URI = "rdu";
  private static final String JSON_FIELD_SCOPE = "scope";
  private static final String JSON_FIELD_STATE = "state";
  private static final String JSON_FIELD_NONCE = "nonce";
  private static final String JSON_FIELD_CODE_CHALLENGE = "cc";
  private static final String JSON_FIELD_CODE_CHALLENGE_METHOD = "ccm";
  private static final String JSON_FIELD_RESPONSE_MODE = "rm";

  @JsonProperty(value = JSON_FIELD_REDIRECT_URI)
  private String redirectUri;

  @JsonProperty(value = JSON_FIELD_SCOPE)
  private String scope;

  @JsonProperty(value = JSON_FIELD_STATE)
  private String state;

  @JsonProperty(value = JSON_FIELD_NONCE)
  private String nonce;

  @JsonProperty(value = JSON_FIELD_CODE_CHALLENGE)
  private String codeChallenge;

  @JsonProperty(value = JSON_FIELD_CODE_CHALLENGE_METHOD)
  private String codeChallengeMethod;

  @JsonProperty(value = JSON_FIELD_RESPONSE_MODE)
  private String responseMode;

  public EmailMagicLinkActionToken(
      String userId,
      int absoluteExpirationInSecs,
      String clientId,
      String redirectUri,
      String scope,
      String nonce,
      String state,
      String codeChallenge,
      String codeChallengeMethod,
      String responseMode) {
    super(userId, TOKEN_TYPE, absoluteExpirationInSecs, null);
    this.issuedFor = clientId;
    this.redirectUri = redirectUri;
    this.scope = scope;
    this.nonce = nonce;
    this.state = state;
    this.codeChallenge = codeChallenge;
    this.codeChallengeMethod = codeChallengeMethod;
    this.responseMode = responseMode;
  }

  public EmailMagicLinkActionToken() {
    // Required for Jackson deserialization - must be public
    super();
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public void setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public String getScope() {
    return scope;
  }

  public void setScope(String scope) {
    this.scope = scope;
  }

  public String getState() {
    return state;
  }

  public void setState(String state) {
    this.state = state;
  }

  public String getNonce() {
    return nonce;
  }

  public void setNonce(String nonce) {
    this.nonce = nonce;
  }

  public String getCodeChallenge() {
    return codeChallenge;
  }

  public void setCodeChallenge(String codeChallenge) {
    this.codeChallenge = codeChallenge;
  }

  public String getCodeChallengeMethod() {
    return codeChallengeMethod;
  }

  public void setCodeChallengeMethod(String codeChallengeMethod) {
    this.codeChallengeMethod = codeChallengeMethod;
  }

  public String getResponseMode() {
    return responseMode;
  }

  public void setResponseMode(String responseMode) {
    this.responseMode = responseMode;
  }
}

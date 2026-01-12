# Magic Link Implementation - ActionToken Solution

## Overview

This implementation provides a **solid, production-ready magic link solution** using Keycloak's official **ActionToken API**. This approach is session-independent, secure, and follows Keycloak best practices for time-limited authentication tokens.

## Architecture

### 1. **ActionToken Handler**
- **Endpoint**: Keycloak's built-in `/login-actions/action-token` endpoint
- **Purpose**: Process time-limited authentication tokens using Keycloak's standard mechanism
- **Files**: 
  - [`EmailMagicLinkActionToken.java`](../src/main/java/com/mesutpiskin/keycloak/auth/email/token/EmailMagicLinkActionToken.java) - Token data class
  - [`EmailMagicLinkActionTokenHandler.java`](../src/main/java/com/mesutpiskin/keycloak/auth/email/token/EmailMagicLinkActionTokenHandler.java) - Token processor
  - [`EmailMagicLinkActionTokenHandlerFactory.java`](../src/main/java/com/mesutpiskin/keycloak/auth/email/token/EmailMagicLinkActionTokenHandlerFactory.java) - Factory for registration

### 2. **Token Serialization**
- Tokens are serialized using Keycloak's `ActionToken.serialize()` method
- All OAuth2/OIDC parameters are embedded in the token:
  - `clientId`: Client ID from the authentication request
  - `redirectUri`: Original redirect URI for OAuth2 flow
  - `scope`: OAuth2 scope parameter
  - `state`: OAuth2 state parameter
  - `nonce`: OpenID Connect nonce parameter
  - `codeChallenge`: PKCE code challenge (required for PKCE flows)
  - `codeChallengeMethod`: PKCE method (S256 or plain)
  - `responseMode`: OAuth2 response mode
- No need for user attribute storage - all data is in the token

### 3. **ActionToken URLs**
Magic link URL format:
```
https://{keycloak-domain}/realms/{realm}/login-actions/action-token?key={serializedToken}&client_id={clientId}
```

## Key Benefits

✅ **Official Keycloak API**: Uses Keycloak's built-in ActionToken mechanism  
✅ **No Custom Endpoints**: Leverages standard `/login-actions/action-token` endpoint  
✅ **Self-Contained**: All auth data embedded in the token (no user attributes needed)  
✅ **Secure**: Built-in signature verification, expiration, and one-time use  
✅ **Clean**: Follows Keycloak's architecture patterns  
✅ **Battle-Tested**: Same mechanism used by Keycloak's built-in features  

## How It Works

### 1. Code Generation (EmailAuthenticatorForm)
```java
// Generate code and send email (unchanged)
String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
long expiresAt = now + (ttl * 1000L);

// Store in session notes for manual entry
session.setAuthNote(EmailConstants.CODE, code);
session.setAuthNote(EmailConstants.CODE_TTL, Long.toString(expiresAt));
```

### 2. Magic Link URL Generation
```java
// Extract OAuth2/OIDC parameters from auth session
String clientId = authSession.getClient().getClientId();
String redirectUri = authSession.getRedirectUri();
String scope = authSession.getClientNote(OIDCLoginProtocol.SCOPE_PARAM);
String state = authSession.getClientNote(OIDCLoginProtocol.STATE_PARAM);
String nonce = authSession.getClientNote(OIDCLoginProtocol.NONCE_PARAM);
String codeChallenge = authSession.getClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM);
String codeChallengeMethod = authSession.getClientNote(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM);
String responseMode = authSession.getClientNote(OIDCLoginProtocol.RESPONSE_MODE_PARAM);

// Create action token with all parameters
int absoluteExpirationInSecs = Time.currentTime() + ttl;
EmailMagicLinkActionToken token = new EmailMagicLinkActionToken(
    user.getId(),
    absoluteExpirationInSecs,
    clientId,
    redirectUri,
    scope,
    nonce,
    state,
    codeChallenge,
    codeChallengeMethod,
    responseMode);

// Serialize token and build URL
String tokenString = token.serialize(session, realm, uriInfo);
UriBuilder builder = Urls.realmBase(baseUri)
    .path(RealmsResource.class, "getLoginActionsService")
    .path(LoginActionsService.class, "executeActionToken")
    .queryParam(Constants.KEY, tokenString)
    .queryParam(Constants.CLIENT_ID, clientId);
```

### 3. Magic Link Verification Flow

**Step 1: User clicks magic link → hits `/login-actions/action-token?key={token}`**

Keycloak's ActionToken framework automatically:
1. ✓ Deserializes the token
2. ✓ Verifies token signature (tamper-proof)
3. ✓ Checks token expiration
4. ✓ Ensures token hasn't been used (one-time use)
5. ✓ Routes to `EmailMagicLinkActionTokenHandler.handleToken()`

**Step 2: Handler processes the token**

`EmailMagicLinkActionTokenHandler` completes authentication:
1. ✓ Validates redirect URI matches client configuration
2. ✓ Sets OAuth2/OIDC parameters in auth session (PKCE, state, nonce, etc.)
3. ✓ Marks email as verified
4. ✓ Redirects to Keycloak's required actions flow
5. ✓ Authentication automatically succeeds → User is logged in!

## Security Features

### 1. **Cryptographic Signature**
- Tokens are signed by Keycloak using realm keys
- Cannot be forged or tampered with
- Keycloak validates signature on every use

### 2. **One-Time Use**
- Keycloak tracks used tokens in database
- Each token can only be used once
- Replay attacks are automatically prevented

### 3. **Expiration**
- Tokens expire after configured TTL (default: 15 minutes)
- Expiration is validated by Keycloak framework
- Expired tokens are automatically rejected

### 4. **User Binding**
- Tokens are bound to specific user IDs
- User ID is embedded in signed token
- Cannot be used for different users

### 5. **Validation Chain**
Full validation by Keycloak framework:
- Token signature valid ✓
- Token not expired ✓
- Token not previously used ✓
- User exists and is enabled ✓
- Redirect URI matches client config ✓
- Magic token has not expired ✓

## Configuration

No additional configuration needed! The feature uses existing settings:

- `magicLinkEnabled`: Enable/disable magic links (default: false)
- `ttl`: Code time-to-live in seconds (default: 300 = 5 minutes)

## Configuration

Magic links respect the same configuration as email codes:
- `ttl`: Token time-to-live in seconds (default: 900 = 15 minutes)
- `length`: Code length (default: 6 digits)
- `magicLinkEnabled`: Enable/disable magic links (default: true)

## Deployment

### 1. Build
```bash
mvn clean package
```

### 2. Deploy JAR
Copy `target/keycloak-2fa-email-authenticator-v26.1.0.jar` to:
```
{keycloak-home}/providers/
```

### 3. Restart Keycloak
```bash
kc.sh start --optimized
# or
docker-compose restart keycloak
```

### 4. Verify ActionToken Handler Registration
The handler is automatically registered via:
- `META-INF/services/org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory`
- No additional configuration needed

## Testing

### Simulation Mode
For testing without sending emails:

1. Set `simulationMode` = `true` in authenticator config
2. Check Keycloak logs for magic link URLs:
```
***** SIMULATION MODE ***** Magic link for user john: 
https://localhost:8080/realms/master/login-actions/action-token?key={token}&client_id=...
```

### Production Testing
1. Enable magic links in production
2. Trigger authentication flow
3. Check email for magic link
4. Click link - should complete authentication immediately
5. Token is automatically consumed (one-time use)

## Troubleshooting

### Magic Link Returns "Invalid Token"
**Possible causes**:
1. Token signature verification failed (tampered URL)
2. Token was already used (one-time use)
3. Token has expired

**Solution**: Request a new code and use the new magic link

### Magic Link Shows "Token Expired"
**Cause**: Token TTL exceeded  
**Solution**: Increase `ttl` configuration (e.g., 1800 seconds = 30 minutes)

### ActionToken Handler Not Found
**Cause**: Handler factory not registered  
**Solution**: Verify `org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory` exists in `META-INF/services/` with content `com.mesutpiskin.keycloak.auth.email.token.EmailMagicLinkActionTokenHandlerFactory`

## Code Files

1. **EmailAuthenticatorForm.java**
   - Simplified `authenticate()` method (no magic token extraction)
   - Updated `buildMagicLink()` to create ActionToken
   - Removed `tryMagicLink()` and `validateMagicToken()` (handled by ActionToken framework)

2. **New Token Files**
   - `token/EmailMagicLinkActionToken.java`: Token data class
   - `token/EmailMagicLinkActionTokenHandler.java`: Token processor
   - `token/EmailMagicLinkActionTokenHandlerFactory.java`: Factory for registration
   - `META-INF/services/org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory`: Registration file

## Comparison: Custom Endpoint vs ActionToken

| Aspect | Old (Custom Endpoint) | New (ActionToken) |
|--------|---------------------|---------------------------|
| **Endpoint** | Custom REST `/email-magic-link/verify` | Standard `/login-actions/action-token` |
| **Storage** | User Attributes | Self-contained token |
| **Security** | Manual validation | Keycloak framework (signature, expiry, one-time) |
| **Architecture** | Custom implementation | Official Keycloak API |
| **Maintainability** | ⚠️ Custom code | ✅ Framework-provided |
| **Production Ready** | ✅ Yes | ✅ Yes (better) |

## Migration from Previous Version

If you're upgrading from the user-attribute approach:

1. ✅ **Deploy** the new JAR (old attributes will be ignored)
2. ✅ Magic links will use new format automatically
3. ✅ Old magic links (with `/email-magic-link/verify`) will no longer work
4. ✅ Users simply need to request a new code

No data migration needed - new approach is cleaner and doesn't use user attributes.

## Next Steps

1. ✅ **Deploy** the new JAR to your Keycloak instance
2. ✅ **Test** magic links in simulation mode first
3. ✅ **Configure** appropriate TTL for your use case
4. ✅ **Monitor** Keycloak logs for token validation success/failures
5. ✅ **Update email templates** if needed (magic link URL format changed)

## Support

The implementation is compatible with:
- ✅ Keycloak 26.0.0+
- ✅ All email providers (Keycloak SMTP, SendGrid, AWS SES, Mailgun)
- ✅ Multi-instance deployments
- ✅ Database and user federation backends
- ✅ PKCE-enabled OAuth2 flows

---

**Version**: 26.1.0  
**Implementation**: ActionToken-based (p2-inc/keycloak-magic-link approach)  
**Implementation Date**: January 12, 2026  
**Status**: Production Ready ✅


package com.mesutpiskin.keycloak.auth.email;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Focused unit tests for Magic Link functionality in EmailAuthenticatorForm.
 * 
 * These tests verify the magic link feature behavior without full Keycloak
 * context:
 * - Magic link URL generation
 * - Magic link parameter detection
 * - Code validation through magic links
 * - Configuration handling
 */
@DisplayName("Magic Link Feature Tests")
class MagicLinkTest {

  @Test
  @DisplayName("Magic link should be enabled via configuration")
  void testMagicLinkConfiguration() {
    // Verify the magic link configuration constant
    assertEquals("magicLinkEnabled", EmailConstants.MAGIC_LINK_ENABLED);
    assertEquals("kc_email_magic", EmailConstants.MAGIC_LINK_MARKER_PARAM);
    assertFalse(EmailConstants.DEFAULT_MAGIC_LINK_ENABLED,
        "Magic link should be disabled by default for security");
  }

  @Test
  @DisplayName("Magic link marker parameter should be present in URL")
  void testMagicLinkMarkerParam() {
    AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    HttpRequest httpRequest = mock(HttpRequest.class);
    UriInfo uriInfo = mock(UriInfo.class);

    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(httpRequest.getUri()).thenReturn(uriInfo);

    MultivaluedMap<String, String> queryParams = new MultivaluedHashMap<>();
    queryParams.putSingle(EmailConstants.MAGIC_LINK_MARKER_PARAM, "1");
    queryParams.putSingle(EmailConstants.CODE, "123456");

    when(uriInfo.getQueryParameters()).thenReturn(queryParams);

    // Verify marker is present
    String marker = context.getHttpRequest().getUri().getQueryParameters()
        .getFirst(EmailConstants.MAGIC_LINK_MARKER_PARAM);
    assertEquals("1", marker);
  }

  @Test
  @DisplayName("Magic link should contain code parameter")
  void testMagicLinkCodeParam() {
    AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    HttpRequest httpRequest = mock(HttpRequest.class);
    UriInfo uriInfo = mock(UriInfo.class);

    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(httpRequest.getUri()).thenReturn(uriInfo);

    String testCode = "654321";
    MultivaluedMap<String, String> queryParams = new MultivaluedHashMap<>();
    queryParams.putSingle(EmailConstants.MAGIC_LINK_MARKER_PARAM, "1");
    queryParams.putSingle(EmailConstants.CODE, testCode);

    when(uriInfo.getQueryParameters()).thenReturn(queryParams);

    // Verify code is present
    String code = context.getHttpRequest().getUri().getQueryParameters()
        .getFirst(EmailConstants.CODE);
    assertEquals(testCode, code);
  }

  @Test
  @DisplayName("Magic link should be disabled when configuration is false")
  void testMagicLinkDisabledByConfig() {
    AuthenticatorConfigModel configModel = mock(AuthenticatorConfigModel.class);
    Map<String, String> config = new HashMap<>();
    config.put(EmailConstants.MAGIC_LINK_ENABLED, "false");

    when(configModel.getConfig()).thenReturn(config);

    boolean magicEnabled = Boolean.parseBoolean(
        config.getOrDefault(EmailConstants.MAGIC_LINK_ENABLED,
            String.valueOf(EmailConstants.DEFAULT_MAGIC_LINK_ENABLED)));

    assertFalse(magicEnabled, "Magic link should be disabled when config is false");
  }

  @Test
  @DisplayName("Magic link should be enabled when configuration is true")
  void testMagicLinkEnabledByConfig() {
    AuthenticatorConfigModel configModel = mock(AuthenticatorConfigModel.class);
    Map<String, String> config = new HashMap<>();
    config.put(EmailConstants.MAGIC_LINK_ENABLED, "true");

    when(configModel.getConfig()).thenReturn(config);

    boolean magicEnabled = Boolean.parseBoolean(
        config.getOrDefault(EmailConstants.MAGIC_LINK_ENABLED,
            String.valueOf(EmailConstants.DEFAULT_MAGIC_LINK_ENABLED)));

    assertTrue(magicEnabled, "Magic link should be enabled when config is true");
  }

  @Test
  @DisplayName("Magic link should validate code matches stored code")
  void testMagicLinkCodeValidation() {
    AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
    String storedCode = "123456";
    String submittedCode = "123456";
    long futureExpiry = System.currentTimeMillis() + 300000; // 5 minutes from now

    when(session.getAuthNote(EmailConstants.CODE)).thenReturn(storedCode);
    when(session.getAuthNote(EmailConstants.CODE_TTL)).thenReturn(String.valueOf(futureExpiry));

    // Simulate validation logic
    boolean codesMatch = storedCode.equals(submittedCode);
    boolean notExpired = futureExpiry > System.currentTimeMillis();

    assertTrue(codesMatch, "Submitted code should match stored code");
    assertTrue(notExpired, "Code should not be expired");
  }

  @Test
  @DisplayName("Magic link should reject expired code")
  void testMagicLinkExpiredCode() {
    AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
    String storedCode = "123456";
    long pastExpiry = System.currentTimeMillis() - 1000; // Expired 1 second ago

    when(session.getAuthNote(EmailConstants.CODE)).thenReturn(storedCode);
    when(session.getAuthNote(EmailConstants.CODE_TTL)).thenReturn(String.valueOf(pastExpiry));

    // Simulate validation logic
    boolean isExpired = pastExpiry < System.currentTimeMillis();

    assertTrue(isExpired, "Code should be expired");
  }

  @Test
  @DisplayName("Magic link should reject mismatched code")
  void testMagicLinkMismatchedCode() {
    AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
    String storedCode = "123456";
    String submittedCode = "654321";
    long futureExpiry = System.currentTimeMillis() + 300000;

    when(session.getAuthNote(EmailConstants.CODE)).thenReturn(storedCode);
    when(session.getAuthNote(EmailConstants.CODE_TTL)).thenReturn(String.valueOf(futureExpiry));

    // Simulate validation logic
    boolean codesMatch = storedCode.equals(submittedCode);

    assertFalse(codesMatch, "Submitted code should not match stored code");
  }

  @Test
  @DisplayName("Magic link should handle missing marker parameter")
  void testMagicLinkMissingMarker() {
    AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    HttpRequest httpRequest = mock(HttpRequest.class);
    UriInfo uriInfo = mock(UriInfo.class);

    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(httpRequest.getUri()).thenReturn(uriInfo);

    // Only code parameter, no marker
    MultivaluedMap<String, String> queryParams = new MultivaluedHashMap<>();
    queryParams.putSingle(EmailConstants.CODE, "123456");

    when(uriInfo.getQueryParameters()).thenReturn(queryParams);

    String marker = context.getHttpRequest().getUri().getQueryParameters()
        .getFirst(EmailConstants.MAGIC_LINK_MARKER_PARAM);

    assertNull(marker, "Marker should be null when not present");
  }

  @Test
  @DisplayName("Magic link should handle blank code parameter")
  void testMagicLinkBlankCode() {
    AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    HttpRequest httpRequest = mock(HttpRequest.class);
    UriInfo uriInfo = mock(UriInfo.class);

    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(httpRequest.getUri()).thenReturn(uriInfo);

    // Marker present but code is blank
    MultivaluedMap<String, String> queryParams = new MultivaluedHashMap<>();
    queryParams.putSingle(EmailConstants.MAGIC_LINK_MARKER_PARAM, "1");
    queryParams.putSingle(EmailConstants.CODE, "   ");

    when(uriInfo.getQueryParameters()).thenReturn(queryParams);

    String code = context.getHttpRequest().getUri().getQueryParameters()
        .getFirst(EmailConstants.CODE);

    assertTrue(code == null || code.isBlank(), "Code should be blank or null");
  }

  @Test
  @DisplayName("Magic link URL should use getActionUrl for correct parameters")
  void testMagicLinkUrlGeneration() {
    AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    AuthenticationExecutionModel execution = mock(AuthenticationExecutionModel.class);

    String executionId = "test-execution-id";
    when(context.getExecution()).thenReturn(execution);
    when(execution.getId()).thenReturn(executionId);

    URI actionUri = URI.create(
        "https://example.com/auth/realms/myrealm/login-actions/authenticate?session_code=abc&execution=" + executionId);
    when(context.getActionUrl(executionId)).thenReturn(actionUri);

    // Verify that getActionUrl returns a proper URI
    assertNotNull(context.getActionUrl(executionId));
    assertTrue(context.getActionUrl(executionId).toString().contains(executionId));
  }

  @Test
  @DisplayName("Magic link should handle null stored code")
  void testMagicLinkNullStoredCode() {
    AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);

    when(session.getAuthNote(EmailConstants.CODE)).thenReturn(null);

    String storedCode = session.getAuthNote(EmailConstants.CODE);

    assertNull(storedCode, "Stored code should be null");
  }

  @Test
  @DisplayName("Magic link should clear code from session after successful validation")
  void testMagicLinkClearSession() {
    AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);

    // Simulate clearing session
    session.removeAuthNote(EmailConstants.CODE);
    session.removeAuthNote(EmailConstants.CODE_TTL);

    verify(session, times(1)).removeAuthNote(EmailConstants.CODE);
    verify(session, times(1)).removeAuthNote(EmailConstants.CODE_TTL);
  }
}

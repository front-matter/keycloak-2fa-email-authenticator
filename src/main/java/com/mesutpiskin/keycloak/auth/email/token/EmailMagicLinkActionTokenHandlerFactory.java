package com.mesutpiskin.keycloak.auth.email.token;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for creating EmailMagicLinkActionTokenHandler instances.
 * <p>
 * This factory is automatically registered via the @AutoService annotation.
 * </p>
 *
 * @author Mesut Pişkin
 * @version 26.1.0
 * @since 26.1.0
 */
@AutoService(ActionTokenHandlerFactory.class)
public class EmailMagicLinkActionTokenHandlerFactory
    implements ActionTokenHandlerFactory<EmailMagicLinkActionToken> {

  public static final String PROVIDER_ID = "email-magic-link";

  @Override
  public EmailMagicLinkActionTokenHandler create(KeycloakSession session) {
    return new EmailMagicLinkActionTokenHandler();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public void init(Config.Scope config) {
    // No initialization needed
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // No post-initialization needed
  }

  @Override
  public void close() {
    // No resources to close
  }
}

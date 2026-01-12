package com.mesutpiskin.keycloak.auth.email.token;

import com.google.auto.service.AutoService;
import org.jboss.logging.Logger;
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

  private static final Logger logger = Logger.getLogger(EmailMagicLinkActionTokenHandlerFactory.class);

  public static final String PROVIDER_ID = "email-magic-link";

  @Override
  public EmailMagicLinkActionTokenHandler create(KeycloakSession session) {
    logger.warnf("[DEBUG] Creating EmailMagicLinkActionTokenHandler for session: %s",
        session != null ? session.hashCode() : "null");
    EmailMagicLinkActionTokenHandler handler = new EmailMagicLinkActionTokenHandler();
    logger.warnf("[DEBUG] EmailMagicLinkActionTokenHandler instance created: %s", handler.getClass().getName());
    return handler;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public void init(Config.Scope config) {
    logger.infof("Initializing EmailMagicLinkActionTokenHandlerFactory with ID: %s", PROVIDER_ID);
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    logger.infof("Post-initializing EmailMagicLinkActionTokenHandlerFactory");
    logger.infof("EmailMagicLinkActionTokenHandlerFactory registered with PROVIDER_ID: %s for token type: %s",
        PROVIDER_ID, EmailMagicLinkActionToken.TOKEN_TYPE);
    logger.infof("Token class: %s", EmailMagicLinkActionToken.class.getName());
  }

  @Override
  public void close() {
    // No resources to close
  }
}

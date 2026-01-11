package com.mesutpiskin.keycloak.auth.email;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for creating MagicLinkResourceProvider instances.
 * <p>
 * This factory registers the custom REST endpoint for magic link verification.
 * </p>
 *
 * @author Mesut Pişkin
 * @version 26.1.0
 * @since 26.1.0
 */
public class MagicLinkResourceProviderFactory implements RealmResourceProviderFactory {

  public static final String ID = "email-magic-link";

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    return new MagicLinkResourceProvider(session);
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

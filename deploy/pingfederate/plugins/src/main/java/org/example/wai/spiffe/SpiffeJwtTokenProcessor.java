package org.example.wai.spiffe;

import com.pingidentity.sdk.GuiConfigDescriptor;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.JsonWebKeySet;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.wstrust.model.BinarySecurityToken;
import org.sourceid.wstrust.plugin.TokenProcessingException;
import org.sourceid.wstrust.plugin.process.TokenContext;
import org.sourceid.wstrust.plugin.process.TokenProcessor;
import org.sourceid.wstrust.plugin.process.TokenProcessorDescriptor;

public final class SpiffeJwtTokenProcessor implements TokenProcessor<BinarySecurityToken> {
  static final String JWKS = "SPIRE JWKS";
  static final String AUDIENCE = "Required Audience";
  static final String TRUST_DOMAIN = "Trust Domain";
  static final String MAX_LIFETIME = "Maximum Lifetime Seconds";
  static final String CLOCK_SKEW = "Allowed Clock Skew Seconds";
  private volatile SpiffeJwtVerifier verifier;

  @Override public void configure(Configuration configuration) {
    try {
      verifier = new SpiffeJwtVerifier(
          configuration.getFieldValue(AUDIENCE), configuration.getFieldValue(TRUST_DOMAIN),
          Duration.ofSeconds(configuration.getLongFieldValue(MAX_LIFETIME)),
          Duration.ofSeconds(configuration.getLongFieldValue(CLOCK_SKEW)), Clock.systemUTC(),
          new JsonWebKeySet(configuration.getFieldValue(JWKS)).getJsonWebKeys());
    } catch (RuntimeException | org.jose4j.lang.JoseException e) {
      throw new IllegalArgumentException("SPIFFE JWT processor configuration is invalid", e);
    }
  }

  @Override public TokenContext processToken(BinarySecurityToken token) throws TokenProcessingException {
    SpiffeJwtVerifier current = verifier;
    if (current == null) throw new TokenProcessingException("SPIFFE JWT processor is not configured");
    try {
      VerifiedWorkload workload = current.verify(token == null ? null : token.getEncodedData());
      TokenContext context = new TokenContext();
      context.setSubjectAttributes(Map.of("sub", new AttributeValue(workload.spiffeId())));
      return context;
    } catch (SpiffeJwtVerifier.VerificationException e) {
      throw new TokenProcessingException("SPIFFE JWT-SVID validation failed");
    }
  }

  @Override public TokenProcessorDescriptor getPluginDescriptor() {
    GuiConfigDescriptor gui = new GuiConfigDescriptor("Validates issuer-less SPIRE JWT-SVID actor tokens.");
    gui.addField(required(JWKS, "Trusted SPIRE JWT bundle in JWKS format."));
    gui.addField(required(AUDIENCE, "Audience required on every actor token."));
    gui.addField(required(TRUST_DOMAIN, "Exact trusted SPIFFE trust domain."));
    gui.addField(required(MAX_LIFETIME, "Maximum accepted JWT-SVID lifetime in seconds."));
    gui.addField(required(CLOCK_SKEW, "Allowed clock skew in seconds; maximum 30."));
    return new TokenProcessorDescriptor("WAI SPIRE JWT-SVID Token Processor", this, gui,
        "urn:ietf:params:oauth:token-type:jwt", Set.of("sub"), "1.0.0");
  }

  private static TextFieldDescriptor required(String name, String description) {
    TextFieldDescriptor field = new TextFieldDescriptor(name, description);
    field.addValidator(new RequiredFieldValidator());
    return field;
  }
}

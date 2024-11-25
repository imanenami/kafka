package com.canonical.kafka.security.authentication;

import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.authenticator.CredentialCache;
import org.apache.kafka.common.security.scram.ScramCredential;
import org.apache.kafka.common.security.scram.internals.ScramFormatter;
import org.apache.kafka.common.security.scram.internals.ScramServerCallbackHandler;
import org.apache.kafka.common.security.scram.internals.ScramMechanism;
import org.apache.kafka.common.security.token.delegation.internals.DelegationTokenCache;

import java.util.List;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.security.NoSuchAlgorithmException;


public class ScramCallbackHandler implements AuthenticateCallbackHandler {

    private ScramFormatter formatter;
    private ScramServerCallbackHandler callbackHandler;
    private static final String JAAS_USER_PREFIX = "user_";

    @Override
    public void configure(Map<String, ?> configs, String mechanism, List<AppConfigurationEntry> jaasConfigEntries) {

        CredentialCache.Cache<ScramCredential> credentialCache = new CredentialCache().createCache(
            mechanism, ScramCredential.class);

        for (AppConfigurationEntry cfg: jaasConfigEntries) {
            Map<String, ?> options = cfg.getOptions();

            ScramMechanism scramMechanism = ScramMechanism.forMechanismName(mechanism);
            try {
                formatter = new ScramFormatter(scramMechanism);
            } catch (NoSuchAlgorithmException e) {
                return;
            }

            for (Map.Entry<String, ?> entry : options.entrySet()) {
                if (entry.getKey().startsWith(JAAS_USER_PREFIX)) {
                    String username = entry.getKey().replaceFirst(JAAS_USER_PREFIX, "");
                    String password = (String) entry.getValue();

                    credentialCache.put(username, formatter.generateCredential(password, 4096));
                }
            }
        }

        callbackHandler = new ScramServerCallbackHandler(credentialCache, new DelegationTokenCache(ScramMechanism.mechanismNames()));
        callbackHandler.configure(configs, mechanism, jaasConfigEntries);
    }

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        callbackHandler.handle(callbacks);
    }

    @Override
    public void close() {
    }

}

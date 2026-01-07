/*
 * Copyright 2017-2020 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.azure.secretmanager.signing;

import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.models.KeyProperties;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import io.micronaut.azure.secretmanager.client.KeyVaultKeyClient;
import io.micronaut.azure.secretmanager.client.KeyVaultSigningClient;
import io.micronaut.azure.secretmanager.configuration.AzureKeyVaultConfigurationProperties;
import io.micronaut.context.annotation.BootstrapContextCompatible;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.ArgumentUtils;
import io.micronaut.core.util.StringUtils;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link KeyVaultKeySigner}.
 */
@Singleton
@BootstrapContextCompatible
@Requires(beans = {KeyVaultKeyClient.class, KeyVaultSigningClient.class})
@Requires(property = AzureKeyVaultConfigurationProperties.PREFIX + ".keys.enabled", value = StringUtils.TRUE)
@Requires(property = AzureKeyVaultConfigurationProperties.PREFIX + ".keys.signing.enabled", value = StringUtils.TRUE)
public class DefaultKeyVaultKeySigner implements KeyVaultKeySigner {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultKeyVaultKeySigner.class);

    private final KeyVaultKeyClient keyVaultKeyClient;
    private final KeyVaultSigningClient keyVaultSigningClient;
    private final AzureKeyVaultConfigurationProperties configurationProperties;

    /**
     * @param keyVaultKeyClient        Key client abstraction
     * @param keyVaultSigningClient    Signing client abstraction
     * @param configurationProperties  Configuration properties
     */
    public DefaultKeyVaultKeySigner(
            KeyVaultKeyClient keyVaultKeyClient,
            KeyVaultSigningClient keyVaultSigningClient,
            AzureKeyVaultConfigurationProperties configurationProperties
    ) {
        this.keyVaultKeyClient = keyVaultKeyClient;
        this.keyVaultSigningClient = keyVaultSigningClient;
        this.configurationProperties = configurationProperties;
    }

    @Override
    public byte[] sign(@NonNull String keyName, @NonNull SignatureAlgorithm algorithm, @NonNull byte[] data) {
        ArgumentUtils.requireNonNull("keyName", keyName);
        ArgumentUtils.requireNonNull("algorithm", algorithm);
        ArgumentUtils.requireNonNull("data", data);
        if (StringUtils.isEmpty(keyName)) {
            throw new IllegalArgumentException("keyName cannot be blank");
        }
        KeyVaultKey key = resolveKey(keyName);
        if (key == null) {
            throw new IllegalArgumentException("No key named [" + keyName + "] found in Azure Key Vault");
        }
        String keyId = key.getId();
        if (StringUtils.isEmpty(keyId)) {
            KeyProperties properties = key.getProperties();
            keyId = properties != null ? properties.getId() : null;
        }
        if (StringUtils.isEmpty(keyId)) {
            throw new IllegalStateException("Resolved key [" + keyName + "] does not expose an identifier");
        }
        return keyVaultSigningClient.sign(keyId, algorithm, data);
    }

    @Override
    public byte[] sign(@NonNull String keyName, @NonNull byte[] data) {
        SignatureAlgorithm algorithm = resolveDefaultAlgorithm();
        if (algorithm == null) {
            throw new IllegalStateException("No default signing algorithm configured. Specify azure.key-vault.keys.signing.default-algorithm or provide an algorithm explicitly.");
        }
        return sign(keyName, algorithm, data);
    }

    private SignatureAlgorithm resolveDefaultAlgorithm() {
        String configured = configurationProperties.getKeys().getSigning().getDefaultAlgorithm();
        if (StringUtils.isEmpty(configured)) {
            return null;
        }
        try {
            return SignatureAlgorithm.fromString(configured);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Unsupported default signing algorithm: " + configured, e);
        }
    }

    private KeyVaultKey resolveKey(String keyName) {
        KeyVaultKey key = findKey(keyName);
        if (key != null) {
            return key;
        }
        if (keyName.contains(".")) {
            key = findKey(keyName.replace('.', '-'));
            if (key != null) {
                return key;
            }
        }
        if (keyName.contains("_")) {
            key = findKey(keyName.replace('_', '-'));
            if (key != null) {
                return key;
            }
        }
        return null;
    }

    private KeyVaultKey findKey(String keyName) {
        try {
            return keyVaultKeyClient.getKey(keyName);
        } catch (RuntimeException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to resolve key [{}]: {}", keyName, ex.getMessage());
            }
            return null;
        }
    }
}

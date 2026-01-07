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
package io.micronaut.azure.secretmanager;

import com.azure.core.credential.TokenCredential;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import io.micronaut.azure.secretmanager.configuration.AzureKeyVaultConfigurationProperties;
import io.micronaut.context.annotation.BootstrapContextCompatible;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.StringUtils;
import jakarta.inject.Singleton;

/**
 * Factory to create Azure Key Vault key client for key operations (signing, verification, etc.).
 * This factory is independent of the configuration client and can be used solely for key operations.
 *
 * @author Tim Searle
 */
@Factory
@BootstrapContextCompatible
@Requires(property = AzureKeyVaultConfigurationProperties.PREFIX)
@Requires(property = AzureKeyVaultConfigurationProperties.PREFIX + ".keys.enabled", value = StringUtils.TRUE)
public class KeyManagerFactory {

    /**
     * Creates a {@link KeyClient} instance for key operations.
     *
     * @param tokenCredential                      azure credentials
     * @param azureKeyvaultConfigurationProperties key vault configuration
     * @return a key client instance using defaults.
     */
    @Singleton
    @Requires(classes = KeyClient.class)
    public KeyClient keyClient(
            @NonNull TokenCredential tokenCredential,
            @NonNull AzureKeyVaultConfigurationProperties azureKeyvaultConfigurationProperties
    ) {
        return new KeyClientBuilder()
                .vaultUrl(azureKeyvaultConfigurationProperties.getVaultURL())
                .credential(tokenCredential)
                .buildClient();
    }
}

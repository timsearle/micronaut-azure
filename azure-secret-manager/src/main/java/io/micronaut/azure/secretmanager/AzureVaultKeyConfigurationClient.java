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

import com.azure.security.keyvault.keys.models.JsonWebKey;
import com.azure.security.keyvault.keys.models.KeyProperties;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import io.micronaut.azure.secretmanager.client.KeyVaultKeyClient;
import io.micronaut.azure.secretmanager.configuration.AzureKeyVaultConfigurationProperties;
import io.micronaut.context.annotation.BootstrapContextCompatible;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.env.Environment;
import io.micronaut.context.env.PropertySource;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.discovery.config.ConfigurationClient;
import io.micronaut.scheduling.TaskExecutors;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

/**
 * Distributed configuration client that fetches key values from Azure Key Vault.
 */
@Singleton
@Requires(beans = KeyVaultKeyClient.class)
@Requires(property = AzureKeyVaultConfigurationProperties.PREFIX + ".keys.enabled", value = StringUtils.TRUE)
@BootstrapContextCompatible
public class AzureVaultKeyConfigurationClient implements ConfigurationClient {

    private static final Logger LOG = LoggerFactory.getLogger(AzureVaultKeyConfigurationClient.class);
    private static final String KEY_PROPERTY_PREFIX = "azure.key-vault.keys.";
    private static final String JSON_WEB_KEY_SUFFIX = ".json-web-key";

    private final AzureKeyVaultConfigurationProperties azureKeyVaultConfigurationProperties;
    private final ExecutorService executorService;
    private final KeyVaultKeyClient keyVaultKeyClient;
    private final String vaultUrl;

    /**
     * @param azureKeyVaultConfigurationProperties Key Vault configuration
     * @param executorService Executor service
     * @param keyVaultKeyClient Key client abstraction
     */
    public AzureVaultKeyConfigurationClient(
            AzureKeyVaultConfigurationProperties azureKeyVaultConfigurationProperties,
            @Named(TaskExecutors.IO) @Nullable ExecutorService executorService,
            KeyVaultKeyClient keyVaultKeyClient
    ) {
        this.azureKeyVaultConfigurationProperties = azureKeyVaultConfigurationProperties;
        this.executorService = executorService;
        this.keyVaultKeyClient = keyVaultKeyClient;
        this.vaultUrl = azureKeyVaultConfigurationProperties.getVaultURL();
    }

    @Override
    public Publisher<PropertySource> getPropertySources(Environment environment) {
        if (StringUtils.isEmpty(vaultUrl)) {
            return Flux.empty();
        }
        if (!azureKeyVaultConfigurationProperties.getKeys().isEnabled()) {
            return Flux.empty();
        }

        Map<String, Object> keys = new HashMap<>();
        Scheduler scheduler = executorService != null ? Schedulers.fromExecutor(executorService) : null;

        if (LOG.isDebugEnabled()) {
            LOG.debug("Retrieving keys from Azure Key Vault with URL: {}", azureKeyVaultConfigurationProperties.getVaultURL());
        }

        int retrieved = 0;
        for (KeyVaultKey keyVaultKey : keyVaultKeyClient.listKeys()) {
            retrieved++;
            registerKey(keys, keyVaultKey);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Retrieved key: {}", keyVaultKey.getName());
            }
        }

        if (retrieved == 0) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No keys retrieved from Azure Key Vault with URL: {}", azureKeyVaultConfigurationProperties.getVaultURL());
            }
        } else if (LOG.isDebugEnabled()) {
            LOG.debug("{} keys were retrieved from Azure Key Vault with URL: {}", retrieved, azureKeyVaultConfigurationProperties.getVaultURL());
        }

        Flux<PropertySource> propertySourceFlux = Flux.just(PropertySource.of("azure-key-vault-keys", keys));
        if (scheduler != null) {
            propertySourceFlux = propertySourceFlux.subscribeOn(scheduler);
        }
        return propertySourceFlux;
    }

    @Override
    public String getDescription() {
        return "Retrieves keys from Azure key vaults";
    }

    private void registerKey(Map<String, Object> target, KeyVaultKey keyVaultKey) {
        addKeyEntry(target, keyVaultKey, keyVaultKey.getName());
        addKeyEntry(target, keyVaultKey, keyVaultKey.getName().replace('-', '.'));
        addKeyEntry(target, keyVaultKey, keyVaultKey.getName().replace('-', '_'));
    }

    private void addKeyEntry(Map<String, Object> target, KeyVaultKey keyVaultKey, String nameVariant) {
        String propertyBase = KEY_PROPERTY_PREFIX + nameVariant;
        target.put(propertyBase, keyVaultKey);
        KeyProperties properties = keyVaultKey.getProperties();
        if (properties != null && properties.getId() != null) {
            target.put(propertyBase + ".id", properties.getId());
        }
        if (keyVaultKey.getKeyType() != null) {
            target.put(propertyBase + ".type", keyVaultKey.getKeyType().toString());
        }
        if (keyVaultKey.getKeyOperations() != null && !keyVaultKey.getKeyOperations().isEmpty()) {
            List<String> operations = new ArrayList<>(keyVaultKey.getKeyOperations().size());
            keyVaultKey.getKeyOperations().forEach(operation -> operations.add(operation.toString()));
            target.put(propertyBase + ".operations", operations);
        }
        JsonWebKey jsonWebKey = keyVaultKey.getKey();
        if (jsonWebKey != null) {
            target.put(propertyBase + JSON_WEB_KEY_SUFFIX, jsonWebKey);
        }
    }
}

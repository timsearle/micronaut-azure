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
package io.micronaut.azure.secretmanager.client;

import com.azure.security.keyvault.keys.models.KeyVaultKey;

import java.util.List;

/**
 * Abstraction over {@link com.azure.security.keyvault.keys.KeyClient} to simplify testing.
 * @author tim
 */
public interface KeyVaultKeyClient {

    /**
     * Fetches a key from the key vault using the provided name.
     *
     * @param keyName name of the key
     * @return The {@link KeyVaultKey} if it exists
     */
    KeyVaultKey getKey(String keyName);

    /**
     * Lists all keys within the configured key vault.
     *
     * @return list of {@link KeyVaultKey}
     */
    List<KeyVaultKey> listKeys();
}

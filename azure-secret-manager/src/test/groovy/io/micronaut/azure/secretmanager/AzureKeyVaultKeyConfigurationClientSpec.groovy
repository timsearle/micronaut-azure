package io.micronaut.azure.secretmanager

import com.azure.security.keyvault.keys.models.JsonWebKey
import com.azure.security.keyvault.keys.models.KeyProperties
import com.azure.security.keyvault.keys.models.KeyVaultKey
import com.azure.security.keyvault.keys.models.KeyOperation
import com.azure.security.keyvault.keys.models.KeyType
import io.micronaut.azure.secretmanager.client.DefaultKeyVaultKeyClient
import io.micronaut.azure.secretmanager.client.KeyVaultKeyClient
import io.micronaut.azure.secretmanager.configuration.AzureKeyVaultConfigurationProperties
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.BootstrapContextCompatible
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.context.env.PropertySource
import jakarta.inject.Singleton
import reactor.core.publisher.Flux
import spock.lang.Specification

class AzureKeyVaultKeyConfigurationClientSpec extends Specification {

    void "it loads keys from mocked vault"() {
        given:
        def jsonWebKey = Stub(JsonWebKey) {
            getId() >> 'https://example-vault.azure.net/keys/sample-key'
        }
        def keyProperties = Stub(KeyProperties) {
            getId() >> 'https://example-vault.azure.net/keys/sample-key'
        }
        MockDefaultKeyVaultKeyClient.testJsonWebKey = jsonWebKey
        MockDefaultKeyVaultKeyClient.testKey = Stub(KeyVaultKey) {
            getName() >> 'sample-key'
            getKeyOperations() >> [KeyOperation.SIGN]
            getKeyType() >> KeyType.RSA
            getKey() >> jsonWebKey
            getProperties() >> keyProperties
        }

        ApplicationContext ctx = ApplicationContext.run([
                'spec.name'                      : 'azure-key-vault-keys',
                'azure.key-vault.vaultUrl'       : 'https://example-vault.azure.net',
                'azure.key-vault.keys.enabled'   : true,
                'micronaut.config-client.enabled': true
        ])
        AzureVaultKeyConfigurationClient client = ctx.getBean(AzureVaultKeyConfigurationClient)
        def config = ctx.getBean(AzureKeyVaultConfigurationProperties)

        when:
        PropertySource propertySource = Flux.from(client.getPropertySources(null)).blockFirst()

        then:
        config.keys.enabled
        propertySource != null
        propertySource.get('azure.key-vault.keys.sample-key') == MockDefaultKeyVaultKeyClient.testKey
        propertySource.get('azure.key-vault.keys.sample.key') == MockDefaultKeyVaultKeyClient.testKey
        propertySource.get('azure.key-vault.keys.sample_key') == MockDefaultKeyVaultKeyClient.testKey
        propertySource.get('azure.key-vault.keys.sample-key.type') == KeyType.RSA.toString()
        propertySource.get('azure.key-vault.keys.sample-key.operations') == [KeyOperation.SIGN.toString()]
        propertySource.get('azure.key-vault.keys.sample-key.json-web-key') == MockDefaultKeyVaultKeyClient.testJsonWebKey
        propertySource.get('azure.key-vault.keys.sample-key.id') == 'https://example-vault.azure.net/keys/sample-key'

        cleanup:
        ctx.close()
        MockDefaultKeyVaultKeyClient.testKey = null
        MockDefaultKeyVaultKeyClient.testJsonWebKey = null
    }

    void "it does not expose key configuration client when disabled"() {
        given:
        ApplicationContext ctx = ApplicationContext.run([
                'azure.key-vault.vaultUrl'       : 'https://example-vault.azure.net',
                'azure.key-vault.keys.enabled'   : false,
                'micronaut.config-client.enabled': true
        ])

        when:
        ctx.getBean(AzureVaultKeyConfigurationClient)

        then:
        thrown NoSuchBeanException

        cleanup:
        ctx.close()
    }

    @Singleton
    @Replaces(DefaultKeyVaultKeyClient)
    @BootstrapContextCompatible
    @Requires(property = 'spec.name', value = 'azure-key-vault-keys')
    static class MockDefaultKeyVaultKeyClient implements KeyVaultKeyClient {

        static KeyVaultKey testKey
        static JsonWebKey testJsonWebKey

        @Override
        KeyVaultKey getKey(String keyName) {
            return testKey
        }

        @Override
        List<KeyVaultKey> listKeys() {
            return [testKey]
        }
    }
}

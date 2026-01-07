package io.micronaut.azure.secretmanager

import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm
import com.azure.security.keyvault.keys.models.KeyProperties
import com.azure.security.keyvault.keys.models.KeyVaultKey
import io.micronaut.azure.secretmanager.client.DefaultKeyVaultKeyClient
import io.micronaut.azure.secretmanager.client.DefaultKeyVaultSigningClient
import io.micronaut.azure.secretmanager.client.KeyVaultKeyClient
import io.micronaut.azure.secretmanager.client.KeyVaultSigningClient
import io.micronaut.azure.secretmanager.signing.KeyVaultKeySigner
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.BootstrapContextCompatible
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import jakarta.inject.Singleton
import spock.lang.Specification

class AzureKeyVaultKeySignerSpec extends Specification {

    void "it signs payloads using provided algorithm"() {
        given:
        byte[] payload = "payload".bytes
        MockKeyVaultSigningClient.signature = "signed".bytes
        MockKeyVaultSigningClient.reset()

        KeyProperties keyProperties = Stub(KeyProperties) {
            getId() >> 'https://example-vault.azure.net/keys/sample-key/123'
        }
        KeyVaultKey key = Stub(KeyVaultKey) {
            getId() >> 'https://example-vault.azure.net/keys/sample-key/123'
            getProperties() >> keyProperties
        }
        MockKeyVaultKeyClient.configureKey('sample-key', key)

        ApplicationContext ctx = ApplicationContext.run([
                'spec.name'                              : 'azure-key-signing',
                'azure.key-vault.vaultUrl'               : 'https://example-vault.azure.net',
                'azure.key-vault.keys.enabled'           : true,
                'azure.key-vault.keys.signing.enabled'   : true,
                'azure.key-vault.keys.signing.default-algorithm': 'RS256'
        ])
        KeyVaultKeySigner signer = ctx.getBean(KeyVaultKeySigner)

        when:
        byte[] signature = signer.sign('sample-key', SignatureAlgorithm.RS256, payload)

        then:
        signature == MockKeyVaultSigningClient.signature
        MockKeyVaultSigningClient.lastKeyId == 'https://example-vault.azure.net/keys/sample-key/123'
        MockKeyVaultSigningClient.lastAlgorithm == SignatureAlgorithm.RS256
        MockKeyVaultSigningClient.lastPayload == payload

        when:
        byte[] signatureWithDefault = signer.sign('sample.key', payload)

        then:
        signatureWithDefault == MockKeyVaultSigningClient.signature
        MockKeyVaultSigningClient.lastAlgorithm == SignatureAlgorithm.RS256

        cleanup:
        ctx.close()
        MockKeyVaultSigningClient.reset()
        MockKeyVaultKeyClient.clear()
    }

    void "it requires a default algorithm when none supplied"() {
        given:
        MockKeyVaultSigningClient.signature = "signed".bytes
        MockKeyVaultSigningClient.reset()

        KeyProperties keyProperties = Stub(KeyProperties) {
            getId() >> 'https://example-vault.azure.net/keys/sample-key/123'
        }
        KeyVaultKey key = Stub(KeyVaultKey) {
            getId() >> 'https://example-vault.azure.net/keys/sample-key/123'
            getProperties() >> keyProperties
        }
        MockKeyVaultKeyClient.configureKey('sample-key', key)

        ApplicationContext ctx = ApplicationContext.run([
                'spec.name'                            : 'azure-key-signing',
                'azure.key-vault.vaultUrl'             : 'https://example-vault.azure.net',
                'azure.key-vault.keys.enabled'         : true,
                'azure.key-vault.keys.signing.enabled' : true
        ])
        KeyVaultKeySigner signer = ctx.getBean(KeyVaultKeySigner)

        when:
        signer.sign('sample-key', "payload".bytes)

        then:
        thrown IllegalStateException

        cleanup:
        ctx.close()
        MockKeyVaultSigningClient.reset()
        MockKeyVaultKeyClient.clear()
    }

    void "it fails when the key is not found"() {
        given:
        MockKeyVaultSigningClient.signature = "signed".bytes
        MockKeyVaultSigningClient.reset()
        MockKeyVaultKeyClient.clear()

        ApplicationContext ctx = ApplicationContext.run([
                'spec.name'                            : 'azure-key-signing',
                'azure.key-vault.vaultUrl'             : 'https://example-vault.azure.net',
                'azure.key-vault.keys.enabled'         : true,
                'azure.key-vault.keys.signing.enabled' : true,
                'azure.key-vault.keys.signing.default-algorithm': 'RS256'
        ])
        KeyVaultKeySigner signer = ctx.getBean(KeyVaultKeySigner)

        when:
        signer.sign('missing-key', SignatureAlgorithm.RS256, "payload".bytes)

        then:
        thrown IllegalArgumentException

        cleanup:
        ctx.close()
        MockKeyVaultSigningClient.reset()
    }

    @Singleton
    @Replaces(DefaultKeyVaultSigningClient)
    @BootstrapContextCompatible
    @Requires(property = 'spec.name', value = 'azure-key-signing')
    static class MockKeyVaultSigningClient implements KeyVaultSigningClient {

        static byte[] signature = "signed".bytes
        static String lastKeyId
        static SignatureAlgorithm lastAlgorithm
        static byte[] lastPayload

        static void reset() {
            lastKeyId = null
            lastAlgorithm = null
            lastPayload = null
        }

        @Override
        byte[] sign(String keyId, SignatureAlgorithm algorithm, byte[] data) {
            lastKeyId = keyId
            lastAlgorithm = algorithm
            lastPayload = data
            return signature
        }
    }

    @Singleton
    @Replaces(DefaultKeyVaultKeyClient)
    @BootstrapContextCompatible
    @Requires(property = 'spec.name', value = 'azure-key-signing')
    static class MockKeyVaultKeyClient implements KeyVaultKeyClient {

        static KeyVaultKey key
        static String normalisedName

        static void configureKey(String keyName, KeyVaultKey keyVaultKey) {
            normalisedName = keyName.replace('.', '-').replace('_', '-')
            key = keyVaultKey
        }

        static void clear() {
            key = null
            normalisedName = null
        }

        @Override
        KeyVaultKey getKey(String keyName) {
            if (key == null) {
                return null
            }
            String candidate = keyName?.replace('.', '-').replace('_', '-')
            return candidate == normalisedName ? key : null
        }

        @Override
        List<KeyVaultKey> listKeys() {
            return key != null ? [key] : []
        }
    }
}

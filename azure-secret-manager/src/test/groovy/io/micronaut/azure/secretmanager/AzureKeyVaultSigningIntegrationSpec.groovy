package io.micronaut.azure.secretmanager

import com.azure.identity.DefaultAzureCredentialBuilder
import com.azure.security.keyvault.keys.KeyClientBuilder
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm
import io.micronaut.azure.secretmanager.signing.KeyVaultKeySigner
import io.micronaut.context.ApplicationContext
import spock.lang.IgnoreIf
import spock.lang.Specification

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.RSAPublicKeySpec

/**
 * Integration test that verifies signing against a real Azure Key Vault.
 *
 * To run this test, set the following environment variables:
 * - AZURE_KEYVAULT_URL: The vault URL (e.g., https://mobiletestharnesskv.vault.azure.net)
 * - AZURE_KEYVAULT_KEY_NAME: The key name (e.g., jwt-signing-key)
 *
 * Authentication uses Azure DefaultAzureCredential (Azure CLI, managed identity, etc.)
 */
@IgnoreIf({
    !System.getenv('AZURE_KEYVAULT_URL') || !System.getenv('AZURE_KEYVAULT_KEY_NAME')
})
class AzureKeyVaultSigningIntegrationSpec extends Specification {

    void "it can sign and verify data with Key Vault"() {
        given:
        String vaultUrl = System.getenv('AZURE_KEYVAULT_URL')
        String keyName = System.getenv('AZURE_KEYVAULT_KEY_NAME')
        byte[] payload = "Hello, Key Vault!".bytes

        ApplicationContext ctx = ApplicationContext.run([
                'azure.key-vault.vault-url'                      : vaultUrl,
                'azure.key-vault.keys.enabled'                   : true,
                'azure.key-vault.keys.signing.enabled'           : true,
                'azure.key-vault.keys.signing.default-algorithm' : 'RS256'
        ])
        KeyVaultKeySigner signer = ctx.getBean(KeyVaultKeySigner)

        when:
        byte[] signature = signer.sign(keyName, SignatureAlgorithm.RS256, payload)

        then:
        signature != null
        signature.length > 0

        and: "signature is valid RSA signature (256 bytes for RSA-2048)"
        signature.length == 256

        cleanup:
        ctx.close()
    }

    void "it handles multiple signing operations efficiently"() {
        given:
        String vaultUrl = System.getenv('AZURE_KEYVAULT_URL')
        String keyName = System.getenv('AZURE_KEYVAULT_KEY_NAME')

        ApplicationContext ctx = ApplicationContext.run([
                'azure.key-vault.vault-url'                      : vaultUrl,
                'azure.key-vault.keys.enabled'                   : true,
                'azure.key-vault.keys.signing.enabled'           : true,
                'azure.key-vault.keys.signing.default-algorithm' : 'RS256'
        ])
        KeyVaultKeySigner signer = ctx.getBean(KeyVaultKeySigner)

        when: "signing multiple payloads"
        def signatures = (1..5).collect { i ->
            signer.sign(keyName, SignatureAlgorithm.RS256, "payload-$i".bytes)
        }

        then: "all signatures are produced"
        signatures.size() == 5
        signatures.every { it != null && it.length == 256 }

        and: "signatures are different for different payloads"
        signatures.toSet().size() == 5

        cleanup:
        ctx.close()
    }

    void "it produces same signature for same input (deterministic)"() {
        given:
        String vaultUrl = System.getenv('AZURE_KEYVAULT_URL')
        String keyName = System.getenv('AZURE_KEYVAULT_KEY_NAME')
        byte[] payload = "deterministic test".bytes

        ApplicationContext ctx = ApplicationContext.run([
                'azure.key-vault.vault-url'                      : vaultUrl,
                'azure.key-vault.keys.enabled'                   : true,
                'azure.key-vault.keys.signing.enabled'           : true,
                'azure.key-vault.keys.signing.default-algorithm' : 'RS256'
        ])
        KeyVaultKeySigner signer = ctx.getBean(KeyVaultKeySigner)

        when:
        byte[] sig1 = signer.sign(keyName, SignatureAlgorithm.RS256, payload)
        byte[] sig2 = signer.sign(keyName, SignatureAlgorithm.RS256, payload)

        then: "RSASSA-PKCS1-v1_5 is deterministic"
        sig1 == sig2

        cleanup:
        ctx.close()
    }

    void "it fails gracefully for non-existent key"() {
        given:
        String vaultUrl = System.getenv('AZURE_KEYVAULT_URL')
        byte[] payload = "test".bytes

        ApplicationContext ctx = ApplicationContext.run([
                'azure.key-vault.vault-url'                      : vaultUrl,
                'azure.key-vault.keys.enabled'                   : true,
                'azure.key-vault.keys.signing.enabled'           : true,
                'azure.key-vault.keys.signing.default-algorithm' : 'RS256'
        ])
        KeyVaultKeySigner signer = ctx.getBean(KeyVaultKeySigner)

        when:
        signer.sign('non-existent-key-12345', SignatureAlgorithm.RS256, payload)

        then:
        thrown(Exception) // Azure SDK throws appropriate exception

        cleanup:
        ctx.close()
    }

    void "signed data can be verified with public key from Key Vault"() {
        given: "signing configuration"
        String vaultUrl = System.getenv('AZURE_KEYVAULT_URL')
        String keyName = System.getenv('AZURE_KEYVAULT_KEY_NAME')
        
        // Simulated JWT signing input (header.payload)
        String header = '{"alg":"RS256","typ":"JWT"}'
        String payload = '{"sub":"test","iat":' + (System.currentTimeMillis() / 1000 as long) + '}'
        String signingInput = Base64.urlEncoder.withoutPadding().encodeToString(header.bytes) + '.' + 
                              Base64.urlEncoder.withoutPadding().encodeToString(payload.bytes)

        ApplicationContext ctx = ApplicationContext.run([
                'azure.key-vault.vault-url'                      : vaultUrl,
                'azure.key-vault.keys.enabled'                   : true,
                'azure.key-vault.keys.signing.enabled'           : true,
                'azure.key-vault.keys.signing.default-algorithm' : 'RS256'
        ])
        KeyVaultKeySigner signer = ctx.getBean(KeyVaultKeySigner)

        when: "signing with Key Vault"
        byte[] signature = signer.sign(keyName, SignatureAlgorithm.RS256, signingInput.bytes)

        and: "retrieving public key from Key Vault"
        def credential = new DefaultAzureCredentialBuilder().build()
        def keyClient = new KeyClientBuilder()
                .vaultUrl(vaultUrl)
                .credential(credential)
                .buildClient()
        def keyVaultKey = keyClient.getKey(keyName)
        def rsaKey = keyVaultKey.key
        
        // Convert to Java RSA public key
        def n = new BigInteger(1, rsaKey.n)  // modulus
        def e = new BigInteger(1, rsaKey.e)  // exponent
        def keySpec = new RSAPublicKeySpec(n, e)
        def keyFactory = KeyFactory.getInstance("RSA")
        def publicKey = keyFactory.generatePublic(keySpec)

        and: "verifying locally with public key"
        def verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(publicKey)
        verifier.update(signingInput.bytes)
        boolean isValid = verifier.verify(signature)

        then: "signature is valid"
        isValid

        cleanup:
        ctx.close()
    }
}

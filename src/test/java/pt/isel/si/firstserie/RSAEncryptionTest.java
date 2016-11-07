package pt.isel.si.firstserie;

import org.junit.Test;
import pt.isel.si.firstserie.crypt.AESEncryption;
import pt.isel.si.firstserie.crypt.Algorithms;
import pt.isel.si.firstserie.crypt.RSAEncryption;

import javax.crypto.SecretKey;
import java.security.KeyPair;

import static org.junit.Assert.*;

/**
 * TODO: Commentary
 */
public class RSAEncryptionTest {

    @Test
    public void generateRSAKey() throws Exception {
        KeyPair keyPair = RSAEncryption.generateRSAKey();

        assertEquals("RSA", keyPair.getPublic().getAlgorithm());
        assertTrue(keyPair.getPublic().getEncoded().length > 2048 /8);
        assertTrue(keyPair.getPrivate().getEncoded().length > 2048 /8);
    }

    @Test
    public void testEncryptAESKeyWithRSA() throws Exception {
        SecretKey expected = AESEncryption.generateSecretKey();

        KeyPair keyPair = RSAEncryption.generateRSAKey();

        RSAEncryption rsa = RSAEncryption.create();

        byte[] encryptedKey = rsa.encrypt(expected.getEncoded(), keyPair.getPublic());

        byte[] actual = rsa.decrypt(encryptedKey, keyPair.getPrivate());

        assertArrayEquals(expected.getEncoded(), actual);
    }

}
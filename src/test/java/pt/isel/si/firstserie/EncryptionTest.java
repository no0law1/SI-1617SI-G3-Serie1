package pt.isel.si.firstserie;

import org.junit.Before;
import org.junit.Test;
import pt.isel.si.firstserie.crypt.Encryption;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import static org.junit.Assert.*;
import static pt.isel.si.firstserie.crypt.Encryption.TAG_LENGTH;

/**
 * Aes Encryption class tests
 */
public class EncryptionTest {

    private SecretKey key;
    private Encryption aes;

    @Before
    public void setUp() throws Exception {
        key = Encryption.generateSecretKey();
        aes = Encryption.create(new GCMParameterSpec(TAG_LENGTH, Encryption.generateIV()));
    }

    @Test
    public void generateSecretKey() throws Exception {
        assertEquals("AES", key.getAlgorithm());
    }

    @Test
    public void testAESAlgorithm() throws Exception {
        byte[] expected = "password123456789".getBytes();

        byte[] cipherText = aes.encrypt(expected, key);

        byte[] actual = aes.decrypt(cipherText, key);

        assertArrayEquals(expected, actual);
    }

    @Test
    public void testFailedDecryption() throws Exception {
        byte[] expected = "olaola".getBytes();

        byte[] cipherText = aes.encrypt(expected, key);
        cipherText[1] = 0x00;

        try {
            byte[] actual = aes.decrypt(cipherText, key);
            fail(); // Should throw exception!
        } catch (Exception e) {
            // everything is fine!
        }
    }

    @Test
    public void testSplitTag() throws Exception {
        byte[] expected = "olaola".getBytes();

        byte[] cipherText = aes.encrypt(expected, key);

        System.out.println(cipherText.length);

        byte[][] res = Encryption.splitAuthTag(cipherText);
        assertEquals(2, res.length);
        assertEquals(TAG_LENGTH / 8, res[1].length);
    }

}
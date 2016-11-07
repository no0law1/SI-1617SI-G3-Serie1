package pt.isel.si.firstserie;

import org.junit.Before;
import org.junit.Test;
import pt.isel.si.firstserie.crypt.AESEncryption;

import javax.crypto.SecretKey;

import static org.junit.Assert.*;

/**
 * Aes Encryption class tests
 */
public class AESEncryptionTest {

    private SecretKey key;
    private AESEncryption aes;

    @Before
    public void setUp() throws Exception {
        key = AESEncryption.generateSecretKey();
        aes = AESEncryption.create(AESEncryption.generateIV());
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

        byte[][] res = AESEncryption.splitAuthTag(cipherText);
        assertEquals(2, res.length);
        assertEquals(AESEncryption.GCM_TAG_LENGTH / 8, res[1].length);
    }

}
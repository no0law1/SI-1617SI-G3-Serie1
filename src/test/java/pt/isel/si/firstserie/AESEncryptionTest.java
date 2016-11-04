package pt.isel.si.firstserie;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.*;

import static org.junit.Assert.*;

/**
 * TODO: Commentary
 */
public class AESEncryptionTest {

    private SecretKey key;

    private AESEncryption aes;

    @Before
    public void setUp() throws Exception {
        key = AESEncryption.generateSecretKey();
        aes = AESEncryption.create(Algorithms.AES_GCM_NOPADDING);
    }

    @Test
    public void generateSecretKey() throws Exception {
        assertEquals("AES", key.getAlgorithm());
    }

    @Test
    public void testAESAlgorithm() throws Exception {
        byte[] expected = "password123456789".getBytes();

        InputStream toEncript = new ByteArrayInputStream(expected);

        byte[] cipherText = aes.encrypt(toEncript, key);

        byte[] actual = aes.decrypt(new ByteArrayInputStream(cipherText), key);

        assertArrayEquals(expected, actual);
    }

    @Test
    public void testLargeFile() throws Exception {
        InputStream toEncript = new FileInputStream(new File("src/test/files/test.pdf"));
        OutputStream cipherText = new FileOutputStream(new File("src/test/files/cipherText.pdf"));

        aes.encrypt(toEncript, cipherText, key);

        // LOAD from file
        File cipherTextFile = new File("src/test/files/cipherText.pdf");
        File plainTextFile = new File("src/test/files/plainText.pdf");
        InputStream toDecrypt = new FileInputStream(cipherTextFile);
        OutputStream plainText = new FileOutputStream(plainTextFile);

        aes.decrypt(toDecrypt, plainText, key);
        assertTrue(cipherTextFile.exists());
        assertTrue(plainTextFile.exists());

        assertTrue(cipherTextFile.delete());
        assertTrue(plainTextFile.delete());
    }

}
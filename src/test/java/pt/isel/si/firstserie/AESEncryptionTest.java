package pt.isel.si.firstserie;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.*;

/**
 * TODO: Commentary
 */
public class AESEncryptionTest {

    private SecretKey key;

    private AESEncryption aes;

    @Before
    public void setUp() throws Exception {
        key = AESEncryption.generateSecretKey();
        aes = AESEncryption.create("AES/GCM/NoPadding");
    }

    @Test
    public void generateSecretKey() throws Exception {
        Assert.assertEquals("AES", key.getAlgorithm());
    }

    @Test
    public void testAESAlgorithm() throws Exception {
        byte[] expected = "password123456789".getBytes();

        InputStream toEncript = new ByteArrayInputStream(expected);

        byte[] cipherText = aes.encrypt(toEncript, key);

        byte[] actual = aes.decrypt(new ByteArrayInputStream(cipherText), key);

        Assert.assertArrayEquals(expected, actual);
    }

    @Test
    public void testLargeFile() throws Exception {
        InputStream toEncript = new FileInputStream(new File("src/test/files/test.pdf"));
        OutputStream cipherText = new FileOutputStream(new File("src/test/files/cipherText.txt"));

        aes.encrypt(toEncript, cipherText, key);

        // SAVE in file
        cipherText.flush();
        cipherText.close();

        // LOAD from file
        InputStream toDecrypt = new FileInputStream(new File("src/test/files/cipherText.txt"));
        OutputStream plainText = new FileOutputStream(new File("src/test/files/plainText.pdf"));

        aes.decrypt(toDecrypt, plainText, key);
    }

    @Test
    public void testError() throws Exception {
        SecretKey key = AESEncryption.generateSecretKey();

        AESEncryption aes = AESEncryption.create("AES/GCM/NoPadding");
    }

}
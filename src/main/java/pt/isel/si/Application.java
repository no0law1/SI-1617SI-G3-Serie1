package pt.isel.si;

import pt.isel.si.firstserie.AESEncryption;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.SecureRandom;

/**
 * TODO: Commentary
 */
public class Application {

    public static final int GCM_NONCE_LENGTH = 12; // in bytes

    public static void main(String[] args) throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong(); //call the strongest crypto source available in the system

        SecretKey key = AESEncryption.generateSecretKey();

        final byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce);

        AESEncryption aes = AESEncryption.create("AES/GCM/NoPadding");

        InputStream toEncript = new ByteArrayInputStream("password123456789".getBytes());

        System.out.println("password123456789");

        byte[] cipherText = aes.encrypt(toEncript, key);

        System.out.println(new String(cipherText));

        byte[] decrypted = aes.decrypt(new ByteArrayInputStream(cipherText), key);

        System.out.println(new String(decrypted));
    }
}

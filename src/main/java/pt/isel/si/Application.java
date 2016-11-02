package pt.isel.si;

import pt.isel.si.firstserie.AESEncryption;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

/**
 * TODO: Commentary
 */
public class Application {

    public static final int AES_KEY_SIZE = 128; // in bits

    public static final int GCM_NONCE_LENGTH = 12; // in bytes

    public static void main(String[] args) throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong(); //call the strongest crypto source available in the system

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE, random);
        SecretKey key = keyGen.generateKey();

        final byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce);

        AESEncryption aes = AESEncryption.create("AES/GCM/NoPadding", nonce);

        byte[] toEncript = "password123456789".getBytes();

        System.out.println(toEncript.length*8);
        System.out.println(new String(toEncript));

        byte[] cipherText = aes.encrypt(toEncript, key);

        System.out.println(new String(cipherText));

        byte[] decrypted = aes.decrypt(cipherText, key);

        System.out.println(new String(decrypted));

    }
}

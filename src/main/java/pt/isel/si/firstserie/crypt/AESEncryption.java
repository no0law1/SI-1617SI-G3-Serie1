package pt.isel.si.firstserie.crypt;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Class to handle AES Encryption and Decryption
 * Default algorithms: AES 128bits GCM
 */
public class AESEncryption {

    private static final int AES_KEY_SIZE = 128; // in bits
    private static final int GCM_NONCE_LENGTH = 12; // in bytes
    public static final int GCM_TAG_LENGTH = 128; // in bits
    private Cipher cipher;
    private GCMParameterSpec spec;

    private AESEncryption(Cipher cipher, GCMParameterSpec spec) {
        this.cipher = cipher;
        this.spec = spec;
    }

    /**
     * Instance creator
     * AES 128 GCM
     *
     * @param nonce initial vector
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public static AESEncryption create(byte[] nonce) throws NoSuchPaddingException,
            NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(Algorithms.AES_GCM_NOPADDING);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);

        return new AESEncryption(cipher, spec);
    }

    /**
     * Generate random AES secret key
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE, SecureRandom.getInstanceStrong());

        return keyGen.generateKey();
    }

    /**
     * Generate random IV
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] generateIV() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstanceStrong();
        final byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce);
        return nonce;
    }


    /**
     * Encrypt
     * @param toEncrypt
     * @param key
     * @return
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     */
    public byte[] encrypt(byte[] toEncrypt, SecretKey key) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        return cipher.doFinal(toEncrypt);
    }

    /**
     * Decrypt
     * @param toDecrypt
     * @param key
     * @return
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     */
    public byte[] decrypt(byte[] toDecrypt, SecretKey key) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(toDecrypt);
    }

    /**
     * Get the GCM Parameter
     * @return
     */
    public GCMParameterSpec getSpec() {
        return spec;
    }

    /**
     * Splite the auth tag from the encripted result
     * @return position 0 -> encripted bytes, position 1 -> auth tag
     */
    public static byte[][] splitAuthTag(byte[] encriptedBytes) {
        byte[][] res = new byte[2][];
        int tagBytes = GCM_TAG_LENGTH / 8; // bits to bytes
        res[0] = Arrays.copyOfRange(encriptedBytes, 0, encriptedBytes.length - tagBytes);
        res[1] = Arrays.copyOfRange(encriptedBytes, encriptedBytes.length - tagBytes, encriptedBytes.length);

        return res;
    }
}

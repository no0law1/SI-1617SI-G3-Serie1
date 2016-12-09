package pt.isel.si.firstserie.crypt;

import javax.crypto.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * Class to handle AES Encryption and Decryption
 * Default algorithms: AES 128bits GCM
 */
public class Encryption {

    public static final int TAG_LENGTH = 128; // in bits
    private static final int KEY_SIZE = 128; // in bits
    private static final int NONCE_LENGTH = 16; // in bytes
    private Cipher cipher;
    private AlgorithmParameterSpec spec;

    private Encryption(Cipher cipher, AlgorithmParameterSpec spec) {
        this.cipher = cipher;
        this.spec = spec;
    }

    /**
     * Instance creator
     * AES 128 GCM
     *
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public static Encryption create(String alg, AlgorithmParameterSpec parameterSpec) throws NoSuchPaddingException,
            NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(alg);

        return new Encryption(cipher, parameterSpec);
    }

    /**
     * Generate random AES secret key
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey generateSecretKey(String alg) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(alg);
        keyGen.init(KEY_SIZE, SecureRandom.getInstanceStrong());

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
        final byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        return nonce;
    }

    /**
     * Splite the auth tag from the encripted result
     * @return position 0 -> encripted bytes, position 1 -> auth tag
     */
    public static byte[][] splitAuthTag(byte[] encriptedBytes) {
        byte[][] res = new byte[2][];
        int tagBytes = TAG_LENGTH / 8; // bits to bytes
        res[0] = Arrays.copyOfRange(encriptedBytes, 0, encriptedBytes.length - tagBytes);
        res[1] = Arrays.copyOfRange(encriptedBytes, encriptedBytes.length - tagBytes, encriptedBytes.length);

        return res;
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
}

package pt.isel.si.firstserie.crypt;

import javax.crypto.*;
import java.security.*;

/**
 * RSA Encryption helper class
 * RSA OAEP
 */
public class RSAEncryption {

    private static final int RSA_KEY_SIZE = 2048;   //in bits
    private Cipher cipher;

    private RSAEncryption(Cipher cipher) {
        this.cipher = cipher;
    }

    /**
     * Create an instance of this class
     * RSA OAEP
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public static RSAEncryption create() throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(Algorithms.RSA_ECB_OAEPWithSHA1ANDMGF1PADDING);

        return new RSAEncryption(cipher);
    }

    /**
     * Generate random KeyPair
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair generateRSAKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(RSA_KEY_SIZE);

        return keygen.generateKeyPair();
    }

    /**
     * Encrypt
     * @param toEncrypt
     * @param publicKey
     * @return
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] encrypt(byte[] toEncrypt, PublicKey publicKey) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(toEncrypt);

    }

    /**
     * Decrypt
     * @param privateKey
     * @param encryptedKey
     * @return
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] decrypt(byte[] encryptedKey, PrivateKey privateKey) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedKey);
    }
}

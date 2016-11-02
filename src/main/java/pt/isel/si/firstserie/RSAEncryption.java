package pt.isel.si.firstserie;

import javax.crypto.*;
import java.security.*;

/**
 * TODO: Commentary
 */
public class RSAEncryption {

    private static final int RSA_KEY_SIZE = 2048;   //in bits

    private Cipher cipher;

    private RSAEncryption(Cipher cipher) {
        this.cipher = cipher;
    }

    public static KeyPair generateRSAKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(RSA_KEY_SIZE);
        return keygen.generateKeyPair();
    }

    public static RSAEncryption create(String protocol) throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(protocol);
        return new RSAEncryption(cipher);
    }

    public byte[] encrypt(PublicKey publicKey, SecretKey secretKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretKey.getEncoded());

    }

    public byte[] decrypt(PrivateKey privateKey, byte[] encryptedKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedKey);
    }
}

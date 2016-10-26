package pt.isel.si.firstserie;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * TODO: Commentary
 */
public class AESEncryption {

    private static final int GCM_TAG_LENGTH = 128; // in bits

    private Cipher cipher;

    private GCMParameterSpec spec;

    private AESEncryption(Cipher cipher, GCMParameterSpec spec) {
        this.cipher = cipher;
        this.spec = spec;
    }

    public byte[] encrypt(InputStream toEncrypt, SecretKey key) {
        throw new NotImplementedException();
    }

    public byte[] decrypt(InputStream toDecrypt, SecretKey key) {
        throw new NotImplementedException();
    }

    public byte[] encrypt(byte[] toEncrypt, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        //TODO: foreach update
        return cipher.doFinal(toEncrypt);
    }

    public byte[] decrypt(byte[] toDecrypt, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        //TODO: foreach update
        return cipher.doFinal(toDecrypt);
    }


    public static AESEncryption create(String protocol, byte[] nonce) throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(protocol);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);

        return new AESEncryption(cipher, spec);
    }
}

package pt.isel.si.firstserie;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * TODO: Commentary
 */
public class AESEncryption {

    public static final int AES_KEY_SIZE = 128; // in bits

    public static final int GCM_NONCE_LENGTH = 12; // in bytes

    private static final int GCM_TAG_LENGTH = 128; // in bits

    private static final int AES_CHUNKS = 16*8; // in bits

    private Cipher cipher;

    private GCMParameterSpec spec;

    private AESEncryption(Cipher cipher, GCMParameterSpec spec) {
        this.cipher = cipher;
        this.spec = spec;
    }

    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");

        keyGen.init(AES_KEY_SIZE, SecureRandom.getInstanceStrong());
        //keyGen.init(AES_KEY_SIZE);

        return keyGen.generateKey();

    }

    public static AESEncryption create(String protocol) throws NoSuchPaddingException, NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstanceStrong();

        Cipher cipher = Cipher.getInstance(protocol);

        final byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);

        return new AESEncryption(cipher, spec);
    }

    public byte[] encrypt(InputStream toEncrypt, SecretKey key) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        try(ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            try (CipherOutputStream writer = new CipherOutputStream(stream, cipher)) {
                byte[] chunk = new byte[AES_CHUNKS];

                while (toEncrypt.read(chunk) != -1) {
                    writer.write(chunk);
                }
            }
            return stream.toByteArray();
        }
    }

    public byte[] decrypt(InputStream toDecrypt, SecretKey key) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        try(ByteArrayOutputStream writer = new ByteArrayOutputStream()) {
            try (CipherInputStream reader = new CipherInputStream(toDecrypt, cipher)) {
                byte[] chunk = new byte[AES_CHUNKS];

                while (reader.read(chunk) != -1) {
                    writer.write(chunk);
                }
            }
            //TODO: should we do this here?
            String str = writer.toString();
            return str.replaceAll("\u0000", "").getBytes();
        }
    }

    public boolean encrypt(InputStream toEncrypt, OutputStream output, SecretKey key) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        try (CipherOutputStream writer = new CipherOutputStream(output, cipher)) {
            byte[] chunk = new byte[AES_CHUNKS];

            while (toEncrypt.read(chunk) != -1) {
                writer.write(chunk);
            }
        }
        return true;
    }

    public boolean decrypt(InputStream toDecrypt, OutputStream output, SecretKey key) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        try (CipherInputStream reader = new CipherInputStream(toDecrypt, cipher)) {
            byte[] chunk = new byte[AES_CHUNKS];

            while (reader.read(chunk) != -1) {
                output.write(chunk);
            }
        }
        return true;
    }

/*
    public byte[] encrypt(InputStream toEncrypt, SecretKey key) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        try(ByteArrayOutputStream stream = new ByteArrayOutputStream()){
            byte[] chunk = new byte[AES_CHUNKS];

            while (toEncrypt.read(chunk) != -1){
                stream.write(cipher.update(chunk));
            }
            byte[] mark = cipher.doFinal();
            if (mark != null) {
                stream.write(mark);
            }
            return stream.toByteArray();
        }
    }

    public byte[] decrypt(InputStream toDecrypt, SecretKey key) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        try(ByteArrayOutputStream stream = new ByteArrayOutputStream()){
            byte[] chunk = new byte[AES_CHUNKS];
            while (toDecrypt.read(chunk) != -1){
                stream.write(cipher.update(chunk));
            }
            byte[] mark = cipher.doFinal();
            if (mark != null) {
                stream.write(mark);
            }
            return stream.toByteArray();
        }
    }
*/

    public byte[] encrypt(byte[] toEncrypt, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(toEncrypt);
    }

    public byte[] decrypt(byte[] toDecrypt, SecretKey key) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(toDecrypt);
    }
}

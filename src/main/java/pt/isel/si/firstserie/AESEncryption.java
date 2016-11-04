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

    private byte[] authTag;

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

    public static AESEncryption create(String protocol, byte[] nonce) throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(protocol);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);

        return new AESEncryption(cipher, spec);
    }

    public static byte[] generateIV() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstanceStrong();
        final byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce);
        return nonce;
    }

    public byte[] encrypt(InputStream toEncrypt, SecretKey key) throws IOException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
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

    public byte[] decrypt(InputStream toDecrypt, SecretKey key) throws IOException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
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

    /**
     * Encrypts input stream to the output stream
     * Closes both input stream and output stream
     *
     * @param toEncrypt
     * @param output
     * @param key
     * @return
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public boolean encrypt(InputStream toEncrypt, OutputStream output, SecretKey key) throws IOException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        try (CipherOutputStream writer = new CipherOutputStream(output, cipher)) {
            byte[] chunk = new byte[AES_CHUNKS];

            while (toEncrypt.read(chunk) != -1) {
                writer.write(chunk);
            }
        }
        toEncrypt.close();
        return true;
    }

    /**
     * Decrypts input stream to output stream.
     * Closes both output stream and input stream
     *
     * @param toDecrypt
     * @param output
     * @param key
     * @return
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public boolean decrypt(InputStream toDecrypt, OutputStream output, SecretKey key) throws IOException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        try (CipherInputStream reader = new CipherInputStream(toDecrypt, cipher)) {
            byte[] chunk = new byte[AES_CHUNKS];

            while (reader.read(chunk) != -1) {
                output.write(chunk);
            }
        }
        output.close();
        return true;
    }

    public byte[] encrypt(byte[] toEncrypt, SecretKey key) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] encrypted = cipher.update(toEncrypt);
        authTag = cipher.doFinal();
        return encrypted;
    }

    public byte[] decrypt(byte[] toDecrypt, SecretKey key) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(toDecrypt);
    }

    public GCMParameterSpec getSpec() {
        return spec;
    }

    public byte[] getAuthTag() {
        return authTag;
    }
}

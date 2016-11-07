package pt.isel.si.firstserie.view;

import pt.isel.si.firstserie.Utils;

import java.io.IOException;

/**
 * JWE Mapper class
 * This class knows how to create a jwe
 * Right now it only produces the compact format of jwe
 */
public class JWEMapper {

    public static final String HEADER = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A128GCM\"}";

    private byte[] headers;
    private byte[] encryptedKey;
    private byte[] iv;
    private byte[] cipherText;
    private byte[] authTag;

    public JWEMapper(byte[] headers, byte[] encryptedKey, byte[] iv, byte[] cipherText, byte[] authTag) {
        this.headers = headers;
        this.encryptedKey = encryptedKey;
        this.iv = iv;
        this.cipherText = cipherText;
        this.authTag = authTag;
    }

    public String createCompactFormat() throws IOException {
        StringBuilder sb = new StringBuilder();

        sb.append(Utils.base64Encode(this.headers));
        sb.append(".");
        sb.append(Utils.base64Encode(this.encryptedKey));
        sb.append(".");
        sb.append(Utils.base64Encode(this.iv));
        sb.append(".");
        sb.append(Utils.base64Encode(this.cipherText));
        sb.append(".");
        sb.append(Utils.base64Encode(this.authTag));

        return sb.toString();
    }

}

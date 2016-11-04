package pt.isel.si.firstserie.application.view;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * TODO: Commentary
 */
public class Mapper {

    public static byte[] jwe(byte[] headers, byte[] encryptedKey, byte[] iv, byte[] cipherText, byte[] authTag) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(headers);
        stream.write(".".getBytes());
        stream.write(encryptedKey);
        stream.write(".".getBytes());
        stream.write(iv);
        stream.write(".".getBytes());
        stream.write(cipherText);
        stream.write(".".getBytes());
        stream.write(authTag);
        return stream.toByteArray();
    }

}

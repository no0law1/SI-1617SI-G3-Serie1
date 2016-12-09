package pt.isel.si.firstserie.commands;

import org.apache.commons.io.FileUtils;
import pt.isel.si.firstserie.Utils;
import pt.isel.si.firstserie.crypt.Algorithms;
import pt.isel.si.firstserie.crypt.Encryption;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.*;
import java.io.File;
import java.security.spec.KeySpec;
import java.util.Scanner;

import static pt.isel.si.firstserie.crypt.Encryption.TAG_LENGTH;

/**
 * TODO: Commentary
 */
public class DecipherJWECommandWithPassword extends CommandWithPassword {

    @Override
    public void execute(File file)
            throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);

        String password = getPassword();

        String cipheredJWE = FileUtils.readFileToString(file, "UTF-8");
        String[] data = cipheredJWE.split("\\.");

        if(data.length != 5) {
            throw new Exception("Invalid JWE file");
        }

        // Decode Headers
        String header = Utils.base64DecodeToString(data[0].getBytes());

        String[] headers = header.split(",", -1);
        byte[] salt = Utils.base64Decode(headers[2].split(":", -1)[1].replace("\"", "").getBytes());
        int itCount = Integer.parseInt(headers[3].substring(headers[3].indexOf(":")+1));

        // Generate Derived Secret Key from password
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, itCount, KEY_SIZE);
        SecretKey passwordKey =
                new SecretKeySpec(factory.generateSecret(keySpec).getEncoded(), ALGORITHM);

        // Decode IV
        byte[] iv = Utils.base64Decode(data[2].getBytes()); // Needs to be provided

        Encryption pbe = Encryption.create(ALGORITHM,
                new PBEParameterSpec(salt, MIN_ITERATION_COUNT, new IvParameterSpec(iv)));
        byte[] cek = pbe.decrypt(Utils.base64Decode(data[1].getBytes()), passwordKey);

        SecretKey cekKey = new SecretKeySpec(cek, "AES");

        byte[] cipherMessage = Utils.base64Decode(data[3].getBytes());
        byte[] authTag = Utils.base64Decode(data[4].getBytes());

        byte[] message = Utils.joinArrays(cipherMessage, authTag);

        Encryption aes = Encryption.create(Algorithms.AES_GCM_NOPADDING, new GCMParameterSpec(TAG_LENGTH, iv));
        byte[] originalMessage = aes.decrypt(message, cekKey);

        System.out.println("Where to save the decrypted file?");
        String newFile = new Scanner(System.in).nextLine();

        FileUtils.writeByteArrayToFile(new File(newFile), originalMessage);
        System.out.println("Success! Saved!");
    }

}

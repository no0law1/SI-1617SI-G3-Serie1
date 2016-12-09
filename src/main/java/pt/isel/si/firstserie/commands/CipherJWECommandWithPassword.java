package pt.isel.si.firstserie.commands;

import org.apache.commons.io.FileUtils;
import pt.isel.si.firstserie.Utils;
import pt.isel.si.firstserie.crypt.Algorithms;
import pt.isel.si.firstserie.crypt.Encryption;
import pt.isel.si.firstserie.view.JWEMapper;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.*;
import java.io.File;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Scanner;

import static pt.isel.si.firstserie.crypt.Encryption.TAG_LENGTH;

/**
 * TODO: Commentary
 */
public class CipherJWECommandWithPassword extends CommandWithPassword {

    @Override
    public void execute(File file)
            throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);

        // Generate IV and Subsequent creation of AES Cipher
        byte[] iv = Encryption.generateIV();
        Encryption aes = Encryption.create(Algorithms.AES_GCM_NOPADDING, new GCMParameterSpec(TAG_LENGTH, iv));

        byte[] salt = new byte[8];  //64 bit is good
        new SecureRandom().nextBytes(salt);
        Encryption pbe = Encryption.create(ALGORITHM,
                new PBEParameterSpec(salt, MIN_ITERATION_COUNT, new IvParameterSpec(iv)));

        // Generate password's Secret Key
        String password = getPassword();
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, MIN_ITERATION_COUNT, KEY_SIZE);
        SecretKey passwordKey =
                new SecretKeySpec(factory.generateSecret(keySpec).getEncoded(), ALGORITHM);

        // Generate Secret Key that encrypts the content
        SecretKey cekKey = Encryption.generateSecretKey("AES");

        // Header Structure
        byte[] headers = ("{" +
                "\"alg\":\""+ALGORITHM+"\"," +
                "\"enc\":\"A128GCM\"," +
                "\"p2s\":\"" + Utils.base64Encode(salt) + "\"," +
                "\"p2c\":" + MIN_ITERATION_COUNT + ",}"
        ).getBytes();

        // Encrypt cek key with password's Secret Key
        byte[] cek = pbe.encrypt(cekKey.getEncoded(), passwordKey);

        byte[] fileContent = FileUtils.readFileToByteArray(file);

        // Cipher message with cek Secret Key
        byte[] cipherMessage = aes.encrypt(fileContent, cekKey);
        byte[][] cipherMessageSplitted = Encryption.splitAuthTag(cipherMessage);

        JWEMapper jwe = new JWEMapper(headers, cek, iv, cipherMessageSplitted[0], cipherMessageSplitted[1]);

        System.out.println("Set path of ciphered file to save: ");
        String path = new Scanner(System.in).nextLine();

        FileUtils.writeStringToFile(new File(path), jwe.createCompactFormat(), "UTF-8");
        System.out.println("JWE successfully created!");
    }

}

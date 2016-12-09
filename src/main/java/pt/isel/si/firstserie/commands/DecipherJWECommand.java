package pt.isel.si.firstserie.commands;

import org.apache.commons.io.FileUtils;
import pt.isel.si.firstserie.Utils;
import pt.isel.si.firstserie.crypt.Algorithms;
import pt.isel.si.firstserie.crypt.Encryption;
import pt.isel.si.firstserie.crypt.Keystores;
import pt.isel.si.firstserie.crypt.RSAEncryption;
import pt.isel.si.firstserie.view.JWEMapper;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.security.PrivateKey;
import java.util.Scanner;

import static pt.isel.si.firstserie.crypt.Encryption.TAG_LENGTH;

/**
 * Decipher the JWE string using a .pfx file
 */
public class DecipherJWECommand implements ICommand {

    private static Scanner scanner = new Scanner(System.in);

    /**
     * To decrypt a JWE:
     * - Validate the header
     * - Decrypt the CEK using RSA with the private key in pfx
     * - Decrypt the message using the IV, cipheredMessage and the authTag
     *
     * This commands asks for the password of the .pfx
     * Asks where to save the new decrypted file
     * Saves the result in a new file
     *
     * @param file JWE file encrypted
     * @param pfx .pfx file with the private key to decrypt
     * @throws Exception
     */
    @Override
    public void execute(File file, File pfx) throws Exception {
        RSAEncryption rsa = RSAEncryption.create();

        String cipheredJWE = FileUtils.readFileToString(file, "UTF-8");
        String[] data = cipheredJWE.split("\\.");

        if(data.length != 5) {
            throw new Exception("Invalid JWE file");
        }

        String header = Utils.base64DecodeToString(data[0].getBytes());

        if(!header.equals(JWEMapper.HEADER)) {
            throw new Exception("Invalid header");
        }

        System.out.println("What is the password of the .pfx file?");
        String pass = scanner.nextLine();

        PrivateKey privateKey = Keystores.getPFXKeystoreKey(new FileInputStream(pfx), pass.toCharArray());

        byte[] decryptedAESkey = rsa.decrypt(Utils.base64Decode(data[1].getBytes()), privateKey);

        byte[] iv = Utils.base64Decode(data[2].getBytes());
        byte[] cipherMessage = Utils.base64Decode(data[3].getBytes());
        byte[] authTag = Utils.base64Decode(data[4].getBytes());

        byte[] message = Utils.joinArrays(cipherMessage, authTag);
        Encryption aes = Encryption.create(Algorithms.AES_GCM_NOPADDING, new GCMParameterSpec(TAG_LENGTH, iv));
        SecretKey aesKey = new SecretKeySpec(decryptedAESkey, 0, decryptedAESkey.length, "AES");

        byte[] originalMessage;
        try {
            originalMessage = aes.decrypt(message, aesKey);
        } catch (Exception e) {
            throw new Exception("Error decrypting the file!");
        }

        System.out.println("Where to save the decrypted file?");
        String newFile = scanner.nextLine();

        FileUtils.writeByteArrayToFile(new File(newFile), originalMessage);
        System.out.println("Success! Saved!");
    }

}

package pt.isel.si.firstserie.commands;

import org.apache.commons.io.FileUtils;
import pt.isel.si.firstserie.Utils;
import pt.isel.si.firstserie.crypt.AESEncryption;
import pt.isel.si.firstserie.crypt.Algorithms;
import pt.isel.si.firstserie.crypt.Keystores;
import pt.isel.si.firstserie.crypt.RSAEncryption;
import pt.isel.si.firstserie.view.JWEMapper;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Decipher the JWE string using a .pfx file
 */
public class DecipherJWECommand implements ICommand {

    private static Scanner scanner = new Scanner(System.in);

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

        // join cipher text + tag

        System.out.println(privateKey.getEncoded());
        System.out.println("OK");

//
//
//        byte[] iv = AESEncryption.generateIV();
//
//        AESEncryption aes = AESEncryption.create(iv);
//        SecretKey secretKey = AESEncryption.generateSecretKey();
//
//        PublicKey publicKey = null;
//        try {
//            publicKey = loadKeyFromCertificate(new FileInputStream(cert));
//        } catch (Exception e) {
//            System.out.println("Invalid Certificate!");
//            e.printStackTrace();
//            return;
//        }
//
//        byte[] fileContent = FileUtils.readFileToByteArray(file);
//
//        byte[] header = JWEMapper.HEADER.getBytes("UTF-8");
//        byte[] cek = rsa.encrypt(secretKey.getEncoded(), publicKey);
//        byte[] cipherMessage = aes.encrypt(fileContent, secretKey);
//
//        // 0 -> cipherMessage, 1 -> authTag
//        byte[][] cipherMessageSplited = AESEncryption.splitAuthTag(cipherMessage);
//
//        JWEMapper jwe = new JWEMapper(header, cek, iv, cipherMessageSplited[0], cipherMessageSplited[1]);
//
//        System.out.println("Set path of ciphered file to save: ");
//        String path = new Scanner(System.in).nextLine();
//
//        FileUtils.writeStringToFile(new File(path), jwe.createCompactFormat(), "UTF-8");
//        System.out.println("JWE succefully created!");
    }

}

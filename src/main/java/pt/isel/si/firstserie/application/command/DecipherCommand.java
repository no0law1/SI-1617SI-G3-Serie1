package pt.isel.si.firstserie.application.command;

import pt.isel.si.firstserie.AESEncryption;
import pt.isel.si.firstserie.Algorithms;
import pt.isel.si.firstserie.Keystores;
import pt.isel.si.firstserie.RSAEncryption;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.util.Scanner;

/**
 * TODO: Commentary
 */
public class DecipherCommand implements ICommand {

    @Override
    public void execute(File file, File jwFile) throws Exception {
        RSAEncryption rsa = RSAEncryption.create(Algorithms.RSA_ECB_OAEPWithSHA1ANDMGF1PADDING);
        // Decrypt uses private key, so file must be keystore (only pfx supported)

        System.out.print("Your password...");
        String pass = new Scanner(System.in).nextLine();

        PrivateKey key = Keystores.getPFXKeystoreKey(new FileInputStream(file), pass.toCharArray());

        //TODO: read file
        //TODO: map the jwe
        byte[] headers = null;
        byte[] encryptedKey = null;
        byte[] iv = null;
        byte[] cipherText = null;
        byte[] authTag = null;  //TODO: something must be done with the authTag

        byte[] secretKey = rsa.decrypt(key, encryptedKey);
        SecretKey sKey = new SecretKeySpec(secretKey, "AES");   //TODO: AES received from headers?

        //TODO: protocol must be received from headers
        AESEncryption aes = AESEncryption.create(Algorithms.AES_GCM_NOPADDING, iv);

        byte[] plainText = aes.decrypt(cipherText, sKey);


        System.out.println("Set path of deciphered file: ");
        String path = new Scanner(System.in).nextLine();

        new FileOutputStream(new File(path)).write(plainText);
    }

}

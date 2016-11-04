package pt.isel.si;

import pt.isel.si.firstserie.AESEncryption;
import pt.isel.si.firstserie.Algorithms;
import pt.isel.si.firstserie.RSAEncryption;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

/**
 * TODO: Commentary
 */
public class Application {

    public static final int GCM_NONCE_LENGTH = 12; // in bytes

    public static void main(String[] args) throws Exception {
        String jwt = "Cenas";
        if(args.length > 0){
            jwt = args[0];
        }
        RSAEncryption rsa = RSAEncryption.create(Algorithms.RSA_ECB_OAEPWithSHA1ANDMGF1PADDING);
        AESEncryption aes = AESEncryption.create(Algorithms.AES_GCM_NOPADDING);

        SecretKey uniqueKey = AESEncryption.generateSecretKey();
        KeyPair keyPair = RSAEncryption.generateRSAKey();

        PublicKey userKey = keyPair.getPublic();
        PrivateKey serverKey = keyPair.getPrivate();


        System.out.println("User sending...");
        byte[] cipheredKey = rsa.encrypt(userKey, uniqueKey);
        System.out.println("Secret Key Encrypted");
        byte[] cipherText = aes.encrypt(jwt.getBytes(), uniqueKey);
        System.out.println("JSON Web Token Encrypted");

        System.out.println("Waiting to Decrypt...");
        new Scanner(System.in).nextLine();

        System.out.println("Server Receiving...");
        byte[] secretKey = rsa.decrypt(serverKey, cipheredKey);
        System.out.println("Secret Key Decrypted");
        SecretKey appSecretKey = new SecretKeySpec(secretKey, "AES");
        System.out.println("JSON Web Token Decrypted");

        byte[] jsonWebToken = aes.decrypt(cipherText, appSecretKey);
        System.out.println("JSON Web Token: "+new String(jsonWebToken));

    }
}

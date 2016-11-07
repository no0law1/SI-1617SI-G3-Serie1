package pt.isel.si.firstserie.commands;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import pt.isel.si.firstserie.crypt.AESEncryption;
import pt.isel.si.firstserie.crypt.Certificates;
import pt.isel.si.firstserie.crypt.RSAEncryption;
import pt.isel.si.firstserie.view.JWEMapper;
import sun.nio.ch.IOUtil;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/**
 * Cipher command to encrypt a file using the public key of a certificate
 * Receives the file to encrypt and the certificate
 * JWE resulted is printed
 */
public class CipherJWECommand implements ICommand {

    @Override
    public void execute(File file, File cert) throws Exception {
        byte[] iv = AESEncryption.generateIV();
        RSAEncryption rsa = RSAEncryption.create();
        AESEncryption aes = AESEncryption.create(iv);
        SecretKey secretKey = AESEncryption.generateSecretKey();

        PublicKey publicKey = null;
        try {
            publicKey = loadKeyFromCertificate(new FileInputStream(cert));
        } catch (Exception e) {
            System.out.println("Invalid Certificate!");
            e.printStackTrace();
            return;
        }

        byte[] fileContent = FileUtils.readFileToByteArray(file);

        byte[] header = JWEMapper.HEADER.getBytes("UTF-8");
        byte[] cek = rsa.encrypt(secretKey.getEncoded(), publicKey);
        byte[] cipherMessage = aes.encrypt(fileContent, secretKey);

        // 0 -> cipherMessage, 1 -> authTag
        byte[][] cipherMessageSplited = AESEncryption.splitAuthTag(cipherMessage);

        JWEMapper jwe = new JWEMapper(header, cek, iv, cipherMessageSplited[0], cipherMessageSplited[1]);

        System.out.println("Set path of ciphered file to save: ");
        String path = new Scanner(System.in).nextLine();

        FileUtils.writeStringToFile(new File(path), jwe.createCompactFormat(), "UTF-8");
        System.out.println("JWE succefully created!");
    }

    /**
     * Loads, validates and gets the public key of a certificate
     * The validation uses all the certificates chain
     * @param cert
     * @return
     * @throws Exception
     */
    private PublicKey loadKeyFromCertificate(InputStream cert) throws Exception {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cer = (X509Certificate) cf.generateCertificate(cert);
            Certificates certificates = Certificates.create();

           return certificates.getKey(cer);
    }

}

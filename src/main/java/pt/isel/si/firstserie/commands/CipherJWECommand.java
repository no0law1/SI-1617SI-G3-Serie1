package pt.isel.si.firstserie.commands;

import org.apache.commons.io.FileUtils;
import pt.isel.si.firstserie.crypt.Algorithms;
import pt.isel.si.firstserie.crypt.Certificates;
import pt.isel.si.firstserie.crypt.Encryption;
import pt.isel.si.firstserie.crypt.RSAEncryption;
import pt.isel.si.firstserie.view.JWEMapper;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import static pt.isel.si.firstserie.crypt.Encryption.TAG_LENGTH;

/**
 * Cipher command to encrypt a file using the public key of a certificate
 * Receives the file to encrypt and the certificate
 * JWE resulted is printed
 */
public class CipherJWECommand implements ICommand {

    /**
     * Info on encrypt a JWE file:
     * https://tools.ietf.org/html/rfc7516#section-3.3
     *
     * Steps:
     * - Generate header
     * - Encrypt the AES key with RSA and a public key
     * - Encrypt the message and preserve the authTag from GCM
     *
     * @param file File to encrypt to a JWE file
     * @param cert .cert Certificate with a public key, will be validated
     * @throws Exception
     */
    @Override
    public void execute(File file, File cert) throws Exception {
        byte[] iv = Encryption.generateIV();
        RSAEncryption rsa = RSAEncryption.create();
        Encryption aes = Encryption.create(Algorithms.AES_GCM_NOPADDING, new GCMParameterSpec(TAG_LENGTH, iv));
        SecretKey secretKey = Encryption.generateSecretKey("AES");

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
        byte[][] cipherMessageSplited = Encryption.splitAuthTag(cipherMessage);

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

package pt.isel.si.firstserie.application.command;

import pt.isel.si.firstserie.AESEncryption;
import pt.isel.si.firstserie.Algorithms;
import pt.isel.si.firstserie.Certificates;
import pt.isel.si.firstserie.RSAEncryption;
import pt.isel.si.firstserie.application.view.Mapper;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedList;
import java.util.Scanner;

/**
 * TODO: Commentary
 */
public class CipherCommand implements ICommand {

    @Override
    public void execute(File file, File jwFile) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        RSAEncryption rsa = RSAEncryption.create(Algorithms.RSA_ECB_OAEPWithSHA1ANDMGF1PADDING);
        AESEncryption aes = AESEncryption.create(Algorithms.AES_GCM_NOPADDING, AESEncryption.generateIV());
        // Encrypt uses public user key, so file must be end user certificate

        X509Certificate cer = (X509Certificate) cf.generateCertificate(new FileInputStream(file));

        Certificates certificates = Certificates.create(getCertificates());

        PublicKey key = certificates.getKey(cer);

        byte[] jwt = new byte[1024];

        new FileInputStream(jwFile).read(jwt);
        //TODO: jwt may not be 1024 bytes

        SecretKey secretKey = AESEncryption.generateSecretKey();

        byte[] encryptedKey = Base64.getEncoder().encode(rsa.encrypt(key, secretKey));

        byte[] cipherText = Base64.getEncoder().encode(aes.encrypt(jwt, secretKey));

        byte[] authTag = Base64.getEncoder().encode(aes.getAuthTag());

        byte[] iv = Base64.getEncoder().encode(aes.getSpec().getIV());

        byte[] headers = Base64.getEncoder().encode(("{" +
                        "\"alg\":\""+Algorithms.RSA_ECB_OAEPWithSHA1ANDMGF1PADDING+"\"" +
                        ",\"enc\":\""+Algorithms.AES_GCM_NOPADDING+ "\"" +
                "}").getBytes());

        System.out.println("Set path of ciphered file: ");
        String path = new Scanner(System.in).nextLine();


        byte[] result = Mapper.jwe(headers, encryptedKey, iv, cipherText, authTag);

        new FileOutputStream(new File(path)).write(result);
    }

    private LinkedList<InputStream> getCertificates() throws FileNotFoundException {
        LinkedList<InputStream> list = new LinkedList<>();
        list.add(new FileInputStream(new File("src/main/files/cert.CAintermedia/CA1-int.cer")));
        list.add(new FileInputStream(new File("src/main/files/cert.CAintermedia/CA2-int.cer")));
        list.add(new FileInputStream(new File("src/main/files/cert.end.entities/Alice_1.cer")));
        list.add(new FileInputStream(new File("src/main/files/cert.end.entities/Alice_2.cer")));
        list.add(new FileInputStream(new File("src/main/files/cert.end.entities/Bob_1.cer")));
        list.add(new FileInputStream(new File("src/main/files/cert.end.entities/Bob_2.cer")));
        list.add(new FileInputStream(new File("src/main/files/cert.end.entities/Carol_2.cer")));
        list.add(new FileInputStream(new File("src/main/files/trust.anchors/CA1.cer")));
        list.add(new FileInputStream(new File("src/main/files/trust.anchors/CA2.cer")));
        return list;
    }

}

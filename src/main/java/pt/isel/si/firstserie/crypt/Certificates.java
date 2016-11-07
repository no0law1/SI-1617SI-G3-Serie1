package pt.isel.si.firstserie.crypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.util.HashSet;
import java.util.LinkedList;

/**
 * This class is projected to work with localCertificates
 * Also loads all the localCertificates from the local files
 */
public class Certificates {

    private static final String X509 = "X.509";
    private LinkedList<TrustAnchor> trustRoot;
    private LinkedList<X509Certificate> intermediates;

    private Certificates(LinkedList<TrustAnchor> trustRoot, LinkedList<X509Certificate> intermediates) {
        this.trustRoot = trustRoot;
        this.intermediates = intermediates;
    }

    /**
     * Creates the certificates chain by loading all the local certificates
     *
     * @return
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws FileNotFoundException
     */
    public static Certificates create() throws CertificateException,
            NoSuchProviderException, NoSuchAlgorithmException, FileNotFoundException {
        LinkedList<InputStream> localCertificates = loadLocalCertificates();
        CertificateFactory cf = CertificateFactory.getInstance(X509);
        LinkedList<TrustAnchor> trustRoot = new LinkedList<>();
        LinkedList<X509Certificate> intermediates = new LinkedList<>();
        for (InputStream certificateStream : localCertificates) {
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(certificateStream);
            if (isSelfSigned(certificate)) {
                trustRoot.add(new TrustAnchor(certificate, null));
            } else {
                intermediates.add(certificate);
            }
        }
        return new Certificates(trustRoot, intermediates);
    }

    /**
     * Test the certificate to see if it is self signed
     *
     * @param certificate
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    private static boolean isSelfSigned(X509Certificate certificate) throws CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException {
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (InvalidKeyException | SignatureException e) {
            return false;
        }
    }

    /**
     * Validate a certificate with certificates chain
     *
     * @param certificate
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    public boolean validate(X509Certificate certificate) throws CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        if (isSelfSigned(certificate)) {
            throw new CertificateException("Certificate is root");
        }

        // Boring! Why not ctor with cert...
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(certificate);

        PKIXBuilderParameters pkixParams =
                new PKIXBuilderParameters(new HashSet<>(trustRoot), selector);

        pkixParams.setRevocationEnabled(false);

        CertStore certStore =
                CertStore.getInstance(
                        "Collection",
                        new CollectionCertStoreParameters(new HashSet<>(intermediates))
                );
        pkixParams.addCertStore(certStore);

        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
        try {
            builder.build(pkixParams);
        } catch (CertPathBuilderException e) {
            return false;
        }
        return true;
    }

    /**
     * Gets the public key of a certificate
     *
     * @param certificate
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws CertPathBuilderException
     */
    public PublicKey getKey(X509Certificate certificate) throws CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            CertPathBuilderException {
        if (validate(certificate)) {
            return certificate.getPublicKey();
        }
        return null;
    }

    /**
     * Load all local certificates
     *
     * @throws FileNotFoundException
     */
    private static LinkedList<InputStream> loadLocalCertificates() throws FileNotFoundException {
        String[] certificates = {
                "src/main/files/cert.CAintermedia/CA1-int.cer",
                "src/main/files/cert.CAintermedia/CA2-int.cer",
                "src/main/files/cert.end.entities/Alice_1.cer",
                "src/main/files/cert.end.entities/Alice_2.cer",
                "src/main/files/cert.end.entities/Bob_1.cer",
                "src/main/files/cert.end.entities/Bob_2.cer",
                "src/main/files/cert.end.entities/Carol_2.cer",
                "src/main/files/trust.anchors/CA1.cer",
                "src/main/files/trust.anchors/CA2.cer"
        };

        LinkedList<InputStream> localCertificates = new LinkedList<>();
        for (String certificate : certificates) {
            localCertificates.add(new FileInputStream(new File(certificate)));
        }

        return localCertificates;
    }
}

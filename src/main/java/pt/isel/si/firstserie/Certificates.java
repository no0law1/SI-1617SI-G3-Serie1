package pt.isel.si.firstserie;

import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.util.HashSet;
import java.util.LinkedList;

/**
 * TODO: Commentary
 */
public class Certificates {

    private static final String X509 = "X.509";

    private LinkedList<TrustAnchor> trustRoot;
    private LinkedList<X509Certificate> intermediates;

    public Certificates(LinkedList<TrustAnchor> trustRoot, LinkedList<X509Certificate> intermediates) {
        this.trustRoot = trustRoot;
        this.intermediates = intermediates;
    }

    private static boolean isSelfSigned(X509Certificate certificate) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (InvalidKeyException | SignatureException e) {
            return false;
        }
    }

    public static Certificates create(LinkedList<InputStream> certificateStreams) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException {
        CertificateFactory cf = CertificateFactory.getInstance(X509);
        LinkedList<TrustAnchor> trustRoot = new LinkedList<>();
        LinkedList<X509Certificate> intermediates = new LinkedList<>();
        for (InputStream certificateStream : certificateStreams) {
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(certificateStream);
            if(isSelfSigned(certificate)){
                trustRoot.add(new TrustAnchor(certificate, null));
            }else {
                intermediates.add(certificate);
            }
        }
        return new Certificates(trustRoot, intermediates);
    }

    public boolean validate(X509Certificate certificate) throws CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        if(isSelfSigned(certificate)){
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

    public PublicKey getKey(X509Certificate certificate) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, CertPathBuilderException {
        if(validate(certificate)){
            return certificate.getPublicKey();
        }
        return null;
    }

    /*public Certificate[] getCertPath() {
        return certPath;
    }*/
}

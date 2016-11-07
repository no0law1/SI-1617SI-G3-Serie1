package pt.isel.si.firstserie;

import org.junit.Before;
import org.junit.Test;
import pt.isel.si.firstserie.crypt.Certificates;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

/**
 * TODO: Commentary
 */
public class CertificatesTest {

    @Test
    public void testGetKey() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cer = (X509Certificate) cf.generateCertificate(
                new FileInputStream(
                        new File("src/main/files/cert.end.entities/Carol_2.cer")));

        Certificates certificates = Certificates.create();

        assertEquals(cer.getPublicKey(), certificates.getKey(cer));
    }

    @Test
    public void testValidate() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cer = (X509Certificate) cf.generateCertificate(
                new FileInputStream(
                        new File("src/main/files/cert.end.entities/Carol_2.cer")));

        Certificates certificates = Certificates.create();

        assertTrue(certificates.validate(cer));
    }

    @Test
    public void testCreate() throws Exception {
        Certificates certificates = Certificates.create();
        assertNotNull(certificates);
    }

}
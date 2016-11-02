package pt.isel.si.firstserie;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import static org.junit.Assert.*;

/**
 * TODO: Commentary
 */
public class CertificatesTest {

    private static LinkedList<InputStream> list;

    @Before
    public void setUp() throws Exception {
        list = new LinkedList<>();
        list.add(new FileInputStream(new File("src/test/files/cert.CAintermedia/CA1-int.cer")));
        list.add(new FileInputStream(new File("src/test/files/cert.CAintermedia/CA2-int.cer")));
        list.add(new FileInputStream(new File("src/test/files/cert.end.entities/Alice_1.cer")));
        list.add(new FileInputStream(new File("src/test/files/cert.end.entities/Alice_2.cer")));
        list.add(new FileInputStream(new File("src/test/files/cert.end.entities/Bob_1.cer")));
        list.add(new FileInputStream(new File("src/test/files/cert.end.entities/Bob_2.cer")));
        list.add(new FileInputStream(new File("src/test/files/cert.end.entities/Carol_2.cer")));
        list.add(new FileInputStream(new File("src/test/files/trust.anchors/CA1.cer")));
        list.add(new FileInputStream(new File("src/test/files/trust.anchors/CA2.cer")));
        //list.add(new FileInputStream(new File("src/test/files/pfx/Alice_1.pfx")));
        //list.add(new FileInputStream(new File("src/test/files/pfx/Alice_2.pfx")));
        //list.add(new FileInputStream(new File("src/test/files/pfx/Bob_1.pfx")));
        //list.add(new FileInputStream(new File("src/test/files/pfx/Bob_2.pfx")));
        //list.add(new FileInputStream(new File("src/test/files/pfx/Carol_2.pfx")));
    }

    @Test
    public void testGetKey() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cer = (X509Certificate) cf.generateCertificate(
                new FileInputStream(
                        new File("src/test/files/cert.end.entities/Carol_2.cer")));

        Certificates certificates = Certificates.create(list);

        assertEquals(cer.getPublicKey(), certificates.getKey(cer));
    }

    @Test
    public void testValidate() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cer = (X509Certificate) cf.generateCertificate(
                new FileInputStream(
                        new File("src/test/files/cert.end.entities/Carol_2.cer")));

        Certificates certificates = Certificates.create(list);

        assertTrue(certificates.validate(cer));
    }

    @Test
    public void testCreate() throws Exception {
        Certificates certificates = Certificates.create(list);
        assertNotNull(certificates);
    }

}
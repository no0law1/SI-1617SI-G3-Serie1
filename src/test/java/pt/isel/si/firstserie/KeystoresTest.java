package pt.isel.si.firstserie;

import org.junit.Test;
import pt.isel.si.firstserie.crypt.Keystores;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;

import static org.junit.Assert.assertNotNull;

/**
 * TODO: Commentary
 */
public class KeystoresTest {

    private static final String PASS = "changeit";

    @Test
    public void testGetKeystoreKey() throws Exception {
        InputStream inputStream = new FileInputStream(new File("src/main/files/pfx/Alice_1.pfx"));

        Key key = Keystores.getPFXKeystoreKey(inputStream, PASS.toCharArray());
        assertNotNull(key);

    }

}
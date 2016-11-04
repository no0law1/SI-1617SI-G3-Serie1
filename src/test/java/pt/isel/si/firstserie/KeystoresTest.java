package pt.isel.si.firstserie;

import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;

/**
 * TODO: Commentary
 */
public class KeystoresTest {

    @Test
    public void test() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new FileInputStream(new File("src/test/files/pfx/Alice_1.pfx")), null);
        //store.load(new FileInputStream(new File("src/test/files/pfx/Alice_2.pfx")), null);
        //store.load(new FileInputStream(new File("src/test/files/pfx/Bob_1.pfx")), null);
        //store.load(new FileInputStream(new File("src/test/files/pfx/Bob_2.pfx")), null);
        //store.load(new FileInputStream(new File("src/test/files/pfx/Carol_2.pfx")), null);

    }

}
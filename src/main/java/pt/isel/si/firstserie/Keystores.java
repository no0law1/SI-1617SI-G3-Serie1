package pt.isel.si.firstserie;

import pt.isel.si.firstserie.exceptions.NoAliasException;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;

/**
 * TODO: Commentary
 */
public class Keystores {

    public static Key getPFXKeystoreKey(InputStream stream, char[] pass) throws KeyStoreException,
            CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, NoAliasException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(stream, pass);

        Enumeration<String> aliases = store.aliases();
        if(!aliases.hasMoreElements()){
            throw new NoAliasException("No Alias to get Key");
        }
        return store.getKey(aliases.nextElement(), pass);
    }
}

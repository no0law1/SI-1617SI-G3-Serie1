package pt.isel.si.firstserie.crypt;

import pt.isel.si.firstserie.exceptions.NoAliasException;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;

/**
 * Working with keystores
 */
public class Keystores {

    /**
     * Load a private key from a .pfx file
     * @param stream
     * @param pass
     * @return
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws UnrecoverableKeyException
     * @throws NoAliasException
     */
    public static PrivateKey getPFXKeystoreKey(InputStream stream, char[] pass) throws KeyStoreException,
            CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, NoAliasException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(stream, pass);

        Enumeration<String> aliases = store.aliases();
        if(!aliases.hasMoreElements()){
            throw new NoAliasException("No Alias to get Key");
        }
        return (PrivateKey) store.getKey(aliases.nextElement(), pass);
    }
}

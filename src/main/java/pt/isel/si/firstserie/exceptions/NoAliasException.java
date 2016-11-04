package pt.isel.si.firstserie.exceptions;

/**
 * Exception used when no alias is used in a {@link java.security.KeyStore}
 */
public class NoAliasException extends Exception {

    public NoAliasException() {
        super();
    }

    public NoAliasException(String message) {
        super(message);
    }

    public NoAliasException(String message, Throwable cause) {
        super(message, cause);
    }

    public NoAliasException(Throwable cause) {
        super(cause);
    }
}

package pt.isel.si.firstserie.exceptions;

/**
 * TODO: Commentary
 */
public class CertificateVerificationException extends Exception {
    public CertificateVerificationException() {
        super();
    }

    public CertificateVerificationException(String message) {
        super(message);
    }

    public CertificateVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CertificateVerificationException(Throwable cause) {
        super(cause);
    }

    protected CertificateVerificationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}

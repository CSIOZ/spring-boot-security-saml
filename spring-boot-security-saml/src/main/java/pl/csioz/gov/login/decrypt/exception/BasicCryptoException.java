package pl.csioz.gov.login.decrypt.exception;

public class BasicCryptoException extends Exception {

	private static final long serialVersionUID = 1L;

    public BasicCryptoException() {
        super();
    }

    public BasicCryptoException(String message) {
        super(message);
    }

    public BasicCryptoException(Throwable t) {
        super(t);
    }

    public BasicCryptoException(String message, Throwable t) {
        super(message, t);
    }
    
}

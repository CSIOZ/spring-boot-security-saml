package pl.csioz.gov.login.decrypt.exception;


public class BasicSamlException extends Exception {
    private static final long serialVersionUID = 1L;

    public BasicSamlException() {
        super();
    }

    public BasicSamlException(String message) {
        super(message);
    }

    public BasicSamlException(Throwable t) {
        super(t);
    }

    public BasicSamlException(String message, Throwable t) {
        super(message, t);
    }
}

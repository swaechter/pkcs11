package ch.swaechter.pkcs11;

import ch.swaechter.pkcs11.headers.CkResult;

/**
 * A checked exception that is thrown for PKCS11 related problems.
 *
 * @author Simon Wächter
 */
public class Pkcs11Exception extends Exception {

    /**
     * Optional PKCS11 result.
     */
    private final CkResult ckResult;

    /**
     * Create a new PKCS11 exception with a message.
     *
     * @param message Exception message
     */
    public Pkcs11Exception(String message) {
        super(message);
        this.ckResult = null;
    }

    /**
     * Create a new PKCS11 exception with a message and a PKCS11 result.
     *
     * @param message  Exception message
     * @param ckResult PKCS11 result
     */
    public Pkcs11Exception(String message, CkResult ckResult) {
        super(message);
        this.ckResult = ckResult;
    }

    /**
     * Create a new PKCS11 exception with a message and the original exception thrower.
     *
     * @param message   Exception message
     * @param throwable Original exception thrower
     */
    public Pkcs11Exception(String message, Throwable throwable) {
        super(message, throwable);
        this.ckResult = null;
    }

    /**
     * Get the optional PKCS11 result. The result is null for common library related errors.
     *
     * @return Optional PKCS11 result
     */
    public CkResult getCkResult() {
        return ckResult;
    }
}

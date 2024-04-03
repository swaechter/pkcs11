package ch.swaechter.pkcs11.library;

/**
 * Abstract class to hold the PKCS11 library.
 *
 * @author Simon Wächter
 */
public abstract class Pkcs11Container {

    /**
     * PKCS11 library to access the middleware.
     */
    private final Pkcs11Library pkcs11Library;

    /**
     * Create a new PKCS11 container that holds the PKCS11 library.
     *
     * @param pkcs11Library PKCS11 library
     */
    protected Pkcs11Container(Pkcs11Library pkcs11Library) {
        this.pkcs11Library = pkcs11Library;
    }

    /**
     * Get the PKCS11 library to access the middleware.
     *
     * @return PKCS11 library
     */
    public Pkcs11Library getPkcs11Library() {
        return pkcs11Library;
    }
}

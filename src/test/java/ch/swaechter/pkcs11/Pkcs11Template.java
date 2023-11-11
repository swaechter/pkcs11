package ch.swaechter.pkcs11;

/**
 * A test template to represent a PKCS11 device. Each tester might change some values to represent his device. The given
 * value match a SafeNet eToken 5110 in FIPS mode.
 *
 * @author Simon Wächter
 */
public class Pkcs11Template {

    /**
     * Name of the PKCS11 library to load.
     */
    public static final String LIBRARY_NAME = "cryptoki";

    /**
     * Security officer PIN of the PKCS11 device.
     */
    public static final String PKCS11_TOKEN_SO_PIN = "2931506555";

    /**
     * User PIN of the PKCS11 device.
     */
    public static final String PKCS11_TOKEN_PIN = "29332903";

    /**
     * Private constructor
     */
    private Pkcs11Template() {
        throw new RuntimeException("Invalid constructor call");
    }
}

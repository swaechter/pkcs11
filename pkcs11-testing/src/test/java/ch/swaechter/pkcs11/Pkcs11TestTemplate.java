package ch.swaechter.pkcs11;

/**
 * A test template to represent a PKCS11 device. Each tester might change some values to represent his device. This
 * template represents a SafeNet eToken 5110 in FIPS mode.
 *
 * @author Simon Wächter
 */
public class Pkcs11TestTemplate {

    /**
     * Name of the PKCS11 library to load.
     */
    public static final String LIBRARY_NAME = "cryptoki";

    /**
     * Security officer PIN of the PKCS11 device.
     */
    public static final String PKCS11_TOKEN_SO_PIN = "CHANGE_ME";

    /**
     * User PIN of the PKCS11 device.
     */
    public static final String PKCS11_TOKEN_PIN = "CHANGE_ME";

    /**
     * ID of the PKCS11 slot.
     */
    public static final long PKCS_SLOT_ID = 0;

    /**
     * Private constructor
     */
    private Pkcs11TestTemplate() {
        throw new RuntimeException("Invalid constructor call");
    }
}

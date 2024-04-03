package ch.swaechter.pkcs11.library.headers;

/**
 * Define various constants.
 *
 * @author Simon Wächter
 */
public class CkConstants {

    /**
     * The CKF_ARRAY_ATTRIBUTE flag identifies an attribute which consists of an array of values.
     */
    public static final int CKF_ARRAY_ATTRIBUTE = 0x40000000;

    /**
     * Private constructor
     */
    private CkConstants() {
    }
}

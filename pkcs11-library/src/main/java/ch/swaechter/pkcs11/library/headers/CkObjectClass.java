package ch.swaechter.pkcs11.library.headers;

/**
 * Define an object class.
 *
 * @author Simon Wächter
 */
public enum CkObjectClass {

    CKO_DATA(0x00000000),
    CKO_CERTIFICATE(0x00000001),
    CKO_PUBLIC_KEY(0x00000002),
    CKO_PRIVATE_KEY(0x00000003),
    CKO_SECRET_KEY(0x00000004),
    CKO_HW_FEATURE(0x00000005),
    CKO_DOMAIN_PARAMETERS(0x00000006),
    CKO_MECHANISM(0x00000007),
    CKO_OTP_KEY(0x00000008),
    CKO_VENDOR_DEFINED(0x80000000);

    /**
     * Object class value.
     */
    public final int value;

    /**
     * Define a new object class.
     *
     * @param value Object class value
     */
    CkObjectClass(int value) {
        this.value = value;
    }

    /**
     * Get the enum by value.
     *
     * @param value Value of the enum
     * @return Matching enum
     */
    public static CkObjectClass valueOf(int value) {
        for (CkObjectClass ckObjectClass : values()) {
            if (ckObjectClass.value == value) {
                return ckObjectClass;
            }
        }
        return null;
    }
}

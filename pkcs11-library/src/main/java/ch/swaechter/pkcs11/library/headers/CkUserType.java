package ch.swaechter.pkcs11.library.headers;

/**
 * Describe the user types.
 *
 * @author Simon Wächter
 */
public enum CkUserType {

    CKU_SO(0),
    CKU_USER(1),
    CKU_AUDIT(2);

    /**
     * Flag value.
     */
    public final int value;

    /**
     * Define a new user type.
     *
     * @param value User type
     */
    CkUserType(int value) {
        this.value = value;
    }

    /**
     * Get the enum by value.
     *
     * @param value Value of the enum
     * @return Matching enum
     */
    public static CkUserType valueOf(int value) {
        for (CkUserType ckUserType : values()) {
            if (ckUserType.value == value) {
                return ckUserType;
            }
        }
        return null;
    }
}

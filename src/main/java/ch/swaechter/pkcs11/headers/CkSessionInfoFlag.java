package ch.swaechter.pkcs11.headers;

/**
 * Describe the session information flags.
 *
 * @author Simon Wächter
 */
public enum CkSessionInfoFlag {

    CKF_RW_SESSION(0x00000002),
    CKF_SERIAL_SESSION(0x00000004);

    /**
     * Flag value.
     */
    public final int value;

    /**
     * Define a new session information flag.
     *
     * @param value Flag value
     */
    CkSessionInfoFlag(int value) {
        this.value = value;
    }

    /**
     * Get the enum by value.
     *
     * @param value Value of the enum
     * @return Matching enum
     */
    public static CkSessionInfoFlag valueOf(long value) {
        for (CkSessionInfoFlag ckSessionInformationFlag : values()) {
            if (ckSessionInformationFlag.value == value) {
                return ckSessionInformationFlag;
            }
        }
        return null;
    }
}

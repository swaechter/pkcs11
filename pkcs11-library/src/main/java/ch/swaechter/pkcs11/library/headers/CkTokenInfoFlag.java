package ch.swaechter.pkcs11.library.headers;

/**
 * Describe the token info flags.
 *
 * @author Simon Wächter
 */
public enum CkTokenInfoFlag {

    CKF_RNG(0x00000001),
    CKF_WRITE_PROTECTED(0x00000002),
    CKF_LOGIN_REQUIRED(0x00000004),
    CKF_USER_PIN_INITIALIZED(0x00000008),
    CKF_EXCLUSIVE_EXISTS(0x00000010),
    CKF_RESTORE_KEY_NOT_NEEDED(0x00000020),
    CKF_CLOCK_ON_TOKEN(0x00000040),
    CKF_AUDIT_PIN_INITIALIZED(0x00000080),
    CKF_PROTECTED_AUTHENTICATION_PATH(0x00000100),
    CKF_TOKEN_INITIALIZED(0x00000400),
    CKF_DUAL_CRYPTO_OPERATIONS(0x00000200),
    CKF_SECONDARY_AUTHENTICATION(0x00000800),
    CKF_USER_PIN_COUNT_LOW(0x00010000),
    CKF_USER_PIN_FINAL_TRY(0x00020000),
    CKF_USER_PIN_LOCKED(0x00040000),
    CKF_USER_PIN_TO_BE_CHANGED(0x00080000),
    CKF_SO_PIN_COUNT_LOW(0x00100000),
    CKF_SO_PIN_FINAL_TRY(0x00200000),
    CKF_SO_PIN_LOCKED(0x00400000),
    CKF_SO_PIN_TO_BE_CHANGED(0x00800000),
    CKF_ERROR_STATE(0x01000000);

    /**
     * Flag value.
     */
    public final int value;

    /**
     * Define a new token info flag.
     *
     * @param value Flag value
     */
    CkTokenInfoFlag(int value) {
        this.value = value;
    }

    /**
     * Get the enum by value.
     *
     * @param value Value of the enum
     * @return Matching enum
     */
    public static CkTokenInfoFlag valueOf(int value) {
        for (CkTokenInfoFlag ckTokenInfoFlag : values()) {
            if (ckTokenInfoFlag.value == value) {
                return ckTokenInfoFlag;
            }
        }
        return null;
    }
}

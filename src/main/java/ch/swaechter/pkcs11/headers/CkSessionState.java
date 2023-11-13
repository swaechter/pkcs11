package ch.swaechter.pkcs11.headers;

/**
 * Describe the state of a session.
 *
 * @author Simon Wächter
 */
public enum CkSessionState {

    CKS_RO_PUBLIC_SESSION(0),
    CKS_RO_USER_FUNCTIONS(1),
    CKS_RW_PUBLIC_SESSION(2),
    CKS_RW_USER_FUNCTIONS(3),
    CKS_RW_SO_FUNCTIONS(4),
    CKS_AUDIT_FUNCTIONS(5);

    /**
     * Flag value.
     */
    public final int value;

    /**
     * Define a new session flag.
     *
     * @param value Flag value
     */
    CkSessionState(int value) {
        this.value = value;
    }

    /**
     * Get the enum by value.
     *
     * @param value Value of the enum
     * @return Matching enum
     */
    public static CkSessionState valueOf(long value) {
        for (CkSessionState ckState : values()) {
            if (ckState.value == value) {
                return ckState;
            }
        }
        return null;
    }
}

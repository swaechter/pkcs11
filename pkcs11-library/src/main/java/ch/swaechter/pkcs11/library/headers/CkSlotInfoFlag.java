package ch.swaechter.pkcs11.library.headers;

/**
 * Describe the slot info flags.
 *
 * @author Simon Wächter
 */
public enum CkSlotInfoFlag {

    CKF_TOKEN_PRESENT(0x00000001),
    CKF_REMOVABLE_DEVICE(0x00000002),
    CKF_HW_SLOT(0x00000004);

    /**
     * Flag value.
     */
    public final int value;

    /**
     * Define a new slot info flag.
     *
     * @param value Flag value
     */
    CkSlotInfoFlag(int value) {
        this.value = value;
    }

    /**
     * Get the enum by value.
     *
     * @param value Value of the enum
     * @return Matching enum
     */
    public static CkSlotInfoFlag valueOf(int value) {
        for (CkSlotInfoFlag ckSlotInfoFlags : values()) {
            if (ckSlotInfoFlags.value == value) {
                return ckSlotInfoFlags;
            }
        }
        return null;
    }
}

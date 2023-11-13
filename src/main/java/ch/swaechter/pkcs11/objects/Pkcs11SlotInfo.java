package ch.swaechter.pkcs11.objects;

import ch.swaechter.pkcs11.headers.CkSlotInfo;
import ch.swaechter.pkcs11.headers.CkSlotInfoFlag;

/**
 * Object that provides the slot info from the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class Pkcs11SlotInfo {

    /**
     * Internal CK_SLOT_INFO struct.
     */
    private final CkSlotInfo ckSlotInfo;

    /**
     * Create a new PKCS11 slot info object.
     *
     * @param ckSlotInfo Internal CK_SLOT_INFO struct
     */
    public Pkcs11SlotInfo(CkSlotInfo ckSlotInfo) {
        this.ckSlotInfo = ckSlotInfo;
    }

    /**
     * Get the description of the slot.
     *
     * @return Slot description
     */
    public String getSlotDescription() {
        return ckSlotInfo.slotDescription().trim();
    }

    /**
     * Get the identifier of the slot manufacturer.
     *
     * @return Slot manufacturer
     */
    public String getManufacturerId() {
        return ckSlotInfo.manufacturerId().trim();
    }

    /**
     * Get the bits flags that provide capabilities of the slot.
     *
     * @return Bit flags
     */
    public long getFlags() {
        return ckSlotInfo.flags();
    }

    /**
     * Get the hardware version of the slot.
     *
     * @return Hardware version of the slot
     */
    public Pkcs11Version getHardwareVersion() {
        return new Pkcs11Version(ckSlotInfo.hardwareVersion().major(), ckSlotInfo.hardwareVersion().minor());
    }

    /**
     * Get the firmware version of the slot.
     *
     * @return Firmware version of the slot
     */
    public Pkcs11Version getFirmwareVersion() {
        return new Pkcs11Version(ckSlotInfo.firmwareVersion().major(), ckSlotInfo.firmwareVersion().minor());
    }

    /**
     * Check if the slot contains a token. This refers to the time the object was created. This flag is mostly used for
     * smartcards readers (Slot) where the smartcard (Token) can be removed.
     *
     * @return Slot contains token or not
     */
    public boolean isTokenPresent() {
        return (ckSlotInfo.flags() & CkSlotInfoFlag.CKF_TOKEN_PRESENT.value) != 0L;
    }

    /**
     * Check if the token is removable from the slot. This refers to the time the object was created. This flag is
     * mostly used for smartcards readers (Slot) where the smartcard (Token) can be removed or USB tokens.
     *
     * @return Token is removable or not
     */
    public boolean isRemovableDevice() {
        return (ckSlotInfo.flags() & CkSlotInfoFlag.CKF_REMOVABLE_DEVICE.value) != 0L;
    }

    /**
     * Check if the token is a hardware device or a software implementation, e.g. SoftHSM.
     *
     * @return Token is a hardware device or not
     */
    public boolean isHardwareSlot() {
        return (ckSlotInfo.flags() & CkSlotInfoFlag.CKF_HW_SLOT.value) != 0L;
    }
}

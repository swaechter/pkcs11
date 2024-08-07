package ch.swaechter.pkcs11.library.objects;

import ch.swaechter.pkcs11.library.Pkcs11Container;
import ch.swaechter.pkcs11.library.Pkcs11Exception;
import ch.swaechter.pkcs11.library.Pkcs11Library;
import ch.swaechter.pkcs11.library.headers.CkSlotInfo;

/**
 * Object that represents a slot in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class Pkcs11Slot extends Pkcs11Container {

    /**
     * ID of the slot.
     */
    private final long slotId;

    /**
     * Create a new PKCS11 slot object.
     *
     * @param pkcs11Library PKCS11 library to access the middleware
     * @param slotId        ID of the slot
     */
    public Pkcs11Slot(Pkcs11Library pkcs11Library, long slotId) {
        super(pkcs11Library);
        this.slotId = slotId;
    }

    /**
     * Get the slot ID.
     *
     * @return ID of the slot
     */
    public long getSlotId() {
        return slotId;
    }

    /**
     * Get the slot info.
     *
     * @return Slot info
     * @throws Pkcs11Exception Thrown if the slot info can't be read
     */
    public Pkcs11SlotInfo getSlotInfo() throws Pkcs11Exception {
        // Get the slot info
        CkSlotInfo ckSlotInfo = getPkcs11Library().C_GetSlotInfo(slotId);

        // Return the slot info
        return new Pkcs11SlotInfo(ckSlotInfo);
    }

    /**
     * Get the token.
     *
     * @return Token
     */
    public Pkcs11Token getToken() {
        // Return the token
        return new Pkcs11Token(getPkcs11Library(), slotId);
    }
}

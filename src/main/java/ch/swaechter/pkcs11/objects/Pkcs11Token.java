package ch.swaechter.pkcs11.objects;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.Pkcs11Library;
import ch.swaechter.pkcs11.headers.CkTokenInfo;

/**
 * Object that represents a token in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class Pkcs11Token {

    /**
     * PKCS11 library to access the middleware.
     */
    private final Pkcs11Library pkcs11Library;

    /**
     * ID of the slot.
     */
    private final long slotId;

    /**
     * Create a new PKCS11 token object.
     *
     * @param pkcs11Library PKCS11 library to access the middleware
     * @param slotId        ID of the slot
     */
    public Pkcs11Token(Pkcs11Library pkcs11Library, long slotId) {
        this.pkcs11Library = pkcs11Library;
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
     * Get the token info.
     *
     * @return Token info
     * @throws Pkcs11Exception Thrown if the token is not present or the info can't be read
     */
    public Pkcs11TokenInfo getTokenInfo() throws Pkcs11Exception {
        // Get the token info
        CkTokenInfo ckTokenInfo = pkcs11Library.C_GetTokenInfo(slotId);

        // Return the token info
        return new Pkcs11TokenInfo(ckTokenInfo);
    }
}

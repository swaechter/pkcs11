package ch.swaechter.pkcs11.library.objects;

import ch.swaechter.pkcs11.library.Pkcs11Container;
import ch.swaechter.pkcs11.library.Pkcs11Exception;
import ch.swaechter.pkcs11.library.Pkcs11Library;
import ch.swaechter.pkcs11.library.headers.CkSessionInfoFlag;
import ch.swaechter.pkcs11.library.headers.CkTokenInfo;

/**
 * Object that represents a token in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class Pkcs11Token extends Pkcs11Container {

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
     * Get the token info.
     *
     * @return Token info
     * @throws Pkcs11Exception Thrown if the token is not present or the info can't be read
     */
    public Pkcs11TokenInfo getTokenInfo() throws Pkcs11Exception {
        // Get the token info
        CkTokenInfo ckTokenInfo = getPkcs11Library().C_GetTokenInfo(slotId);

        // Return the token info
        return new Pkcs11TokenInfo(ckTokenInfo);
    }

    /**
     * Open a new PKCS11 session in the PKCS11 middleware.
     *
     * @param rwSession     Flag whether the session is read/write or read-only.
     * @param serialSession Flag used for backwards compatibility. Always set to true
     * @return Opened session
     * @throws Pkcs11Exception Thrown if the slot does not exist or the session can't be opened
     */
    public Pkcs11Session openSession(boolean rwSession, boolean serialSession) throws Pkcs11Exception {
        // Build the flags
        long flags = 0L;
        flags |= rwSession ? CkSessionInfoFlag.CKF_RW_SESSION.value : 0L;
        flags |= serialSession ? CkSessionInfoFlag.CKF_SERIAL_SESSION.value : 0L;

        // Open a new session
        long sessionId = getPkcs11Library().C_OpenSession(slotId, flags);

        // Return the session
        return new Pkcs11Session(getPkcs11Library(), sessionId);
    }

    /**
     * Close all existing sessions for the slot in the PKCS11 middleware.
     *
     * @throws Pkcs11Exception Thrown if the sessions can't be closed
     */
    public void closeAllSessions() throws Pkcs11Exception {
        // Close all sessions on the token
        getPkcs11Library().C_CloseAllSessions(slotId);
    }

    /**
     * Check whether a login is required.
     *
     * @return Login is required or not
     * @throws Pkcs11Exception Thrown if the token info can't be read
     */
    public boolean isLoginRequired() throws Pkcs11Exception {
        // Get the token info
        Pkcs11TokenInfo pkcs11TokenInfo = getTokenInfo();
        return pkcs11TokenInfo.isLoginRequired();
    }
}

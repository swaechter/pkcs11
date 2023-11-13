package ch.swaechter.pkcs11.objects;

import ch.swaechter.pkcs11.headers.CkSessionInfo;
import ch.swaechter.pkcs11.headers.CkSessionInfoFlag;
import ch.swaechter.pkcs11.headers.CkSessionState;

/**
 * Object that provides the session info from the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class Pkcs11SessionInfo {

    /**
     * Internal CK_SESSION_INFO struct.
     */
    private final CkSessionInfo ckSessionInfo;

    /**
     * Create a new PKCS11 session info object.
     *
     * @param ckSessionInfo Internal CK_SESSION_INFO struct
     */
    public Pkcs11SessionInfo(CkSessionInfo ckSessionInfo) {
        this.ckSessionInfo = ckSessionInfo;
    }

    /**
     * Get the ID of the slot that interfaces with the token.
     *
     * @return ID of the slot
     */
    public long getSlotId() {
        return ckSessionInfo.slotId();
    }

    /**
     * Get the state of the session.
     *
     * @return State of the session
     */
    public CkSessionState getSessionState() {
        return ckSessionInfo.state();
    }

    /**
     * Get the bit flags that define the type of session.
     *
     * @return Bit flags of the session
     */
    public long getFlags() {
        return ckSessionInfo.flags();
    }

    /**
     * Get an error code defined by the cryptographic device. Used for errors not covered by Cryptoki.
     *
     * @return Error code of the session
     */
    public long getDeviceError() {
        return ckSessionInfo.deviceError();
    }

    /**
     * Check if the session is read/write or read-only
     *
     * @return Read/write or read-only
     */
    public boolean isRwSession() {
        return (ckSessionInfo.flags() & CkSessionInfoFlag.CKF_RW_SESSION.value) != 0L;
    }

    /**
     * Check whether the session is serial. Provided for backwards compatibility.
     *
     * @return Serial session or not
     */
    public boolean isSerialSession() {
        return (ckSessionInfo.flags() & CkSessionInfoFlag.CKF_SERIAL_SESSION.value) != 0L;
    }
}

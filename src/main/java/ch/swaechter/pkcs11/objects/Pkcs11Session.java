package ch.swaechter.pkcs11.objects;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.Pkcs11Library;
import ch.swaechter.pkcs11.headers.CkSessionInfo;
import ch.swaechter.pkcs11.headers.CkUserType;

import java.io.Closeable;
import java.io.IOException;

/**
 * Object that represents a slot in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class Pkcs11Session implements Closeable {

    /**
     * PKCS11 library to access the middleware.
     */
    private final Pkcs11Library pkcs11Library;

    /**
     * ID of the session.
     */
    private final long sessionId;

    /**
     * Create a new PKCS11 session object.
     *
     * @param pkcs11Library PKCS11 library to access the middleware
     * @param sessionId     ID of the session
     */
    public Pkcs11Session(Pkcs11Library pkcs11Library, long sessionId) {
        this.pkcs11Library = pkcs11Library;
        this.sessionId = sessionId;
    }

    /**
     * Get the session ID.
     *
     * @return ID of the session
     */
    public long getSessionId() {
        return sessionId;
    }

    /**
     * Get the session info.
     *
     * @return Session info
     * @throws Pkcs11Exception Thrown if the session info can't be read
     */
    public Pkcs11SessionInfo getSessionInfo() throws Pkcs11Exception {
        // Get the session info
        CkSessionInfo ckSessionInfo = pkcs11Library.C_GetSessionInfo(sessionId);

        // Return the session info
        return new Pkcs11SessionInfo(ckSessionInfo);
    }

    /**
     * Log a user into the token.
     *
     * @param ckUserType Type of the user
     * @param pinOrPuk   PIN/PUK or null in case the token has a protected authentication path
     * @throws Pkcs11Exception Thrown for an error during login
     */
    public void loginUser(CkUserType ckUserType, String pinOrPuk) throws Pkcs11Exception {
        // Login the user
        pkcs11Library.C_Login(sessionId, ckUserType, pinOrPuk);
    }

    /**
     * Log a user out of the token.
     *
     * @throws Pkcs11Exception Thrown for an error during logout
     */
    public void logoutUser() throws Pkcs11Exception {
        // Logout the user
        pkcs11Library.C_Logout(sessionId);
    }

    /**
     * The session supports the try-with-resource statement. A caller can create the session via try and close will
     * automatically close the session, even when an exception is thrown after opening it.
     */
    @Override
    public void close() throws IOException {
        try {
            // Close the session
            pkcs11Library.C_CloseSession(sessionId);
        } catch (Pkcs11Exception exception) {
            throw new IOException(exception.getMessage(), exception);
        }
    }
}

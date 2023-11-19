package ch.swaechter.pkcs11.objects;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.Pkcs11Library;
import ch.swaechter.pkcs11.headers.CkAttributeValue;
import ch.swaechter.pkcs11.headers.CkSessionInfo;
import ch.swaechter.pkcs11.headers.CkUserType;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
     * Find all objects for the given search template.
     *
     * @param searchTemplate Search template
     * @return All matching and found objects
     * @throws Pkcs11Exception Thrown if the find operation fails
     */
    public List<Long> findObjects(List<CkAttributeValue> searchTemplate) throws Pkcs11Exception {
        return findObjects(searchTemplate, 10);
    }

    /**
     * Find all objects for the given search template.
     *
     * @param searchTemplate Search template
     * @param batchSize      Batch size to retrieve objects
     * @return All matching and found objects
     * @throws Pkcs11Exception Thrown if the find operation fails
     */
    public List<Long> findObjects(List<CkAttributeValue> searchTemplate, int batchSize) throws Pkcs11Exception {
        // Check the batch size
        if (batchSize < 1 || batchSize > 1000) {
            throw new Pkcs11Exception("The batch size has to be in the range 1 to 1000, not " + batchSize);
        }

        // Flag whether the find was initialized
        boolean findInitialized = false;

        try {
            // Define the current objects list and a list with all found object IDs
            List<Long> currentObjectIds;
            List<Long> allObjectIds = new ArrayList<>();

            // Initialize the object finding
            pkcs11Library.C_FindObjectsInit(sessionId, searchTemplate);
            findInitialized = true;

            // Search as long we find new objects/no empty array
            do {
                // Find the current objects
                currentObjectIds = pkcs11Library.C_FindObjects(sessionId, batchSize);

                // Add the current objects
                allObjectIds.addAll(currentObjectIds);
            } while (!currentObjectIds.isEmpty() && currentObjectIds.size() == batchSize);

            // Return the found object IDs
            return allObjectIds;
        } finally {
            // Finalize the object finding if required
            if (findInitialized) {
                pkcs11Library.C_FindObjectsFinal(sessionId);
            }
        }
    }

    /**
     * Mix in additional seed material to the random number generator.
     *
     * @param seed Additional seed material
     * @throws Pkcs11Exception Thrown if the random number generator can't be seeded
     */
    public void seedRandom(byte[] seed) throws Pkcs11Exception {
        // Seed the random number generator
        pkcs11Library.C_SeedRandom(sessionId, seed);
    }

    /**
     * Generates random data for the given length.
     *
     * @param length Length of the random data
     * @return Random date with the length
     * @throws Pkcs11Exception Thrown if the random data can't be generated
     */
    public byte[] generateRandom(int length) throws Pkcs11Exception {
        // Generate random data
        return pkcs11Library.C_GenerateRandom(sessionId, length);
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

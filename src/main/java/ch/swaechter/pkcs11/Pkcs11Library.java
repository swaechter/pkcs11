package ch.swaechter.pkcs11;

import ch.swaechter.pkcs11.functions.*;
import ch.swaechter.pkcs11.headers.*;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.Arena;
import java.lang.foreign.Linker;
import java.lang.foreign.SymbolLookup;
import java.util.List;

/**
 * The PKCS11 library allows direct interactions with the PKCS11 middleware. The library is as simple as possible and
 * doesn't provide a convenient object-oriented view like the PKCS11 module, e.g. many operations are handle based.
 *
 * @author Simon Wächter
 */
public class Pkcs11Library {

    /**
     * Linker to lookup functions in the library.
     */
    private final Linker linker;

    /**
     * Symbol lookup to resolve functions from the linker.
     */
    private final SymbolLookup loaderLookup;

    /**
     * Template that provides the architecture specific memory layouts, e.g. packed or aligned structs.
     */
    private final Template template;

    /**
     * Create a new PKCS11 library and load the given PKCS11 middleware.
     *
     * @param libraryName Name of the PKCS11 middleware that has to be on the library path
     * @param template    Template that provides the architecture specific memory layouts
     * @throws Pkcs11Exception Thrown if the PKCS11 middleware can't be loaded
     */
    public Pkcs11Library(String libraryName, Template template) throws Pkcs11Exception {
        // Load the PKCS11 library
        loadPkcs11Library(libraryName);

        // Create the linker and lookup
        this.linker = Linker.nativeLinker();
        this.loaderLookup = SymbolLookup.loaderLookup();

        // Set the template
        this.template = template;
    }

    /**
     * Load the given PKCS11 middleware.
     *
     * @param libraryName Name of the PKCS11 middleware
     * @throws Pkcs11Exception Thrown if the PKCS11 middleware can't be loaded
     */
    private void loadPkcs11Library(String libraryName) throws Pkcs11Exception {
        try {
            // Load the library
            System.loadLibrary(libraryName);
        } catch (Exception exception) {
            throw new Pkcs11Exception("Unable to load the PKCS11 library: " + exception.getMessage(), exception);
        }
    }

    /**
     * Initialize the PKCS11 middleware.
     *
     * @throws Pkcs11Exception Thrown if the PKCS11 middleware can't be initialized
     */
    public void C_Initialize() throws Pkcs11Exception {
        // Invoke the function
        InitializeFunction function = new InitializeFunction(linker, loaderLookup, template);
        function.invokeFunction();
    }

    /**
     * Finalize the PKCS11 middleware.
     *
     * @throws Pkcs11Exception Thrown if the PKCS11 middleware can't be finalized
     */
    public void C_Finalize() throws Pkcs11Exception {
        // Invoke the function
        FinalizeFunction finalizeFunction = new FinalizeFunction(linker, loaderLookup, template);
        finalizeFunction.invokeFunction();
    }

    /**
     * Get info from the PKCS11 middleware.
     *
     * @return PKCS11 middleware information
     * @throws Pkcs11Exception Thrown if the info can't be read
     */
    public CkInfo C_GetInfo() throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            GetInfoFunction function = new GetInfoFunction(linker, loaderLookup, template);
            return function.invokeFunction(arena);
        }
    }

    /**
     * Get all slots from the PKCS11 middleware.
     *
     * @param tokenPresent Flag whether the tokens have to be present
     * @return List with the slot IDs
     * @throws Pkcs11Exception Thrown if the slot list can't be read
     */
    public List<Long> C_GetSlotList(boolean tokenPresent) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            GetSlotListFunction function = new GetSlotListFunction(linker, loaderLookup, template);
            return function.invokeFunction(arena, tokenPresent);
        }
    }

    /**
     * Get the slot information from a slot.
     *
     * @param slotId ID of the slot
     * @return Slot information
     * @throws Pkcs11Exception Thrown if the slot does not exist or can't be read
     */
    public CkSlotInfo C_GetSlotInfo(long slotId) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            GetSlotInfoFunction function = new GetSlotInfoFunction(linker, loaderLookup, template);
            return function.invokeFunction(arena, slotId);
        }
    }

    /**
     * Get the token information from a slot.
     *
     * @param slotId ID of the slot
     * @return Token information
     * @throws Pkcs11Exception Thrown if the slot does not exist, the token is not present or can't be read
     */
    public CkTokenInfo C_GetTokenInfo(long slotId) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            GetTokenInfoFunction function = new GetTokenInfoFunction(linker, loaderLookup, template);
            return function.invokeFunction(arena, slotId);
        }
    }

    /**
     * Open a new session.
     *
     * @param slotId ID of the slot
     * @param flags  Session flags
     * @return ID of the session
     * @throws Pkcs11Exception Thrown if the slot does not exist or the session can't be opened
     */
    public long C_OpenSession(long slotId, long flags) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            OpenSessionFunction function = new OpenSessionFunction(linker, loaderLookup, template);
            return function.invokeFunction(arena, slotId, flags);
        }
    }

    /**
     * Close an existing session.
     *
     * @param sessionId ID of the session
     * @throws Pkcs11Exception Thrown if the session does not exist or can't be closed
     */
    public void C_CloseSession(long sessionId) throws Pkcs11Exception {
        // Invoke the function
        CloseSessionFunction function = new CloseSessionFunction(linker, loaderLookup, template);
        function.invokeFunction(sessionId);
    }

    /**
     * Close all existing sessions for the slot.
     *
     * @param slotId ID of the slot
     * @throws Pkcs11Exception Thrown if the slot does not exist or the sessions can't be closed
     */
    public void C_CloseAllSessions(long slotId) throws Pkcs11Exception {
        // Invoke the function
        CloseAllSessionFunction function = new CloseAllSessionFunction(linker, loaderLookup, template);
        function.invokeFunction(slotId);
    }

    /**
     * Get the session information.
     *
     * @param sessionId ID of the session
     * @return Session information
     * @throws Pkcs11Exception Thrown if the session does not exist or the session info can't be read
     */
    public CkSessionInfo C_GetSessionInfo(long sessionId) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            GetSessionInfoFunction function = new GetSessionInfoFunction(linker, loaderLookup, template);
            return function.invokeFunction(arena, sessionId);
        }
    }

    /**
     * Log a user into the token.
     *
     * @param sessionId  ID of the session
     * @param ckUserType Type of the user
     * @param pinOrPuk   PIN/PUK or null in case the token has a protected authentication path
     * @throws Pkcs11Exception Thrown if the session does not exist or an error during login
     */
    public void C_Login(long sessionId, CkUserType ckUserType, String pinOrPuk) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            LoginFunction function = new LoginFunction(linker, loaderLookup, template);
            function.invokeFunction(arena, sessionId, ckUserType, pinOrPuk);
        }
    }

    /**
     * Log a user out of the token.
     *
     * @param sessionId ID of the session
     * @throws Pkcs11Exception Thrown if the session does not exist or an error during logout
     */
    public void C_Logout(long sessionId) throws Pkcs11Exception {
        // Invoke the function
        LogoutFunction function = new LogoutFunction(linker, loaderLookup, template);
        function.invokeFunction(sessionId);
    }

    /**
     * Obtains the size of an object in bytes.
     *
     * @param sessionId      ID of the session
     * @param objectHandleId ID of the object handle
     * @return Size of the object
     * @throws Pkcs11Exception Thrown if the session/object does not exist or can't be read
     */
    public long C_GetObjectSize(long sessionId, long objectHandleId) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            GetObjectSizeFunction function = new GetObjectSizeFunction(linker, loaderLookup, template);
            return function.invokeFunction(arena, sessionId, objectHandleId);
        }
    }

    /**
     * Obtains an attribute value of an object.
     *
     * @param sessionId      ID of the session
     * @param objectHandleId ID of the object handle
     * @param attributes   Attributes to read
     * @return Attribute values
     * @throws Pkcs11Exception Thrown if the session/object do not exist or the attributes can't be read
     */
    public List<byte[]> C_GetAttributeValue(long sessionId, long objectHandleId, List<CkAttribute> attributes) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            GetAttributeFunction function = new GetAttributeFunction(linker, loaderLookup, template);
            return function.invokeFunction(arena, sessionId, objectHandleId, attributes);
        }
    }

    /**
     * Initializes an object search operation.
     *
     * @param sessionId                 ID of the session
     * @param searchTemplate Search template
     * @throws Pkcs11Exception Thrown if the session does not exist or the search operation can't be initialized
     */
    public void C_FindObjectsInit(long sessionId, List<CkAttributeValue> searchTemplate) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            FindObjectsInitFunction function = new FindObjectsInitFunction(linker, loaderLookup, template);
            function.invokeFunction(arena, sessionId, searchTemplate);
        }
    }

    /**
     * Continues an object search operation.
     *
     * @param sessionId  ID of the session
     * @param maxObjects Maximum number of object handles returned
     * @return Found object handles
     * @throws Pkcs11Exception Thrown if the session does not exist or the search operation can't succeed
     */
    public List<Long> C_FindObjects(long sessionId, int maxObjects) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            FindObjectsFunction function = new FindObjectsFunction(linker, loaderLookup, template);
            return function.invokeFunction(arena, sessionId, maxObjects);
        }
    }

    /**
     * Finishes an object search operation.
     *
     * @param sessionId ID of the session
     * @throws Pkcs11Exception Thrown if the session does not exist or the search operation can't be finalized
     */
    public void C_FindObjectsFinal(long sessionId) throws Pkcs11Exception {
        // Invoke the function
        FindObjectsFinalFunction function = new FindObjectsFinalFunction(linker, loaderLookup, template);
        function.invokeFunction(sessionId);
    }

    /**
     * Initializes a signature operation.
     *
     * @param sessionId   ID of the session
     * @param ckMechanism ID of the mechanism
     * @param keyHandleId ID of the key handle
     * @throws Pkcs11Exception Thrown if the session does not exist or the sign init operation can't succeed
     */
    public void C_SignInit(long sessionId, CkMechanism ckMechanism, long keyHandleId) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            SignInitFunction function = new SignInitFunction(linker, loaderLookup, template);
            function.invokeFunction(arena, sessionId, ckMechanism, keyHandleId);
        }
    }

    /**
     * Sign single-part data.
     *
     * @param sessionId     ID of the session
     * @param message       Message to sign
     * @param signatureSize Size of the signature buffer
     * @return Signed message
     * @throws Pkcs11Exception Thrown if the session does not exist or the sign operation can't succeed
     */
    public byte[] C_Sign(long sessionId, byte[] message, int signatureSize) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            SignFunction function = new SignFunction(linker, loaderLookup, template);
            return function.invokeFunction(arena, sessionId, message, signatureSize);
        }
    }

    /**
     * Mix in additional seed material to the random number generator.
     *
     * @param sessionId ID of the session
     * @param seed      Additional seed material
     * @throws Pkcs11Exception Thrown if the random number generator can't be seeded
     */
    public void C_SeedRandom(long sessionId, byte[] seed) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            SeedRandomFunction function = new SeedRandomFunction(linker, loaderLookup, template);
            function.invokeFunction(arena, sessionId, seed);
        }
    }

    /**
     * Generates random data for the given length.
     *
     * @param sessionId ID of the session
     * @param length    Length of the random data
     * @return Random date with the length
     * @throws Pkcs11Exception Thrown if the random data can't be generated
     */
    public byte[] C_GenerateRandom(long sessionId, int length) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            GenerateRandomFunction function = new GenerateRandomFunction(linker, loaderLookup, template);
            return function.invokeFunction(arena, sessionId, length);
        }
    }
}

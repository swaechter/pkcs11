package ch.swaechter.pkcs11.library;

import ch.swaechter.pkcs11.library.headers.*;
import ch.swaechter.pkcs11.library.platforms.LinuxPkcs11Library;
import ch.swaechter.pkcs11.library.platforms.WindowsPkcs11Library;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Create a new abstract PKCS11 library that contains the core logic. The struct related information are handled
 * by the core PKCS11 template, powered by a platform dependent implementation.
 *
 * @author Simon Wächter
 */
public abstract class Pkcs11Library extends Pkcs11Template {

    /**
     * @param libraryName Name of the PKCS11 middleware that has to be on the library path
     * @return Loaded, but un-initialized PKCS11 library
     * @throws Pkcs11Exception Thrown if the PKCS11 middleware can't be loaded
     */
    public static Pkcs11Library detectPlatform(String libraryName) throws Pkcs11Exception {
        // Ensure we are not running in a 32-bit JVM
        String jvmArch = System.getProperty("os.arch");
        if (jvmArch.contains("x86")) {
            throw new Pkcs11Exception("This PKCS11 project can't run in a 32-bit JVM. Please use a 64-bit JVM.");
        }

        // Get the operating system name
        String operatingSystemName = System.getProperty("os.name").toLowerCase();
        if (operatingSystemName.contains("win")) {
            return new WindowsPkcs11Library(libraryName);
        } else if (operatingSystemName.contains("nux")) {
            return new LinuxPkcs11Library(libraryName);
        } else {
            throw new Pkcs11Exception("Unsupported template platform!");
        }
    }

    /**
     * Create a new PKCS11 library and load the given PKCS11 middleware.
     *
     * @param libraryName Name of the PKCS11 middleware that has to be on the library path
     * @throws Pkcs11Exception Thrown if the PKCS11 middleware can't be loaded
     */
    public Pkcs11Library(String libraryName) throws Pkcs11Exception {
        super(libraryName);
    }

    /**
     * Initializes Cryptoki.
     *
     * @throws Pkcs11Exception Thrown if the function invocation fails
     */
    public void C_Initialize() throws Pkcs11Exception {
        try {
            // Allocate the init arguments value
            MemorySegment pInitArgsMemorySegment = MemorySegment.NULL;

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_Initialize", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact(pInitArgsMemorySegment));

            // Check the result
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_Initialize failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_Initialize failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Clean up miscellaneous Cryptoki-associated resources.
     *
     * @throws Pkcs11Exception Thrown if the function invocation fails
     */
    public void C_Finalize() throws Pkcs11Exception {
        try {
            // Allocate the pReserved value
            MemorySegment pReservedMemorySegment = MemorySegment.NULL;

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_Finalize", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact(pReservedMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_Finalize failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_Finalize failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Obtains general information about Cryptoki.
     *
     * @return General information
     * @throws Pkcs11Exception Thrown if the function invocation fails
     */
    public CkInfo C_GetInfo() throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Allocate the info struct
            MemorySegment infoMemorySegment = arena.allocate(ckInfoLayout);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetInfo", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact(infoMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetInfo failed", ckResult);
            }

            // Get the cryptoki version
            MemorySegment cryptokiNamedMemorySegment = invokeExact(ckInfoCryptokiVersionHandle, infoMemorySegment);
            byte cryptokiMajor = (byte) ckVersionMajorVarHandle.get(cryptokiNamedMemorySegment);
            byte cryptokiMinor = (byte) ckVersionMinorHandle.get(cryptokiNamedMemorySegment);
            CkVersion cryptokiVersion = new CkVersion(cryptokiMajor, cryptokiMinor);

            // Get the manufacturer ID
            String manufacturerId = readFixedString(infoMemorySegment, ckInfoLayout, "manufacturerId");

            // Vet the library version
            MemorySegment libraryNamedMemorySegment = invokeExact(ckInfoLibraryVersionHandle, infoMemorySegment);
            byte libraryMajor = (byte) ckVersionMajorVarHandle.get(libraryNamedMemorySegment);
            byte libraryMinor = (byte) ckVersionMinorHandle.get(libraryNamedMemorySegment);
            CkVersion libraryVersion = new CkVersion(libraryMajor, libraryMinor);

            // Get the flags
            Long flags = readLong(infoMemorySegment, ckInfoLayout, "flags");

            // Get the library description
            String libraryDescription = readFixedString(infoMemorySegment, ckInfoLayout, "libraryDescription");

            // Return the info
            return new CkInfo(
                cryptokiVersion,
                manufacturerId,
                flags,
                libraryDescription,
                libraryVersion
            );
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetInfo failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Obtains a list of slots in the system.
     *
     * @param tokenPresent Flag whether to only list slots with a token present
     * @return All slot IDs
     * @throws Pkcs11Exception Thrown if the function invocation fails
     */
    public List<Long> C_GetSlotList(boolean tokenPresent) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Define the flag to search for all slots present/not present
            byte presentFlag = tokenPresent ? (byte) 0x1 : (byte) 0x0;

            // Define the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_BYTE, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetSlotList", functionDescriptor);

            // Allocate an array with maxSlots items/potential tokens
            MemorySegment slotIdCountMemorySegment = allocateLong(arena);
            MemorySegment slotIdsMemorySegment = MemorySegment.NULL;

            // Invoke the function to get the number of slots
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact(presentFlag, slotIdsMemorySegment, slotIdCountMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetSlotList failed", ckResult);
            }

            // Allocate a buffer for the given slots
            int slotCount = (int) readLong(slotIdCountMemorySegment);
            slotIdsMemorySegment = allocateLong(arena, slotCount);

            // Invoke the function to get the slot list
            ckResult = CkResult.valueOf((int) methodHandle.invokeExact(presentFlag, slotIdsMemorySegment, slotIdCountMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetSlotList failed", ckResult);
            }

            // Convert the slot IDs
            List<Long> slotIds = new ArrayList<>(slotCount);
            for (int i = 0; i < slotCount; i++) {
                // Get slot ID at the given offset
                long slotId = readLongFromArray(slotIdsMemorySegment, i);
                slotIds.add(slotId);
            }

            // Return the slots
            return slotIds;
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetSlotList failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Obtains information about a particular slot.
     *
     * @param slotId ID of the slot
     * @return Slot information
     * @throws Pkcs11Exception Thrown if the slot does not exist or can't be read
     */
    public CkSlotInfo C_GetSlotInfo(long slotId) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Allocate the slot info struct
            MemorySegment slotInfoMemorySegment = arena.allocate(ckSlotInfoLayout);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetSlotInfo", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invoke((int) slotId, slotInfoMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetSlotInfo failed", ckResult);
            }

            // Get the slot description
            String slotDescription = readFixedString(slotInfoMemorySegment, ckSlotInfoLayout, "slotDescription");

            // Get the manufacturer ID
            String manufacturerId = readFixedString(slotInfoMemorySegment, ckSlotInfoLayout, "manufacturerId");

            // Get the flags
            Long flags = readLong(slotInfoMemorySegment, ckSlotInfoLayout, "flags");

            // Get the hardware version
            MemorySegment hardwareNamedMemorySegment = invokeExact(ckSlotInfoHardwareVersionHandle, slotInfoMemorySegment);
            byte hardwareMajor = (byte) ckVersionMajorVarHandle.get(hardwareNamedMemorySegment);
            byte hardwareMinor = (byte) ckVersionMinorHandle.get(hardwareNamedMemorySegment);
            CkVersion hardwareVersion = new CkVersion(hardwareMajor, hardwareMinor);

            // Get the firmware version
            MemorySegment firmwareNamedMemorySegment = invokeExact(ckSlotInfoFirmwareVersionHandle, slotInfoMemorySegment);
            byte firmwareMajor = (byte) ckVersionMajorVarHandle.get(firmwareNamedMemorySegment);
            byte firmwareMinor = (byte) ckVersionMinorHandle.get(firmwareNamedMemorySegment);
            CkVersion firmwareVersion = new CkVersion(firmwareMajor, firmwareMinor);

            // Return the slot info
            return new CkSlotInfo(
                slotDescription,
                manufacturerId,
                flags,
                hardwareVersion,
                firmwareVersion
            );
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetSlotList failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Obtains information about a particular token.
     *
     * @param slotId ID of the slot
     * @return Token information
     * @throws Pkcs11Exception Thrown if the slot does not exist or can't be read
     */
    public CkTokenInfo C_GetTokenInfo(long slotId) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Allocate the token info struct
            MemorySegment tokenInfoMemorySegment = arena.allocate(ckTokenInfoLayout);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetTokenInfo", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) slotId, tokenInfoMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetTokenInfo failed", ckResult);
            }

            // Get the label
            String label = readFixedString(tokenInfoMemorySegment, ckTokenInfoLayout, "label");

            // Get the manufacturer ID
            String manufacturerId = readFixedString(tokenInfoMemorySegment, ckTokenInfoLayout, "manufacturerId");

            // Get the model
            String model = readFixedString(tokenInfoMemorySegment, ckTokenInfoLayout, "model");

            // Get the serial number
            String serialNumber = readFixedString(tokenInfoMemorySegment, ckTokenInfoLayout, "serialNumber");

            // Get all values
            Long flags = readLong(tokenInfoMemorySegment, ckTokenInfoLayout, "flags");
            Long maxSessionCount = readLong(tokenInfoMemorySegment, ckTokenInfoLayout, "maxSessionCount");
            Long sessionCount = readLong(tokenInfoMemorySegment, ckTokenInfoLayout, "sessionCount");
            Long maxRwSessionCount = readLong(tokenInfoMemorySegment, ckTokenInfoLayout, "maxRwSessionCount");
            Long rwSessionCount = readLong(tokenInfoMemorySegment, ckTokenInfoLayout, "rwSessionCount");
            Long maxPinLen = readLong(tokenInfoMemorySegment, ckTokenInfoLayout, "maxPinLen");
            Long minPinLen = readLong(tokenInfoMemorySegment, ckTokenInfoLayout, "minPinLen");
            Long totalPublicMemory = readLong(tokenInfoMemorySegment, ckTokenInfoLayout, "totalPublicMemory");
            Long freePublicMemory = readLong(tokenInfoMemorySegment, ckTokenInfoLayout, "freePublicMemory");
            Long totalPrivateMemory = readLong(tokenInfoMemorySegment, ckTokenInfoLayout, "totalPrivateMemory");
            Long freePrivateMemory = readLong(tokenInfoMemorySegment, ckTokenInfoLayout, "freePrivateMemory");

            // Get the hardware version
            MemorySegment hardwareNamedMemorySegment = invokeExact(ckTokenInfoHardwareVersionHandle, tokenInfoMemorySegment);
            byte hardwareMajor = (byte) ckVersionMajorVarHandle.get(hardwareNamedMemorySegment);
            byte hardwareMinor = (byte) ckVersionMinorHandle.get(hardwareNamedMemorySegment);
            CkVersion hardwareVersion = new CkVersion(hardwareMajor, hardwareMinor);

            // Get the firmware version
            MemorySegment firmwareNamedMemorySegment = invokeExact(ckTokenInfoFirmwareVersionHandle, tokenInfoMemorySegment);
            byte firmwareMajor = (byte) ckVersionMajorVarHandle.get(firmwareNamedMemorySegment);
            byte firmwareMinor = (byte) ckVersionMinorHandle.get(firmwareNamedMemorySegment);
            CkVersion firmwareVersion = new CkVersion(firmwareMajor, firmwareMinor);

            // Get the time
            String utcTime = readFixedString(tokenInfoMemorySegment, ckTokenInfoLayout, "utcTime");

            // Return the token info
            return new CkTokenInfo(
                label,
                manufacturerId,
                model,
                serialNumber,
                flags,
                maxSessionCount,
                sessionCount,
                maxRwSessionCount,
                rwSessionCount,
                maxPinLen,
                minPinLen,
                totalPublicMemory,
                freePublicMemory,
                totalPrivateMemory,
                freePrivateMemory,
                hardwareVersion,
                firmwareVersion,
                utcTime
            );
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetTokenInfo failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Opens a connection between an application and a particular token or sets up an application callback for token insertion.
     *
     * @param slotId ID of the slot
     * @param flags  Session flags
     * @return ID of the session
     * @throws Pkcs11Exception Thrown if the slot does not exist or the session can't be opened
     */
    public long C_OpenSession(long slotId, long flags) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Allocate all values
            MemorySegment pApplicationMemorySegment = MemorySegment.NULL;
            MemorySegment notifyMemorySegment = MemorySegment.NULL;
            MemorySegment sessionIdMemorySegment = allocateLong(arena);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_OpenSession", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) slotId, (int) flags, pApplicationMemorySegment, notifyMemorySegment, sessionIdMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_OpenSession failed", ckResult);
            }

            // Get and return the session ID
            return readLong(sessionIdMemorySegment);
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_OpenSession failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Closes a session.
     *
     * @param sessionId ID of the session
     * @throws Pkcs11Exception Thrown if the session does not exist or can't be closed
     */
    public void C_CloseSession(long sessionId) throws Pkcs11Exception {
        try {
            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_CloseSession", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_CloseSession failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_CloseSession failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Closes all sessions with a token.
     *
     * @param slotId ID of the slot
     * @throws Pkcs11Exception Thrown if the slot does not exist or the sessions can't be closed
     */
    public void C_CloseAllSessions(long slotId) throws Pkcs11Exception {
        try {
            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_CloseAllSessions", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) slotId));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_CloseAllSessions failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_CloseAllSessions failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Obtains information about the session.
     *
     * @param sessionId ID of the session
     * @return Session information
     * @throws Pkcs11Exception Thrown if the session does not exist or the session info can't be read
     */
    public CkSessionInfo C_GetSessionInfo(long sessionId) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Allocate the layout
            MemorySegment sessionInfoMemorySegment = arena.allocate(ckSessionInfoLayout);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetSessionInfo", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, sessionInfoMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetSessionInfo failed", ckResult);
            }

            // Get the slot ID
            Long slotId = readLong(sessionInfoMemorySegment, ckSessionInfoLayout, "slotId");

            // Get the state
            long state = readLong(sessionInfoMemorySegment, ckSessionInfoLayout, "state");
            CkSessionState sessionStateEnum = CkSessionState.valueOf(state);

            // Get the flags
            Long flags = readLong(sessionInfoMemorySegment, ckSessionInfoLayout, "flags");

            // Get the device error
            Long deviceError = readLong(sessionInfoMemorySegment, ckSessionInfoLayout, "deviceError");

            // Return the session info
            return new CkSessionInfo(
                slotId,
                sessionStateEnum,
                flags,
                deviceError
            );
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetSessionInfo failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Logs into a token.
     *
     * @param sessionId  ID of the session
     * @param ckUserType Type of the user
     * @param pinOrPuk   PIN/PUK or null in case the token has a protected authentication path
     * @throws Pkcs11Exception Thrown if the session does not exist or an error during login
     */
    public void C_Login(long sessionId, CkUserType ckUserType, String pinOrPuk) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Convert the user type
            long userType = ckUserType.value;

            // Convert the PIN/PUK or use null for a token with a protected authentication path
            MemorySegment pinOrPukMemorySegment = pinOrPuk != null ? arena.allocateArray(ValueLayout.JAVA_BYTE, pinOrPuk.getBytes(StandardCharsets.US_ASCII)) : MemorySegment.NULL;

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_Login", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, (int) userType, pinOrPukMemorySegment, (int) pinOrPukMemorySegment.byteSize()));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_Login failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_Login failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Logs out from a token.
     *
     * @param sessionId ID of the session
     * @throws Pkcs11Exception Thrown if the session does not exist or an error during logout
     */
    public void C_Logout(long sessionId) throws Pkcs11Exception {
        try {
            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_Logout", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_Login failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_Logout failed: " + throwable.getMessage(), throwable);
        }
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
            // Allocate a pointer for the object size
            MemorySegment objectSizeMemorySegment = allocateLong(arena);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetObjectSize", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, (int) objectHandleId, objectSizeMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetObjectSize failed", ckResult);
            }

            // Return the object size
            return readLong(objectSizeMemorySegment);
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetObjectSize failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Obtains an attribute value of an object.
     *
     * @param sessionId      ID of the session
     * @param objectHandleId ID of the object handle
     * @param attributes     Attributes to read
     * @return Attribute values
     * @throws Pkcs11Exception Thrown if the session does not exist or the attributes can't be read
     */
    public List<byte[]> C_GetAttributeValue(long sessionId, long objectHandleId, List<CkAttribute> attributes) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Define the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_GetAttributeValue", functionDescriptor);

            // Create a struct array with the attributes
            MemorySegment attributesMemorySegment = arena.allocate(MemoryLayout.sequenceLayout(attributes.size(), ckAttributeLayout));

            // Add all attributes
            for (int i = 0; i < attributes.size(); i++) {
                // Get the attribute
                CkAttribute ckAttribute = attributes.get(i);
                ckAttributeTypeHandle.set(attributesMemorySegment.asSlice(i * ckAttributeLayout.byteSize()), ckAttribute.value);
                ckAttributePValueHandle.set(attributesMemorySegment.asSlice(i * ckAttributeLayout.byteSize()), MemorySegment.NULL);
                ckAttributeValueLenHandle.set(attributesMemorySegment.asSlice(i * ckAttributeLayout.byteSize()), 0);
            }

            // Invoke the function to get the sizes we have to allocate
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, (int) objectHandleId, attributesMemorySegment, 1));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetAttributeValue failed", ckResult);
            }

            // Allocate the buffer for all attribute values
            List<MemorySegment> allocatedMemorySegments = new ArrayList<>(attributes.size());
            for (int i = 0; i < attributes.size(); i++) {
                // Get the attribute size
                long size = 2000;

                // Allocate the attribute value
                MemorySegment attributeValueMemorySegment = arena.allocateArray(JAVA_BYTE, size);
                allocatedMemorySegments.add(attributeValueMemorySegment);

                // Set the attribute value pointer
                ckAttributePValueHandle.set(attributesMemorySegment.asSlice(i * ckAttributeLayout.byteSize()), attributeValueMemorySegment);
                ckAttributeValueLenHandle.set(attributesMemorySegment.asSlice(i * ckAttributeLayout.byteSize()), (int) attributeValueMemorySegment.byteSize());
            }

            // Invoke the function to get the attribute values
            ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, (int) objectHandleId, attributesMemorySegment, 1));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetAttributeValue failed", ckResult);
            }

            // Convert all values
            List<byte[]> returnValues = new ArrayList<>(attributes.size());
            for (int i = 0; i < attributes.size(); i++) {
                byte[] data = readBytes(allocatedMemorySegments.get(i));
                long value = (long) ckAttributeValueLenHandle.get(attributesMemorySegment.asSlice(i * ckAttributeLayout.byteSize()));
                byte[] realData = Arrays.copyOf(data, (int) value);
                returnValues.add(realData);
            }

            // Return the values
            return returnValues;
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetAttributeValue failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Initializes an object search operation.
     *
     * @param sessionId      ID of the session
     * @param searchTemplate Search template
     * @throws Pkcs11Exception Thrown if the session does not exist or the search operation can't be initialized
     */
    public void C_FindObjectsInit(long sessionId, List<CkAttributeValue> searchTemplate) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Create a struct array with the attributes
            MemorySegment attributesMemorySegment = arena.allocate(MemoryLayout.sequenceLayout(searchTemplate.size(), ckAttributeLayout));

            // Fill in the values
            for (int i = 0; i < searchTemplate.size(); i++) {
                // Get the attribute
                CkAttributeValue ckAttribute = searchTemplate.get(i);

                // Set the type
                ckAttributeTypeHandle.set(attributesMemorySegment.asSlice(i * ckAttributeLayout.byteSize()), ckAttribute.type().value);

                // Set the value
                if (ckAttribute.pValue() != null) {
                    // Allocate the object class
                    MemorySegment objectClassMemorySegment = allocateLong(arena, ckAttribute.pValue());

                    // Set the value and length
                    ckAttributePValueHandle.set(attributesMemorySegment.asSlice(i * ckAttributeLayout.byteSize()), objectClassMemorySegment);
                    ckAttributeValueLenHandle.set(attributesMemorySegment.asSlice(i * ckAttributeLayout.byteSize()), (int) objectClassMemorySegment.byteSize());
                } else {
                    // Set a missing value with zero length
                    ckAttributePValueHandle.set(attributesMemorySegment.asSlice(i * ckAttributeLayout.byteSize()), MemorySegment.NULL);
                    ckAttributeValueLenHandle.set(attributesMemorySegment.asSlice(i * ckAttributeLayout.byteSize()), 0);
                }
            }

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_FindObjectsInit", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, attributesMemorySegment, 1));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_FindObjectsInit failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_FindObjectsInit failed: " + throwable.getMessage(), throwable);
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
            // Allocate the object count
            MemorySegment objectCountMemorySegment = allocateLong(arena);

            // Allocate the object handle array
            MemorySegment objectHandlesMemorySegment = allocateLongArray(arena, maxObjects);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_FindObjects", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, objectHandlesMemorySegment, maxObjects, objectCountMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_FindObjects failed", ckResult);
            }

            // Get all object handles
            int foundObjectHandles = (int) readLong(objectCountMemorySegment);
            List<Long> objectIds = new ArrayList<>(foundObjectHandles);
            for (int i = 0; i < foundObjectHandles; i++) {
                // Get the object handle
                long foundObjectHandle = readLongFromArray(objectHandlesMemorySegment, i);
                objectIds.add(foundObjectHandle);
            }

            // Return the object IDs
            return objectIds;
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_FindObjects failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Finishes an object search operation.
     *
     * @param sessionId ID of the session
     * @throws Pkcs11Exception Thrown if the session does not exist or the search operation can't be finalized
     */
    public void C_FindObjectsFinal(long sessionId) throws Pkcs11Exception {
        try {
            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_FindObjectsFinal", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_FindObjectsFinal failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_FindObjectsFinal failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Initializes a message-digesting operation.
     *
     * @param sessionId ID of the session
     * @param mechanism ID of the mechanism
     * @throws Pkcs11Exception Thrown if the session does not exist or the digest init operation can't succeed
     */
    public void C_DigestInit(long sessionId, CkMechanism mechanism) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Allocate the mechanism
            MemorySegment mechanismMemorySegment = arena.allocate(ckMechanismLayout);
            ckMechanismMechanismHandle.set(mechanismMemorySegment, mechanism.value);
            ckMechanismPParameterHandle.set(mechanismMemorySegment, MemorySegment.NULL);
            ckMechanismParameterLenHandle.set(mechanismMemorySegment, 0);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_DigestInit", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, mechanismMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_DigestInit failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_DigestInit failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Digests single-part data.
     *
     * @param sessionId ID of the session
     * @param data      Data to digest
     * @return Digested data
     * @throws Pkcs11Exception Thrown if the session does not exist or the digest operation can't succeed
     */
    public byte[] C_Digest(long sessionId, byte[] data) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Define the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_Digest", functionDescriptor);

            // Allocate an array for the data
            MemorySegment messageMemorySegment = arena.allocateArray(JAVA_BYTE, data);

            // Allocate a value to hold the digest length
            MemorySegment digestMemorySegment = MemorySegment.NULL;
            MemorySegment digestLengthMemorySegment = allocateLong(arena);

            // Invoke the function to get the digest length
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, messageMemorySegment, (int) messageMemorySegment.byteSize(), digestMemorySegment, digestLengthMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_Digest failed", ckResult);
            }

            // Allocate the digest buffer
            int digestLength = (int) readLong(digestLengthMemorySegment);
            digestMemorySegment = arena.allocateArray(JAVA_BYTE, digestLength);

            // Invoke the function to digest the data
            ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, messageMemorySegment, (int) messageMemorySegment.byteSize(), digestMemorySegment, digestLengthMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_Digest failed", ckResult);
            }

            // Return the digest
            return readBytes(digestMemorySegment);
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_Digest failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Continues a multiple-part digesting operation.
     *
     * @param sessionId ID of the session
     * @param data      Data to digest
     * @throws Pkcs11Exception Thrown if the session does not exist or the digest update operation can't succeed
     */
    public void C_DigestUpdate(long sessionId, byte[] data) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Allocate an array for the data
            MemorySegment messageMemorySegment = arena.allocateArray(JAVA_BYTE, data);

            // Invoke the function to digest the data
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_DigestUpdate", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, messageMemorySegment, (int) messageMemorySegment.byteSize()));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_DigestUpdate failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_DigestUpdate failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Finishes a multiple-part digesting operation.
     *
     * @param sessionId ID of the session
     * @return Digested data
     * @throws Pkcs11Exception Thrown if the session does not exist or the digest final operation can't succeed
     */
    public byte[] C_DigestFinal(long sessionId) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Define the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_DigestFinal", functionDescriptor);

            // Allocate a value to hold the digest length
            MemorySegment digestMemorySegment = MemorySegment.NULL;
            MemorySegment digestLengthMemorySegment = allocateLong(arena);

            // Invoke the function to get the digest length
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, digestMemorySegment, digestLengthMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_DigestFinal failed", ckResult);
            }

            // Allocate the digest buffer
            int digestLength = (int) readLong(digestLengthMemorySegment);
            digestMemorySegment = arena.allocateArray(JAVA_BYTE, digestLength);

            // Invoke the function to digest the data
            ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, digestMemorySegment, digestLengthMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_DigestFinal failed", ckResult);
            }

            // Return the digest
            return readBytes(digestMemorySegment);
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_DigestFinal failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Initializes a signature operation.
     *
     * @param sessionId   ID of the session
     * @param mechanism   ID of the mechanism
     * @param keyHandleId ID of the key handle
     * @throws Pkcs11Exception Thrown if the session does not exist or the sign init operation can't succeed
     */
    public void C_SignInit(long sessionId, CkMechanism mechanism, long keyHandleId) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Allocate the mechanism
            MemorySegment mechanismMemorySegment = arena.allocate(ckMechanismLayout);
            ckMechanismMechanismHandle.set(mechanismMemorySegment, mechanism.value);
            ckMechanismPParameterHandle.set(mechanismMemorySegment, MemorySegment.NULL);
            ckMechanismParameterLenHandle.set(mechanismMemorySegment, 0);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_SignInit", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, mechanismMemorySegment, (int) keyHandleId));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_SignInit failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_SignInit failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Signs single-part data.
     *
     * @param sessionId     ID of the session
     * @param message       Message to sign
     * @param signatureSize Size of the signature buffer
     * @return Signed message
     * @throws Pkcs11Exception Thrown if the session does not exist or the sign operation can't succeed
     */
    public byte[] C_Sign(long sessionId, byte[] message, int signatureSize) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Allocate an array for the message
            MemorySegment messageMemorySegment = arena.allocateArray(JAVA_BYTE, message);

            // Allocate an array for the signed data and a pointer for the signature length
            MemorySegment signedDataMemorySegment = arena.allocateArray(JAVA_BYTE, signatureSize);
            MemorySegment signedDataLengthMemorySegment = allocateLong(arena, signedDataMemorySegment.byteSize());

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_Sign", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, messageMemorySegment, (int) messageMemorySegment.byteSize(), signedDataMemorySegment, signedDataLengthMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_Sign failed", ckResult);
            }

            // Return the signed message
            int signedMessageLength = (int) readLong(signedDataLengthMemorySegment);
            byte[] signedMessage = readBytes(signedDataMemorySegment);
            return Arrays.copyOf(signedMessage, signedMessageLength);
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_Sign failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Mixes in additional seed material to the random number generator.
     *
     * @param sessionId ID of the session
     * @param seed      Additional seed material
     * @throws Pkcs11Exception Thrown if the random number generator can't be seeded
     */
    public void C_SeedRandom(long sessionId, byte[] seed) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Allocate the seed buffer
            MemorySegment seedBufferMemorySegment = arena.allocateArray(ValueLayout.JAVA_BYTE, seed);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_SeedRandom", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, seedBufferMemorySegment, (int) seedBufferMemorySegment.byteSize()));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_SeedRandom failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_SeedRandom failed: " + throwable.getMessage(), throwable);
        }
    }

    /**
     * Generates random data.
     *
     * @param sessionId ID of the session
     * @param length    Length of the random data
     * @return Random date with the length
     * @throws Pkcs11Exception Thrown if the random data can't be generated
     */
    public byte[] C_GenerateRandom(long sessionId, int length) throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Allocate the random buffer
            MemorySegment randomBufferMemorySegment = arena.allocateArray(ValueLayout.JAVA_BYTE, length);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_GenerateRandom", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, randomBufferMemorySegment, (int) randomBufferMemorySegment.byteSize()));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GenerateRandom failed", ckResult);
            }

            // Convert and return the buffer
            return readBytes(randomBufferMemorySegment);
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GenerateRandom failed: " + throwable.getMessage(), throwable);
        }
    }
}

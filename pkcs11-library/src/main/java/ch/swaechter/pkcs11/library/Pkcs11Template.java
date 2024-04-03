package ch.swaechter.pkcs11.library;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.util.Optional;

/**
 * Base template that requires platform specific implementations of the long method and of the native structs.
 *
 * @author Simon Wächter
 */
public abstract class Pkcs11Template {

    /**
     * Linker to lookup functions in the library.
     */
    private final Linker linker;

    /**
     * Symbol lookup to resolve functions from the linker.
     */
    private final SymbolLookup symbolLookup;

    /**
     * CK_VERSION group layout.
     */
    protected final GroupLayout ckVersionLayout;

    /**
     * CK_VERSION major var handle.
     */
    protected final VarHandle ckVersionMajorVarHandle;

    /**
     * CK_VERSION minor var handle.
     */
    protected final VarHandle ckVersionMinorHandle;

    /**
     * CK_INFO group layout.
     */
    protected final GroupLayout ckInfoLayout;

    /**
     * CK_INFO cryptoki version var handle.
     */
    protected final MethodHandle ckInfoCryptokiVersionHandle;

    /**
     * CK_INFO library version var handle.
     */
    protected final MethodHandle ckInfoLibraryVersionHandle;

    /**
     * CK_SLOT_INFO group layout.
     */
    protected final GroupLayout ckSlotInfoLayout;

    /**
     * CK_SLOT_INFO hardware version var handle.
     */
    protected final MethodHandle ckSlotInfoHardwareVersionHandle;

    /**
     * CK_SLOT_INFO firmware version var handle.
     */
    protected final MethodHandle ckSlotInfoFirmwareVersionHandle;

    /**
     * CK_TOKEN_INFO group layout.
     */
    protected final GroupLayout ckTokenInfoLayout;

    /**
     * CK_TOKEN_INFO hardware version var handle.
     */
    protected final MethodHandle ckTokenInfoHardwareVersionHandle;

    /**
     * CK_TOKEN_INFO firmware version var handle.
     */
    protected final MethodHandle ckTokenInfoFirmwareVersionHandle;

    /**
     * CK_SESSION_INFO group layout.
     */
    protected final GroupLayout ckSessionInfoLayout;

    /**
     * CK_ATTRIBUT group layout.
     */
    protected final GroupLayout ckAttributeLayout;

    /**
     * CK_ATTRIBUT type var handle.
     */
    protected final VarHandle ckAttributeTypeHandle;

    /**
     * CK_ATTRIBUT pValue var handle.
     */
    protected final VarHandle ckAttributePValueHandle;

    /**
     * CK_ATTRIBUT valueLen var handle.
     */
    protected final VarHandle ckAttributeValueLenHandle;

    /**
     * CK_MECHANISM group layout.
     */
    protected final GroupLayout ckMechanismLayout;

    /**
     * CK_MECHANISM mechanism var handle.
     */
    protected final VarHandle ckMechanismMechanismHandle;

    /**
     * CK_MECHANISM pParameter var handle.
     */
    protected final VarHandle ckMechanismPParameterHandle;

    /**
     * CK_MECHANISM parameterLen var handle.
     */
    protected final VarHandle ckMechanismParameterLenHandle;

    /**
     * Create a new template and initialize all group layouts and var handles.
     */
    public Pkcs11Template(String libraryName) throws Pkcs11Exception {
        // Load the PKCS11 library
        loadPkcs11Library(libraryName);

        // Create the linker and lookup
        linker = Linker.nativeLinker();
        symbolLookup = SymbolLookup.loaderLookup();

        // Build the version layout and handles
        this.ckVersionLayout = buildCkVersionLayout();
        this.ckVersionMajorVarHandle = ckVersionLayout.varHandle(MemoryLayout.PathElement.groupElement("major"));
        this.ckVersionMinorHandle = ckVersionLayout.varHandle(MemoryLayout.PathElement.groupElement("minor"));

        // Build the info layout and handles
        this.ckInfoLayout = buildCkInfoLayout();
        this.ckInfoCryptokiVersionHandle = ckInfoLayout.sliceHandle(MemoryLayout.PathElement.groupElement("cryptokiVersion"));
        this.ckInfoLibraryVersionHandle = ckInfoLayout.sliceHandle(MemoryLayout.PathElement.groupElement("libraryVersion"));

        // Build the slot info layout and handles
        this.ckSlotInfoLayout = buildCkSlotInfoLayout();
        this.ckSlotInfoHardwareVersionHandle = ckSlotInfoLayout.sliceHandle(MemoryLayout.PathElement.groupElement("hardwareVersion"));
        this.ckSlotInfoFirmwareVersionHandle = ckSlotInfoLayout.sliceHandle(MemoryLayout.PathElement.groupElement("firmwareVersion"));

        // Build the token info layout and handles
        this.ckTokenInfoLayout = buildCkTokenInfoLayout();
        this.ckTokenInfoHardwareVersionHandle = ckTokenInfoLayout.sliceHandle(MemoryLayout.PathElement.groupElement("hardwareVersion"));
        this.ckTokenInfoFirmwareVersionHandle = ckTokenInfoLayout.sliceHandle(MemoryLayout.PathElement.groupElement("firmwareVersion"));

        // Build the session info layout
        this.ckSessionInfoLayout = buildCkSessionInfoLayout();

        // Build the attribute layout and handles
        this.ckAttributeLayout = buildCkAttributeLayout();
        this.ckAttributeTypeHandle = ckAttributeLayout.varHandle(MemoryLayout.PathElement.groupElement("type"));
        this.ckAttributePValueHandle = ckAttributeLayout.varHandle(MemoryLayout.PathElement.groupElement("pValue"));
        this.ckAttributeValueLenHandle = ckAttributeLayout.varHandle(MemoryLayout.PathElement.groupElement("valueLen"));

        // Build the mechanism layout and handles
        this.ckMechanismLayout = buildCkMechanismLayout();
        this.ckMechanismMechanismHandle = ckMechanismLayout.varHandle(MemoryLayout.PathElement.groupElement("mechanism"));
        this.ckMechanismPParameterHandle = ckMechanismLayout.varHandle(MemoryLayout.PathElement.groupElement("pParameter"));
        this.ckMechanismParameterLenHandle = ckMechanismLayout.varHandle(MemoryLayout.PathElement.groupElement("parameterLen"));
    }

    /**
     * Load the given PKCS11 middleware.
     *
     * @param libraryName Name of the PKCS11 middleware
     * @throws Pkcs11Exception Thrown if the PKCS11 middleware can't be loaded
     */
    protected void loadPkcs11Library(String libraryName) throws Pkcs11Exception {
        try {
            // Load the library
            System.loadLibrary(libraryName);
        } catch (Exception exception) {
            throw new Pkcs11Exception("Unable to load the PKCS11 library: " + exception.getMessage(), exception);
        }
    }

    /**
     * Resolve a method to later make a downcall. The function needs to be resolved with it matching function signature.
     *
     * @param name               Name of the function
     * @param functionDescriptor Function description
     * @return Resolved and matching function
     * @throws Pkcs11Exception Thrown if the function can't be found
     */
    protected MethodHandle downCallHandle(String name, FunctionDescriptor functionDescriptor) throws Pkcs11Exception {
        // Find the function
        Optional<MemorySegment> optionalMemorySegment = symbolLookup.find(name);
        if (optionalMemorySegment.isEmpty()) {
            throw new Pkcs11Exception("Unable to find the function " + name);
        }
        MemorySegment memorySegment = optionalMemorySegment.get();

        // Map it with the linker
        return linker.downcallHandle(memorySegment, functionDescriptor);
    }

    /**
     * Get a spliced memory segment that can be read, e.g. a string.
     *
     * @param methodHandle  Method handler
     * @param memorySegment Allocated memory segment
     * @return Spliced memory segment
     */
    protected MemorySegment invokeExact(MethodHandle methodHandle, MemorySegment memorySegment) {
        try {
            return (MemorySegment) methodHandle.invokeExact(memorySegment);
        } catch (Throwable throwable) {
            throw new RuntimeException(throwable.getMessage(), throwable);
        }
    }

    /**
     * Allocate a long without a value.
     *
     * @param arena Memory arena
     * @return Allocated memory segment
     */
    public abstract MemorySegment allocateLong(Arena arena);

    /**
     * Allocate a long and set a value.
     *
     * @param arena Memory arena
     * @param value Value to set
     * @return Allocated memory segment
     */
    public abstract MemorySegment allocateLong(Arena arena, long value);

    /**
     * Allocate a long array with the given size.
     *
     * @param arena Memory arena
     * @param size  Size of the array
     * @return Allocated memory segment
     */
    public abstract MemorySegment allocateLongArray(Arena arena, int size);

    /**
     * Read an allocated long value.
     *
     * @param memorySegment Allocated memory segment
     * @return Read value
     */
    public abstract long readLong(MemorySegment memorySegment);

    /**
     * Read an allocated long value from an array at the given array entry index.
     *
     * @param memorySegment Allocated memory segment
     * @param index         Index of the array entry
     * @return Read value
     */
    public abstract long readLongFromArray(MemorySegment memorySegment, long index);

    /**
     * Read the platform/architecture specific long value, mostly 4 or 8 bytes. A 4 byte has to be casted to a long.
     *
     * @param memorySegment Allocated memory segment
     * @param groupLayout   Group layout to identify the offset
     * @param name          Name of the element in the group layout
     * @return Long value
     */
    public abstract long readLong(MemorySegment memorySegment, GroupLayout groupLayout, String name);

    /**
     * Get a byte array from the full memory segment.
     *
     * @param memorySegment Allocated memory segment
     * @return Byte array from the full memory segment
     */
    public byte[] readBytes(MemorySegment memorySegment) {
        return memorySegment.toArray(ValueLayout.JAVA_BYTE);
    }

    /**
     * Get a fixed string value by name. We have to access the memory segment because PKCS11 uses fixed byte ranges
     * that are not null terminated but padded with whitespaces.
     *
     * @param memorySegment Allocated memory segment
     * @param groupLayout   Group layout to identify the offset
     * @param name          Name of the element in the group layout
     * @return String value with potential whitespaces
     */
    public String readFixedString(MemorySegment memorySegment, GroupLayout groupLayout, String name) {
        try {
            MethodHandle methodHandle = groupLayout.sliceHandle(MemoryLayout.PathElement.groupElement(name));
            MemorySegment namedMemorySegment = (MemorySegment) methodHandle.invokeExact(memorySegment);
            byte[] namedData = namedMemorySegment.toArray(ValueLayout.JAVA_BYTE);
            return new String(namedData);
        } catch (Throwable throwable) {
            throw new RuntimeException(throwable.getMessage(), throwable);
        }
    }

    /**
     * Build the platform/architecture specific CK_VERSION group layout.
     *
     * @return Specific CK_VERSION group layout
     */
    protected abstract GroupLayout buildCkVersionLayout();

    /**
     * Build the platform/architecture specific CK_INFO group layout.
     *
     * @return Specific CK_INFO group layout
     */
    protected abstract GroupLayout buildCkInfoLayout();

    /**
     * Build the platform/architecture specific CK_SLOT_INFO group layout.
     *
     * @return Specific CK_SLOT_INFO group layout
     */
    protected abstract GroupLayout buildCkTokenInfoLayout();

    /**
     * Build the platform/architecture specific CK_TOKEN_INFO group layout.
     *
     * @return Specific CK_TOKEN_INFO group layout
     */
    protected abstract GroupLayout buildCkSlotInfoLayout();

    /**
     * Build the platform/architecture specific CK_SESSION_INFO group layout.
     *
     * @return Specific CK_SESSION_INFO group layout
     */
    protected abstract GroupLayout buildCkSessionInfoLayout();

    /**
     * Build the platform/architecture specific CK_ATTRIBUTE group layout.
     *
     * @return Specific CK_ATTRIBUTE group layout
     */
    protected abstract GroupLayout buildCkAttributeLayout();

    /**
     * Build the platform/architecture specific CK_MECHANISM group layout.
     *
     * @return Specific CK_MECHANISM group layout
     */
    protected abstract GroupLayout buildCkMechanismLayout();
}

package ch.swaechter.pkcs11.templates;

import ch.swaechter.pkcs11.Pkcs11Exception;

import java.lang.foreign.GroupLayout;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;

/**
 * Base template that requires platform specific implementations of the long method and of the native structs.
 *
 * @author Simon Wächter
 */
public abstract class Template {

    /**
     * CK_VERSION group layout.
     */
    private final GroupLayout ckVersionLayout;

    /**
     * CK_VERSION major var handle.
     */
    private final VarHandle ckVersionMajorVarHandle;

    /**
     * CK_VERSION minor var handle.
     */
    private final VarHandle ckVersionMinorHandle;

    /**
     * CK_INFO group layout.
     */
    private final GroupLayout ckInfoLayout;

    /**
     * CK_INFO cryptoki version var handle.
     */
    private final MethodHandle ckInfoCryptokiVersionHandle;

    /**
     * CK_INFO library version var handle.
     */
    private final MethodHandle ckInfoLibraryVersionHandle;

    /**
     * Create a new template and initialize all group layouts and var handles.
     */
    public Template() {
        // Build the version template and handles
        this.ckVersionLayout = buildCkVersionLayout();
        this.ckVersionMajorVarHandle = ckVersionLayout.varHandle(MemoryLayout.PathElement.groupElement("major"));
        this.ckVersionMinorHandle = ckVersionLayout.varHandle(MemoryLayout.PathElement.groupElement("minor"));

        // Build the info template and handles
        this.ckInfoLayout = buildCkInfoLayout();
        this.ckInfoCryptokiVersionHandle = ckInfoLayout.sliceHandle(MemoryLayout.PathElement.groupElement("cryptokiVersion"));
        this.ckInfoLibraryVersionHandle = ckInfoLayout.sliceHandle(MemoryLayout.PathElement.groupElement("libraryVersion"));
    }

    /**
     * Detect the best matching template for the platform and architecture.
     *
     * @return Matching template
     * @throws Pkcs11Exception Thrown for a 32-bit JVM or wrong platform
     */
    public static Template detectTemplate() throws Pkcs11Exception {
        // Ensure we are not running in a 32-bit JVM
        String jvmArch = System.getProperty("os.arch");
        if (jvmArch.contains("x86")) {
            throw new Pkcs11Exception("This PKCS11 project can't run in a 32-bit JVM. Please use a 64-bit JVM.");
        }

        // Get the operating system name
        String operatingSystemName = System.getProperty("os.name").toLowerCase();
        if (operatingSystemName.contains("win")) {
            return new PackedWindowsTemplate();
        } else if (operatingSystemName.contains("nux")) {
            return new AlignedLinuxTemplate();
        } else {
            throw new Pkcs11Exception("Unsupported template platform!");
        }
    }

    /**
     * Get the CK_INFO group layout.
     *
     * @return Group layout
     */
    public GroupLayout getCkVersionLayout() {
        return ckVersionLayout;
    }

    /**
     * Get the CK_VERSION major var handle.
     *
     * @return Var handle
     */
    public VarHandle getCkVersionMajorVarHandle() {
        return ckVersionMajorVarHandle;
    }

    /**
     * Get the CK_VERSION minor var handle.
     *
     * @return Var handle
     */
    public VarHandle getCkVersionMinorHandle() {
        return ckVersionMinorHandle;
    }

    /**
     * Get the CK_INFO group layout.
     *
     * @return Group layout
     */
    public GroupLayout getCkInfoLayout() {
        return ckInfoLayout;
    }

    /**
     * Get the CK_INFO cryptoki version var handle.
     *
     * @return Var handle
     */
    public MethodHandle getCkInfoCryptokiVersionHandle() {
        return ckInfoCryptokiVersionHandle;
    }

    /**
     * Get the CK_INFO library version var handle.
     *
     * @return Var handle
     */
    public MethodHandle getCkInfoLibraryVersionHandle() {
        return ckInfoLibraryVersionHandle;
    }

    /**
     * Get the platform/architecture specific long value, mostly 4 or 8 bytes. A 4 byte has to be casted to a long.
     *
     * @param memorySegment Allocated memory segment
     * @param groupLayout   Group layout to identify the offset
     * @param name          Name of the element in the group layout
     * @return Long value
     */
    public abstract long getLong(MemorySegment memorySegment, GroupLayout groupLayout, String name);

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
}

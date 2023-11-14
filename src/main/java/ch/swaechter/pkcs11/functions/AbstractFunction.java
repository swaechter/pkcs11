package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.Optional;

/**
 * Abstract function that provide the base mechanism for calling functions.
 *
 * @author Simon Wächter
 */
public abstract class AbstractFunction {

    /**
     * Linker to lookup functions in the library.
     */
    private final Linker linker;

    /**
     * Symbol lookup to resolve functions from the linker.
     */
    private final SymbolLookup symbolLookup;

    /**
     * Template that provides the architecture specific memory layouts, e.g. packed or aligned structs.
     */
    private final Template template;

    /**
     * Provide all required mechanisms for calling functions.
     *
     * @param linker       Linker to lookup functions in the library
     * @param symbolLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    protected AbstractFunction(Linker linker, SymbolLookup symbolLookup, Template template) {
        this.linker = linker;
        this.symbolLookup = symbolLookup;
        this.template = template;
    }

    /**
     * Get the template.
     *
     * @return The template
     */
    protected Template getTemplate() {
        return template;
    }

    /**
     * Resolve a method to later make a downcall. The function needs to be resolved with it matching function signature.
     *
     * @param name               Name of the function
     * @param functionDescriptor Function description
     * @return Resolved and matching function
     * @throws Pkcs11Exception Thrown if the function can't be found
     */
    public MethodHandle downCallHandle(String name, FunctionDescriptor functionDescriptor) throws Pkcs11Exception {
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
     * Get the template specific long value by name.
     *
     * @param memorySegment Allocated memory segment
     * @param groupLayout   Group layout to identify the offset
     * @param name          Name of the element in the group layout
     * @return Long value
     */
    public long getLong(MemorySegment memorySegment, GroupLayout groupLayout, String name) {
        return template.getLong(memorySegment, groupLayout, name);
    }

    /**
     * Get a byte array from the full memory segment.
     *
     * @param memorySegment Allocated memory segment
     * @return Byte array from the full memory segment
     */
    public byte[] getBytes(MemorySegment memorySegment) {
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
    public String getFixedString(MemorySegment memorySegment, GroupLayout groupLayout, String name) {
        try {
            MethodHandle methodHandle = groupLayout.sliceHandle(MemoryLayout.PathElement.groupElement(name));
            MemorySegment namedMemorySegment = (MemorySegment) methodHandle.invokeExact(memorySegment);
            byte[] namedData = namedMemorySegment.toArray(ValueLayout.JAVA_BYTE);
            return new String(namedData);
        } catch (Throwable throwable) {
            throw new RuntimeException(throwable.getMessage(), throwable);
        }
    }
}

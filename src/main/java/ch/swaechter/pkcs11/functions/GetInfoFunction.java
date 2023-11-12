package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkInfo;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.headers.CkVersion;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Get the PKCS11 middleware info.
 *
 * @author Simon Wächter
 */
public class GetInfoFunction extends AbstractFunction {

    /**
     * Create a new function that gets the PKCS11 middleware info.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public GetInfoFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena Memory arena
     * @return Middleware information
     * @throws Pkcs11Exception Thrown if the function invocation fails
     */
    public CkInfo invokeFunction(Arena arena) throws Pkcs11Exception {
        try {
            // Allocate the info struct
            MemorySegment infoMemorySegment = arena.allocate(getTemplate().getCkInfoLayout());

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetInfo", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact(infoMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetInfo failed", ckResult);
            }

            // Get the cryptoki version
            MethodHandle cryptokiMethodHandle = getTemplate().getCkInfoCryptokiVersionHandle();
            MemorySegment cryptokiNamedMemorySegment = invokeExact(cryptokiMethodHandle, infoMemorySegment);
            byte cryptokiMajor = (byte) getTemplate().getCkVersionMajorVarHandle().get(cryptokiNamedMemorySegment);
            byte cryptokiMinor = (byte) getTemplate().getCkVersionMinorHandle().get(cryptokiNamedMemorySegment);
            CkVersion cryptokiVersion = new CkVersion(cryptokiMajor, cryptokiMinor);

            // Get the manufacturer ID
            String manufacturerId = getFixedString(infoMemorySegment, getTemplate().getCkInfoLayout(), "manufacturerId");

            // Vet the library version
            MethodHandle libraryMethodHandle = getTemplate().getCkInfoLibraryVersionHandle();
            MemorySegment libraryNamedMemorySegment = invokeExact(libraryMethodHandle, infoMemorySegment);
            byte libraryMajor = (byte) getTemplate().getCkVersionMajorVarHandle().get(libraryNamedMemorySegment);
            byte libraryMinor = (byte) getTemplate().getCkVersionMinorHandle().get(libraryNamedMemorySegment);
            CkVersion libraryVersion = new CkVersion(libraryMajor, libraryMinor);

            // Get the flags
            Long flags = getLong(infoMemorySegment, getTemplate().getCkInfoLayout(), "flags");

            // Get the library description
            String libraryDescription = getFixedString(infoMemorySegment, getTemplate().getCkInfoLayout(), "libraryDescription");

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
}

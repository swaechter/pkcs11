package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Obtains the size of an object in bytes from the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class GetObjectSizeFunction extends AbstractFunction {

    /**
     * Create a new function that obtains the size of an object in bytes.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public GetObjectSizeFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena          Memory arena
     * @param sessionId      ID of the session
     * @param objectHandleId ID of the object handle
     * @return Size of the object
     * @throws Pkcs11Exception Thrown if the session/object does not exist or can't be read
     */
    public long invokeFunction(Arena arena, long sessionId, long objectHandleId) throws Pkcs11Exception {
        try {
            // Allocate a pointer for the object size
            MemorySegment objectSizeMemorySegment = getTemplate().allocateLong(arena);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetObjectSize", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, (int) objectHandleId, objectSizeMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetObjectSize failed", ckResult);
            }

            // Return the object size
            return getTemplate().getLong(objectSizeMemorySegment);
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetObjectSize failed: " + throwable.getMessage(), throwable);
        }
    }
}

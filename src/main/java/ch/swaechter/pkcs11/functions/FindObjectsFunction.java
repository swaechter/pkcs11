package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.ArrayList;
import java.util.List;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Continues an object search operation in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class FindObjectsFunction extends AbstractFunction {

    /**
     * Create a new function that continues an object search operation.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public FindObjectsFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena      Memory arena
     * @param sessionId  ID of the session
     * @param maxObjects Maximum number of object handles returned
     * @return Found object handles
     * @throws Pkcs11Exception Thrown if the session does not exist or the search operation can't succeed
     */
    public List<Long> invokeFunction(Arena arena, long sessionId, int maxObjects) throws Pkcs11Exception {
        try {
            // Allocate the object count
            MemorySegment objectCountMemorySegment = getTemplate().allocateLong(arena);

            // Allocate the object handle array
            MemorySegment objectHandlesMemorySegment = getTemplate().allocateLongArray(arena, maxObjects);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_FindObjects", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, objectHandlesMemorySegment, maxObjects, objectCountMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_FindObjects failed", ckResult);
            }

            // Get all object handles
            int foundObjectHandles = (int) getTemplate().getLong(objectCountMemorySegment);
            List<Long> objectIds = new ArrayList<>(foundObjectHandles);
            for (int i = 0; i < foundObjectHandles; i++) {
                // Get the object handle
                long foundObjectHandle = getTemplate().getLongFromArray(objectHandlesMemorySegment, i);
                objectIds.add(foundObjectHandle);
            }

            // Return the object IDs
            return objectIds;
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_FindObjects failed: " + throwable.getMessage(), throwable);
        }
    }
}

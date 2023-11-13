package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Open a new session in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class OpenSessionFunction extends AbstractFunction {

    /**
     * Create a new function that opens a session in the PKCS11 middleware.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public OpenSessionFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        // Call the parent constructor
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena  Memory arena
     * @param slotId ID of the slot
     * @param flags  Session flags
     * @return ID of the session
     * @throws Pkcs11Exception Thrown if the slot does not exist or the session can't be opened
     */
    public long invokeFunction(Arena arena, long slotId, long flags) throws Pkcs11Exception {
        try {
            // Allocate all values
            MemorySegment pApplicationMemorySegment = MemorySegment.NULL;
            MemorySegment notifyMemorySegment = MemorySegment.NULL;
            MemorySegment sessionIdMemorySegment = arena.allocate(ValueLayout.JAVA_LONG);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_OpenSession", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) slotId, (int) flags, pApplicationMemorySegment, notifyMemorySegment, sessionIdMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_OpenSession failed", ckResult);
            }

            // Get and return the session ID
            return sessionIdMemorySegment.get(ValueLayout.JAVA_LONG, 0);
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_OpenSession failed: " + throwable.getMessage(), throwable);
        }
    }
}

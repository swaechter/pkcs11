package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Continues a multiple-part digesting operation in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class DigestUpdateFunction extends AbstractFunction {

    /**
     * Create a new function that continues a multiple-part digesting operation.
     *
     * @param linker       Linker to lookup functions in the library
     * @param symbolLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public DigestUpdateFunction(Linker linker, SymbolLookup symbolLookup, Template template) {
        super(linker, symbolLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena     Memory arena
     * @param sessionId ID of the session
     * @param data      Data to digest
     * @throws Pkcs11Exception Thrown if the session does not exist or the digest update operation can't succeed
     */
    public void invokeFunction(Arena arena, long sessionId, byte[] data) throws Pkcs11Exception {
        try {
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
}

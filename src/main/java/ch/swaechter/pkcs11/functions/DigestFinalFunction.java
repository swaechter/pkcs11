package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Finishes a multiple-part digesting operation in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class DigestFinalFunction extends AbstractFunction {

    /**
     * Create a new function that finishes a multiple-part digesting operation.
     *
     * @param linker       Linker to lookup functions in the library
     * @param symbolLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public DigestFinalFunction(Linker linker, SymbolLookup symbolLookup, Template template) {
        super(linker, symbolLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena     Memory arena
     * @param sessionId ID of the session
     * @return Digested data
     * @throws Pkcs11Exception Thrown if the session does not exist or the digest final operation can't succeed
     */
    public byte[] invokeFunction(Arena arena, long sessionId) throws Pkcs11Exception {
        try {
            // Define the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_DigestFinal", functionDescriptor);

            // Allocate a value to hold the digest length
            MemorySegment digestMemorySegment = MemorySegment.NULL;
            MemorySegment digestLengthMemorySegment = getTemplate().allocateLong(arena);

            // Invoke the function to get the digest length
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, digestMemorySegment, digestLengthMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_DigestFinal failed", ckResult);
            }

            // Allocate the digest buffer
            int digestLength = (int) getTemplate().getLong(digestLengthMemorySegment);
            digestMemorySegment = arena.allocateArray(JAVA_BYTE, digestLength);

            // Invoke the function to digest the data
            ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, digestMemorySegment, digestLengthMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_DigestFinal failed", ckResult);
            }

            // Return the digest
            return getBytes(digestMemorySegment);
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_DigestFinal failed: " + throwable.getMessage(), throwable);
        }
    }
}

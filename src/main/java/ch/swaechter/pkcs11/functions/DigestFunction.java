package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Digests single-part data in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class DigestFunction extends AbstractFunction {

    /**
     * Create a new function that digests single-part data.
     *
     * @param linker       Linker to lookup functions in the library
     * @param symbolLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public DigestFunction(Linker linker, SymbolLookup symbolLookup, Template template) {
        super(linker, symbolLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena     Memory arena
     * @param sessionId ID of the session
     * @param data      Data to digest
     * @return Digested data
     * @throws Pkcs11Exception Thrown if the session does not exist or the digest operation can't succeed
     */
    public byte[] invokeFunction(Arena arena, long sessionId, byte[] data) throws Pkcs11Exception {
        try {
            // Define the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_Digest", functionDescriptor);

            // Allocate an array for the data
            MemorySegment messageMemorySegment = arena.allocateArray(JAVA_BYTE, data);

            // Allocate a value to hold the digest length
            MemorySegment digestMemorySegment = MemorySegment.NULL;
            MemorySegment digestLengthMemorySegment = getTemplate().allocateLong(arena);

            // Invoke the function to get the digest length
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, messageMemorySegment, (int) messageMemorySegment.byteSize(), digestMemorySegment, digestLengthMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_Digest failed", ckResult);
            }

            // Allocate the digest buffer
            int digestLength = (int) getTemplate().getLong(digestLengthMemorySegment);
            digestMemorySegment = arena.allocateArray(JAVA_BYTE, digestLength);

            // Invoke the function to digest the data
            ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, messageMemorySegment, (int) messageMemorySegment.byteSize(), digestMemorySegment, digestLengthMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_Digest failed", ckResult);
            }

            // Return the digest
            return getBytes(digestMemorySegment);
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_Digest failed: " + throwable.getMessage(), throwable);
        }
    }
}

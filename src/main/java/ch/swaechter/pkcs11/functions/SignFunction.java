package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.Arrays;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Sign single-part data in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class SignFunction extends AbstractFunction {

    /**
     * Create a new function that signs single-part data.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public SignFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena         Memory arena
     * @param sessionId     ID of the session
     * @param message       Message to sign
     * @param signatureSize Size of the signature buffer
     * @return Signed message
     * @throws Pkcs11Exception Thrown if the session does not exist or the sign operation can't succeed
     */
    public byte[] invokeFunction(Arena arena, long sessionId, byte[] message, int signatureSize) throws Pkcs11Exception {
        try {
            // Allocate an array for the message
            MemorySegment messageMemorySegment = arena.allocateArray(JAVA_BYTE, message);

            // Allocate an array for the signed data and a pointer for the signature length
            MemorySegment signedDataMemorySegment = arena.allocateArray(JAVA_BYTE, signatureSize);
            MemorySegment signedDataLengthMemorySegment = getTemplate().allocateLong(arena, signedDataMemorySegment.byteSize());

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_Sign", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, messageMemorySegment, (int) messageMemorySegment.byteSize(), signedDataMemorySegment, signedDataLengthMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_Sign failed", ckResult);
            }

            // Return the signed message
            int signedMessageLength = (int) getTemplate().getLong(signedDataLengthMemorySegment);
            byte[] signedMessage = getBytes(signedDataMemorySegment);
            return Arrays.copyOf(signedMessage, signedMessageLength);
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_Sign failed: " + throwable.getMessage(), throwable);
        }
    }
}

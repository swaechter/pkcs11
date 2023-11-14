package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Generates random data from the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class GenerateRandomFunction extends AbstractFunction {

    /**
     * Create a new function that generates random data.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public GenerateRandomFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena     Memory arena
     * @param sessionId ID of the session
     * @param length    Length of the random data
     * @return Random date with the length
     * @throws Pkcs11Exception Thrown if the random data can't be generated
     */
    public byte[] invokeFunction(Arena arena, long sessionId, int length) throws Pkcs11Exception {
        try {
            // Allocate the random buffer
            MemorySegment randomBufferMemorySegment = arena.allocateArray(ValueLayout.JAVA_BYTE, length);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_GenerateRandom", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, randomBufferMemorySegment, (int) randomBufferMemorySegment.byteSize()));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GenerateRandom failed", ckResult);
            }

            // Convert and return the buffer
            return getBytes(randomBufferMemorySegment);
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GenerateRandom failed: " + throwable.getMessage(), throwable);
        }
    }
}

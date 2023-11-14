package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Mix in additional seed material to the random number generator in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class SeedRandomFunction extends AbstractFunction {

    /**
     * Create a new function that mixes in additional seed material to the random number generator.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public SeedRandomFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena     Memory arena
     * @param sessionId ID of the session
     * @param seed      Additional seed material
     * @throws Pkcs11Exception Thrown if the random number generator can't be seeded
     */
    public void invokeFunction(Arena arena, long sessionId, byte[] seed) throws Pkcs11Exception {
        try {
            // Allocate the seed buffer
            MemorySegment seedBufferMemorySegment = arena.allocateArray(ValueLayout.JAVA_BYTE, seed);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_SeedRandom", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, seedBufferMemorySegment, (int) seedBufferMemorySegment.byteSize()));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_SeedRandom failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_SeedRandom failed: " + throwable.getMessage(), throwable);
        }
    }
}

package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkMechanism;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Initializes a message-digesting operation in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class DigestInitFunction extends AbstractFunction {

    /**
     * Create a new function that initializes a message-digesting operation.
     *
     * @param linker       Linker to lookup functions in the library
     * @param symbolLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public DigestInitFunction(Linker linker, SymbolLookup symbolLookup, Template template) {
        super(linker, symbolLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena     Memory arena
     * @param sessionId ID of the session
     * @param mechanism ID of the mechanism
     * @throws Pkcs11Exception Thrown if the session does not exist or the digest init operation can't succeed
     */
    public void invokeFunction(Arena arena, long sessionId, CkMechanism mechanism) throws Pkcs11Exception {
        try {
            // Allocate the mechanism
            MemorySegment mechanismMemorySegment = arena.allocate(getTemplate().getCkMechanismLayout());
            getTemplate().getCkMechanismMechanismHandle().set(mechanismMemorySegment, mechanism.value);
            getTemplate().getCkMechanismPParameterHandle().set(mechanismMemorySegment, MemorySegment.NULL);
            getTemplate().getCkMechanismParameterLenHandle().set(mechanismMemorySegment, 0);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_DigestInit", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, mechanismMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_DigestInit failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_DigestInit failed: " + throwable.getMessage(), throwable);
        }
    }
}

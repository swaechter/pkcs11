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
 * Initializes a signature operation in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class SignInitFunction extends AbstractFunction {

    /**
     * Create a new function that initializes a signature operation.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public SignInitFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena       Memory arena
     * @param sessionId   ID of the session
     * @param ckMechanism ID of the mechanism
     * @param keyHandleId ID of the key handle
     * @throws Pkcs11Exception Thrown if the session does not exist or the sign init operation can't succeed
     */
    public void invokeFunction(Arena arena, long sessionId, CkMechanism ckMechanism, long keyHandleId) throws Pkcs11Exception {
        try {
            // Allocate the mechanism
            MemorySegment mechanismMemorySegment = arena.allocate(getTemplate().getCkMechanismLayout());
            getTemplate().getCkMechanismMechanismHandle().set(mechanismMemorySegment, ckMechanism.value);
            getTemplate().getCkMechanismPParameterHandle().set(mechanismMemorySegment, MemorySegment.NULL);
            getTemplate().getCkMechanismParameterLenHandle().set(mechanismMemorySegment, 0);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_SignInit", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, mechanismMemorySegment, (int) keyHandleId));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_SignInit failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_SignInit failed: " + throwable.getMessage(), throwable);
        }
    }
}

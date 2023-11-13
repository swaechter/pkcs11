package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.headers.CkUserType;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Log a user into the token.
 *
 * @author Simon Wächter
 */
public class LoginFunction extends AbstractFunction {

    /**
     * Create a new function that logs a user into the token.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public LoginFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function
     *
     * @param arena      Memory arena
     * @param sessionId  ID of the session
     * @param ckUserType Type of the user
     * @param pinOrPuk   PIN/PUK or null in case the token has a protected authentication path
     * @throws Pkcs11Exception Thrown if the session does not exist or an error during login
     */
    public void invokeFunction(Arena arena, long sessionId, CkUserType ckUserType, String pinOrPuk) throws Pkcs11Exception {
        try {
            // Convert the user type
            long userType = ckUserType.value;

            // Convert the PIN/PUK or use null for a token with a protected authentication path
            MemorySegment pinOrPukMemorySegment = pinOrPuk != null ? arena.allocateArray(ValueLayout.JAVA_BYTE, pinOrPuk.getBytes(StandardCharsets.US_ASCII)) : MemorySegment.NULL;

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_Login", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, (int) userType, pinOrPukMemorySegment, (int) pinOrPukMemorySegment.byteSize()));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_Login failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_Login failed: " + throwable.getMessage(), throwable);
        }
    }
}

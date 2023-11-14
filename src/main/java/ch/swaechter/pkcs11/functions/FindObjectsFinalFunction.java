package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Finishes an object search operation in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class FindObjectsFinalFunction extends AbstractFunction {

    /**
     * Function that finishes an object search operation in the PKCS11 middleware
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public FindObjectsFinalFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param sessionId ID of the session
     * @throws Pkcs11Exception Thrown if the session does not exist or the search operation can't be finalized
     */
    public void invokeFunction(long sessionId) throws Pkcs11Exception {
        try {
            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_FindObjectsFinal", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_FindObjectsFinal failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_FindObjectsFinal failed: " + throwable.getMessage(), throwable);
        }
    }
}

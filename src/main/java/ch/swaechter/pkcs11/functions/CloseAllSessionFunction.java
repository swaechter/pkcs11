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
 * Close all existing sessions for the slot in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class CloseAllSessionFunction extends AbstractFunction {

    /**
     * Create a new function that closes all existing sessions for the slot in the PKCS11 middleware.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public CloseAllSessionFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param slotId ID of the slot
     * @throws Pkcs11Exception Thrown if the slot does not exist or the sessions can't be closed
     */
    public void invokeFunction(long slotId) throws Pkcs11Exception {
        try {
            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_CloseAllSessions", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) slotId));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_CloseAllSessions failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_CloseAllSessions failed: " + throwable.getMessage(), throwable);
        }
    }
}

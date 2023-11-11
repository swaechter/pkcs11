package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Finalize the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class FinalizeFunction extends AbstractFunction {

    /**
     * Create a new function that finalizes the PKCS11 middleware.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public FinalizeFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @throws Pkcs11Exception Thrown if the function invocation fails
     */
    public void invokeFunction() throws Pkcs11Exception {
        try {
            // Allocate the pReserved value
            MemorySegment pReservedMemorySegment = MemorySegment.NULL;

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_Finalize", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact(pReservedMemorySegment));

            // Check the result
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_Finalize failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_Finalize failed: " + throwable.getMessage(), throwable);
        }
    }
}

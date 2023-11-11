package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.ArrayList;
import java.util.List;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Get all slots from the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class GetSlotListFunction extends AbstractFunction {

    /**
     * Create a new function that lists the slots.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public GetSlotListFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @throws Pkcs11Exception Thrown if the function invocation fails
     */
    public List<Long> invokeFunction(Arena arena, boolean tokenPresent, int maxSlots) throws Pkcs11Exception {
        try {
            // Define the flag to search for all slots present/not present
            byte presentFlag = tokenPresent ? (byte) 0x1 : (byte) 0x0;

            // Allocate an array with maxSlots items/potential tokens
            int[] slotIdBuffer = new int[maxSlots];
            MemorySegment slotIdsMemorySegment = arena.allocateArray(ValueLayout.JAVA_INT, slotIdBuffer);

            // Allocate the number of max tokens to search (maxSlots)
            MemorySegment slotIdCountMemorySegment = arena.allocate(ValueLayout.JAVA_LONG, maxSlots);

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_BYTE, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetSlotList", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact(presentFlag, slotIdsMemorySegment, slotIdCountMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetSlotList failed", ckResult);
            }

            // Get the slot count
            int slotCount = (int) slotIdCountMemorySegment.get(ValueLayout.JAVA_LONG, 0);

            // Get the slot IDs
            List<Long> slotIds = new ArrayList<>(slotCount);
            for (int i = 0; i < slotCount; i++) {
                // Get slot ID at the given offset
                long slotId = slotIdBuffer[i];
                slotIds.add(slotId);
            }

            // Return the slots
            return slotIds;
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetSlotList failed: " + throwable.getMessage(), throwable);
        }
    }
}

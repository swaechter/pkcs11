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
     * @param arena        Memory arena
     * @param tokenPresent Flag whether to only list slots with a token present
     * @return All slot IDs
     * @throws Pkcs11Exception Thrown if the function invocation fails
     */
    public List<Long> invokeFunction(Arena arena, boolean tokenPresent) throws Pkcs11Exception {
        try {
            // Define the flag to search for all slots present/not present
            byte presentFlag = tokenPresent ? (byte) 0x1 : (byte) 0x0;

            // Define the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_BYTE, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetSlotList", functionDescriptor);

            // Allocate an array with maxSlots items/potential tokens
            MemorySegment slotIdCountMemorySegment = getTemplate().allocateLong(arena);
            MemorySegment slotIdsMemorySegment = MemorySegment.NULL;

            // Invoke the function to get the number of slots
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact(presentFlag, slotIdsMemorySegment, slotIdCountMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetSlotList failed", ckResult);
            }

            // Allocate a buffer for the given slots
            int slotCount = (int) getTemplate().getLong(slotIdCountMemorySegment);
            slotIdsMemorySegment = getTemplate().allocateLong(arena, slotCount);

            // Invoke the function to get the slot list
            ckResult = CkResult.valueOf((int) methodHandle.invokeExact(presentFlag, slotIdsMemorySegment, slotIdCountMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetSlotList failed", ckResult);
            }

            // Convert the slot IDs
            List<Long> slotIds = new ArrayList<>(slotCount);
            for (int i = 0; i < slotCount; i++) {
                // Get slot ID at the given offset
                long slotId = getTemplate().getLongFromArray(slotIdsMemorySegment, i);
                slotIds.add(slotId);
            }

            // Return the slots
            return slotIds;
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetSlotList failed: " + throwable.getMessage(), throwable);
        }
    }
}

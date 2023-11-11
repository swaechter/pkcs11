package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.headers.CkSlotInfo;
import ch.swaechter.pkcs11.headers.CkVersion;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Get information for a slot from the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class GetSlotInfoFunction extends AbstractFunction {

    /**
     * Create a new function that gets the slot information from the PKCS11 middleware.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public GetSlotInfoFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena  Memory arena
     * @param slotId ID of the slot
     * @return Slot information
     * @throws Pkcs11Exception Thrown if the slot does not exist or can't be read
     */
    public CkSlotInfo invokeFunction(Arena arena, long slotId) throws Pkcs11Exception {
        try {
            // Allocate the slot info struct
            MemorySegment slotInfoMemorySegment = arena.allocate(getTemplate().getCkSlotInfoLayout());

            // TODO: Fix int cast
            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetSlotInfo", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) slotId, slotInfoMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetSlotInfo failed", ckResult);
            }

            // Get the slot description
            String slotDescription = getFixedString(slotInfoMemorySegment, getTemplate().getCkSlotInfoLayout(), "slotDescription");

            // Get the manufacturer ID
            String manufacturerId = getFixedString(slotInfoMemorySegment, getTemplate().getCkSlotInfoLayout(), "manufacturerId");

            // Get the flags
            Long flags = getLong(slotInfoMemorySegment, getTemplate().getCkSlotInfoLayout(), "flags");

            // Get the hardware version
            MethodHandle hardwareMethodHandle = getTemplate().getCkSlotInfoHardwareVersionHandle();
            MemorySegment hardwareNamedMemorySegment = invokeExact(hardwareMethodHandle, slotInfoMemorySegment);
            byte hardwareMajor = (byte) getTemplate().getCkVersionMajorVarHandle().get(hardwareNamedMemorySegment);
            byte hardwareMinor = (byte) getTemplate().getCkVersionMinorHandle().get(hardwareNamedMemorySegment);
            CkVersion hardwareVersion = new CkVersion(hardwareMajor, hardwareMinor);

            // Get the firmware version
            MethodHandle firmwareMethodHandle = getTemplate().getCkSlotInfoFirmwareVersionHandle();
            MemorySegment firmwareNamedMemorySegment = invokeExact(firmwareMethodHandle, slotInfoMemorySegment);
            byte firmwareMajor = (byte) getTemplate().getCkVersionMajorVarHandle().get(firmwareNamedMemorySegment);
            byte firmwareMinor = (byte) getTemplate().getCkVersionMinorHandle().get(firmwareNamedMemorySegment);
            CkVersion firmwareVersion = new CkVersion(firmwareMajor, firmwareMinor);

            // Return the slot info
            return new CkSlotInfo(
                slotDescription,
                manufacturerId,
                flags,
                hardwareVersion,
                firmwareVersion
            );
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetSlotList failed: " + throwable.getMessage(), throwable);
        }
    }
}

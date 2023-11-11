package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.headers.CkTokenInfo;
import ch.swaechter.pkcs11.headers.CkVersion;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Get information for a token from the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class GetTokenInfoFunction extends AbstractFunction {

    /**
     * Create a new function that gets the token information from the PKCS11 middleware.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public GetTokenInfoFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena  Memory arena
     * @param slotId ID of the slot
     * @return Token information
     * @throws Pkcs11Exception Thrown if the slot does not exist or can't be read
     */
    public CkTokenInfo invokeFunction(Arena arena, long slotId) throws Pkcs11Exception {
        try {
            // Allocate the token info struct
            MemorySegment tokenInfoMemorySegment = arena.allocate(getTemplate().getCkTokenInfoLayout());

            // TODO: Fix int cast
            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetTokenInfo", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) slotId, tokenInfoMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetTokenInfo failed", ckResult);
            }

            // Get the label
            String label = getFixedString(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "label");

            // Get the manufacturer ID
            String manufacturerId = getFixedString(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "manufacturerID");

            // Get the model
            String model = getFixedString(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "model");

            // Get the serial number
            String serialNumber = getFixedString(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "serialNumber");

            // Get all values
            Long flags = getLong(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "flags");
            Long maxSessionCount = getLong(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "maxSessionCount");
            Long sessionCount = getLong(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "sessionCount");
            Long maxRwSessionCount = getLong(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "maxRwSessionCount");
            Long rwSessionCount = getLong(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "rwSessionCount");
            Long maxPinLen = getLong(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "maxPinLen");
            Long minPinLen = getLong(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "minPinLen");
            Long totalPublicMemory = getLong(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "totalPublicMemory");
            Long freePublicMemory = getLong(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "freePublicMemory");
            Long totalPrivateMemory = getLong(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "totalPrivateMemory");
            Long freePrivateMemory = getLong(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "freePrivateMemory");

            // Get the hardware version
            MethodHandle hardwareMethodHandle = getTemplate().getCkTokenInfoHardwareVersionHandle();
            MemorySegment hardwareNamedMemorySegment = invokeExact(hardwareMethodHandle, tokenInfoMemorySegment);
            byte hardwareMajor = (byte) getTemplate().getCkVersionMajorVarHandle().get(hardwareNamedMemorySegment);
            byte hardwareMinor = (byte) getTemplate().getCkVersionMinorHandle().get(hardwareNamedMemorySegment);
            CkVersion hardwareVersion = new CkVersion(hardwareMajor, hardwareMinor);

            // Get the firmware version
            MethodHandle firmwareMethodHandle = getTemplate().getCkTokenInfoFirmwareVersionHandle();
            MemorySegment firmwareNamedMemorySegment = invokeExact(firmwareMethodHandle, tokenInfoMemorySegment);
            byte firmwareMajor = (byte) getTemplate().getCkVersionMajorVarHandle().get(firmwareNamedMemorySegment);
            byte firmwareMinor = (byte) getTemplate().getCkVersionMinorHandle().get(firmwareNamedMemorySegment);
            CkVersion firmwareVersion = new CkVersion(firmwareMajor, firmwareMinor);

            // Get the time
            String utcTime = getFixedString(tokenInfoMemorySegment, getTemplate().getCkTokenInfoLayout(), "utcTime");

            // Return the token info
            return new CkTokenInfo(
                label,
                manufacturerId,
                model,
                serialNumber,
                flags,
                maxSessionCount,
                sessionCount,
                maxRwSessionCount,
                rwSessionCount,
                maxPinLen,
                minPinLen,
                totalPublicMemory,
                freePublicMemory,
                totalPrivateMemory,
                freePrivateMemory,
                hardwareVersion,
                firmwareVersion,
                utcTime
            );
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetTokenInfo failed: " + throwable.getMessage(), throwable);
        }
    }
}

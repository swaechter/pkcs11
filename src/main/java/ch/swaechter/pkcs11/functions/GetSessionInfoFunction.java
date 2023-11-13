package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.headers.CkSessionInfo;
import ch.swaechter.pkcs11.headers.CkSessionState;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Get information for a session from the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class GetSessionInfoFunction extends AbstractFunction {

    /**
     * Create a new function that gets the session information from the PKCS11 middleware.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public GetSessionInfoFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena     Memory arena
     * @param sessionId ID of the session
     * @return Session information
     * @throws Pkcs11Exception Thrown if the session does not exist or the session info can't be read
     */
    public CkSessionInfo invokeFunction(Arena arena, long sessionId) throws Pkcs11Exception {
        try {
            // Allocate the layout
            MemorySegment sessionInfoMemorySegment = arena.allocate(getTemplate().getCkSessionInfoLayout());

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)));
            MethodHandle methodHandle = downCallHandle("C_GetSessionInfo", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, sessionInfoMemorySegment));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_GetSessionInfo failed", ckResult);
            }

            // Get the slot ID
            Long slotId = getLong(sessionInfoMemorySegment, getTemplate().getCkSessionInfoLayout(), "slotId");

            // Get the state
            Long state = getLong(sessionInfoMemorySegment, getTemplate().getCkSessionInfoLayout(), "state");
            CkSessionState sessionStateEnum = CkSessionState.valueOf(state);

            // Get the flags
            Long flags = getLong(sessionInfoMemorySegment, getTemplate().getCkSessionInfoLayout(), "flags");

            // Get the device error
            Long deviceError = getLong(sessionInfoMemorySegment, getTemplate().getCkSessionInfoLayout(), "deviceError");

            // Return the session info
            return new CkSessionInfo(
                slotId,
                sessionStateEnum,
                flags,
                deviceError
            );
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_GetSessionInfo failed: " + throwable.getMessage(), throwable);
        }
    }
}

package ch.swaechter.pkcs11;

import ch.swaechter.pkcs11.headers.CkInfo;
import ch.swaechter.pkcs11.objects.Pkcs11Info;
import ch.swaechter.pkcs11.objects.Pkcs11Slot;
import ch.swaechter.pkcs11.templates.Template;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * The PKCS11 module allows an object-oriented interaction with the PKCS11 library/middleware.
 *
 * @author Simon Wächter
 */
public class Pkcs11Module extends Pkcs11Container implements Closeable {

    /**
     * Flag whether the PKCS11 module is initialized.
     */
    private Boolean initialized;

    /**
     * Create a new PKCS11 module and load the givenPKCS11 middleware via library.
     *
     * @param libraryName Name of the PKCS11 middleware that has to be on the library path
     * @param template    Template that provides the architecture specific memory layouts
     * @throws Pkcs11Exception Thrown if the PKCS11 middleware can't be loaded
     */
    public Pkcs11Module(String libraryName, Template template) throws Pkcs11Exception {
        // Create the PKCS11 library
        super(new Pkcs11Library(libraryName, template));
        this.initialized = false;
    }

    /**
     * Flag whether the PKCS11 module is initialized.
     *
     * @return Status of the initialization
     */
    public Boolean isInitialized() {
        return initialized;
    }

    /**
     * Initialize the PKCS11 module. Another invocation won't re-initialize the module another time.
     *
     * @throws Pkcs11Exception Thrown if the PKCS11 module can't be initialized.
     */
    public void initializeModule() throws Pkcs11Exception {
        // Ignore if module is initialized
        if (initialized) {
            return;
        }

        // Initialize the module
        getPkcs11Library().C_Initialize();

        // Mark as initialized
        initialized = true;
    }

    /**
     * Finalize the PKCS11 module. Another invocation won't re-finalize the module another time.
     *
     * @throws Pkcs11Exception Thrown if the PKCS11 module can't be finalized.
     */
    public void finalizeModule() throws Pkcs11Exception {
        // Ignore if module is finalized
        if (!initialized) {
            return;
        }

        // Finalize the module
        getPkcs11Library().C_Finalize();

        // Mark as finalized
        initialized = false;
    }

    /**
     * Ensure the PKCS11 is initialized or will be initialized. The flag can be set to enforce the module is
     * initialized or an exception will be thrown.
     *
     * @param throwExceptionIfNot Flag whether an exception should be thrown if the module is not initialized
     * @throws Pkcs11Exception Thrown if the module should be initialized or can't be initialized
     */
    public void ensureIsInitialized(Boolean throwExceptionIfNot) throws Pkcs11Exception {
        // Throw an exception if the module is not initialized
        if (!initialized && throwExceptionIfNot) {
            throw new Pkcs11Exception("The PKCS11 module is not initialized, but the high level client requires it. Did you forget to call Pkcs11HighLevel.initializeModule() or called Pkcs11HighLevel.finalizeModule() before?");
        }

        // Initialize the module
        initializeModule();
    }

    /**
     * Get the module info.
     *
     * @throws Pkcs11Exception Thrown if the module info can't be read
     */
    public Pkcs11Info getInfo() throws Pkcs11Exception {
        // Ensure is initialized
        ensureIsInitialized(false);

        // Get the info
        CkInfo ckInfo = getPkcs11Library().C_GetInfo();

        // Return the info
        return new Pkcs11Info(ckInfo);
    }

    /**
     * Get all slots.
     *
     * @param tokenPresent Flag whether the tokens have to be present
     * @return List with the slots
     * @throws Pkcs11Exception Thrown if the slot list can't be read
     */
    public List<Pkcs11Slot> getSlots(boolean tokenPresent) throws Pkcs11Exception {
        // Ensure is initialized
        ensureIsInitialized(false);

        // Get the slots
        List<Long> slotIds = getPkcs11Library().C_GetSlotList(tokenPresent);

        // Return the slots
        List<Pkcs11Slot> pkcs11Slots = new ArrayList<>(slotIds.size());
        for (Long slotId : slotIds) {
            Pkcs11Slot pkcs11Slot = new Pkcs11Slot(getPkcs11Library(), slotId);
            pkcs11Slots.add(pkcs11Slot);
        }
        return pkcs11Slots;
    }

    /**
     * Get a specific slot.
     *
     * @param slotId ID of the slot
     * @return Slot
     * @throws Pkcs11Exception Thrown if the slot does not exist or can't be read
     */
    public Pkcs11Slot getSlot(long slotId) throws Pkcs11Exception {
        // Ensure is initialized
        ensureIsInitialized(false);

        // Get the slot info for the slot to ensure it exists
        getPkcs11Library().C_GetSlotInfo(slotId);

        // Return the slot
        return new Pkcs11Slot(getPkcs11Library(), slotId);
    }

    /**
     * The module supports the try-with-resource statement. A caller can create the module via try, initialize it and
     * close will automatically finalize, even when an exception is thrown after the initialization.
     */
    @Override
    public void close() throws IOException {
        try {
            // Finalize if initialized
            finalizeModule();
        } catch (Pkcs11Exception exception) {
            throw new IOException(exception.getMessage(), exception);
        }
    }
}

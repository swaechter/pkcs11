package ch.swaechter.pkcs11;

import ch.swaechter.pkcs11.headers.CkInfo;
import ch.swaechter.pkcs11.templates.Template;

import java.io.Closeable;

/**
 * The PKCS11 module allows an object-oriented interaction with the PKCS11 library/middleware.
 *
 * @author Simon Wächter
 */
public class Pkcs11Module implements Closeable {

    /**
     * PKCS11 library to access the middleware.
     */
    private final Pkcs11Library pkcs11Library;

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
        this.pkcs11Library = new Pkcs11Library(libraryName, template);
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
        pkcs11Library.C_Initialize();

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
        pkcs11Library.C_Finalize();

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
    public CkInfo getInfo() throws Pkcs11Exception {
        // Ensure is initialized
        ensureIsInitialized(false);

        // Get the info
        return pkcs11Library.C_GetInfo();
    }

    /**
     * The module supports the try-with-resource statement. A caller can create the module via try, initialize it and
     * close will automatically finalize, even when an exception is thrown after the initialization.
     */
    @Override
    public void close() {
        try {
            // Finalize if initialized
            finalizeModule();
        } catch (Pkcs11Exception exception) {
            throw new RuntimeException(exception.getMessage(), exception);
        }
    }
}

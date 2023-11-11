package ch.swaechter.pkcs11;

import ch.swaechter.pkcs11.function.FinalizeFunction;
import ch.swaechter.pkcs11.function.GetInfoFunction;
import ch.swaechter.pkcs11.function.InitializeFunction;
import ch.swaechter.pkcs11.headers.CkInfo;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.Arena;
import java.lang.foreign.Linker;
import java.lang.foreign.SymbolLookup;

/**
 * The PKCS11 library allows direct interactions with the PKCS11 middleware. The library is as simple as possible and
 * doesn't provide a convenient object-oriented view like the PKCS11 module, e.g. many operations are handle based.
 *
 * @author Simon Wächter
 */
public class Pkcs11Library {

    /**
     * Linker to lookup functions in the library.
     */
    private final Linker linker;

    /**
     * Symbol lookup to resolve functions from the linker.
     */
    private final SymbolLookup loaderLookup;

    /**
     * Template that provides the architecture specific memory layouts, e.g. packed or aligned structs.
     */
    private final Template template;

    /**
     * Create a new PKCS11 library and load the given PKCS11 middleware.
     *
     * @param libraryName Name of the PKCS11 middleware that has to be on the library path
     * @param template    Template that provides the architecture specific memory layouts
     * @throws Pkcs11Exception Thrown if the PKCS11 middleware can't be loaded
     */
    public Pkcs11Library(String libraryName, Template template) throws Pkcs11Exception {
        // Load the PKCS11 library
        loadPkcs11Library(libraryName);

        // Create the linker and lookup
        this.linker = Linker.nativeLinker();
        this.loaderLookup = SymbolLookup.loaderLookup();

        // Set the template
        this.template = template;
    }

    /**
     * Load the given PKCS11 middleware.
     *
     * @param libraryName Name of the PKCS11 middleware
     * @throws Pkcs11Exception Thrown if the PKCS11 middleware can't be loaded
     */
    private void loadPkcs11Library(String libraryName) throws Pkcs11Exception {
        try {
            // Load the library
            System.loadLibrary(libraryName);
        } catch (Exception exception) {
            throw new Pkcs11Exception("Unable to load the PKCS11 library: " + exception.getMessage(), exception);
        }
    }

    /**
     * Initialize the PKCS11 middleware.
     *
     * @throws Pkcs11Exception Thrown if the PKCS11 middleware can't be initialized
     */
    public void C_Initialize() throws Pkcs11Exception {
        // Invoke the function
        InitializeFunction function = new InitializeFunction(linker, loaderLookup, template);
        function.invokeFunction();
    }

    /**
     * Finalize the PKCS11 middleware.
     *
     * @throws Pkcs11Exception Thrown if the PKCS11 middleware can't be finalized
     */
    public void C_Finalize() throws Pkcs11Exception {
        // Invoke the function
        FinalizeFunction finalizeFunction = new FinalizeFunction(linker, loaderLookup, template);
        finalizeFunction.invokeFunction();
    }

    /**
     * Get info from the PKCS11 middleware.
     *
     * @return PKCS11 middleware information
     * @throws Pkcs11Exception Thrown if the info can't be read
     */
    public CkInfo C_GetInfo() throws Pkcs11Exception {
        try (Arena arena = Arena.ofConfined()) {
            // Invoke the function
            GetInfoFunction function = new GetInfoFunction(linker, loaderLookup, template);
            return function.invokeFunction(arena);
        }
    }
}

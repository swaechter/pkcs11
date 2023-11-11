package ch.swaechter.pkcs11;

import ch.swaechter.pkcs11.headers.CkInfo;
import ch.swaechter.pkcs11.headers.CkVersion;
import ch.swaechter.pkcs11.templates.AlignedLinuxTemplate;
import ch.swaechter.pkcs11.templates.PackedWindowsTemplate;
import ch.swaechter.pkcs11.templates.Template;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the PKCS11 module.
 *
 * @author Simon Wächter
 */
public class Pkcs11ModuleTest {

    @Test
    public void testWorkflow() throws Pkcs11Exception {
        // Create the template
        Template template = Template.detectTemplate();
        assertTrue(template instanceof PackedWindowsTemplate || template instanceof AlignedLinuxTemplate);

        try (Pkcs11Module pkcs11Module = new Pkcs11Module(Pkcs11Template.LIBRARY_NAME, template)) {
            // Ensure the PKCS11 client is not initialized
            Assertions.assertFalse(pkcs11Module.isInitialized());

            // Initialize the module
            pkcs11Module.initializeModule();

            // Get the information
            CkInfo ckInfo = pkcs11Module.getInfo();

            // Check the information
            CkVersion cryptokiVersion = ckInfo.cryptokiVersion();
            assertNotNull(cryptokiVersion);
            assertEquals(2, cryptokiVersion.major());
            assertEquals(20, cryptokiVersion.minor());
            assertEquals("SafeNet, Inc.                   ", ckInfo.manufacturerId());
            assertEquals(0, ckInfo.flags());
            assertEquals("SafeNet eToken PKCS#11          ", ckInfo.libraryDescription());
            CkVersion libraryVersion = ckInfo.libraryVersion();
            assertEquals(10, libraryVersion.major());
            assertTrue(libraryVersion.minor() == 7 || libraryVersion.minor() == 8);

            // Finalize the module explicitly. The try-with-resource won't finalize the module another time
            pkcs11Module.finalizeModule();
        }
    }
}

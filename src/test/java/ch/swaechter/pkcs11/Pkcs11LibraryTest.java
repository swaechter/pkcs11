package ch.swaechter.pkcs11;

import ch.swaechter.pkcs11.headers.CkInfo;
import ch.swaechter.pkcs11.headers.CkVersion;
import ch.swaechter.pkcs11.templates.AlignedLinuxTemplate;
import ch.swaechter.pkcs11.templates.PackedWindowsTemplate;
import ch.swaechter.pkcs11.templates.Template;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the PKCS11 library.
 *
 * @author Simon Wächter
 */
public class Pkcs11LibraryTest {

    private static Pkcs11Library pkcs11LowLevel;

    @BeforeAll
    public static void initializePkcs11LowLevel() throws Pkcs11Exception {
        // Create the template
        Template template = Template.detectTemplate();
        assertTrue(template instanceof PackedWindowsTemplate || template instanceof AlignedLinuxTemplate);

        // Create the client
        pkcs11LowLevel = new Pkcs11Library(Pkcs11Template.LIBRARY_NAME, template);

        // Initialize the PKCS11 middleware
        pkcs11LowLevel.C_Initialize();
    }

    @AfterAll
    public static void finalizePkcs11LowLevel() throws Pkcs11Exception {
        // Finalize the PKCS11 middleware
        pkcs11LowLevel.C_Finalize();
    }

    @Test
    public void testGetInfo() throws Pkcs11Exception {
        // Get the information
        CkInfo ckInfo = pkcs11LowLevel.C_GetInfo();

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
    }
}

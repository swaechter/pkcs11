package ch.swaechter.pkcs11;

import ch.swaechter.pkcs11.headers.CkInfo;
import ch.swaechter.pkcs11.headers.CkSlotInfo;
import ch.swaechter.pkcs11.headers.CkTokenInfo;
import ch.swaechter.pkcs11.headers.CkVersion;
import ch.swaechter.pkcs11.templates.AlignedLinuxTemplate;
import ch.swaechter.pkcs11.templates.PackedWindowsTemplate;
import ch.swaechter.pkcs11.templates.Template;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

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

    @Test
    public void testGetSlotList() throws Pkcs11Exception {
        // Get the slot list
        boolean tokenPresent = true;
        int maxSlots = 100;
        List<Long> slotIds = pkcs11LowLevel.C_GetSlotList(tokenPresent, maxSlots);
        assertEquals(1, slotIds.size());
        assertEquals(0, slotIds.get(0));
    }

    @Test
    public void testGetSlotInfo() throws Pkcs11Exception {
        // Get the slot list
        boolean tokenPresent = true;
        int maxSlots = 100;
        List<Long> slotIds = pkcs11LowLevel.C_GetSlotList(tokenPresent, maxSlots);
        assertEquals(1, slotIds.size());
        assertEquals(0, slotIds.get(0));

        // Check all slots
        for (Long slotId : slotIds) {
            // Check the slot ID
            assertTrue(slotId >= 0);

            // Get the slot information
            CkSlotInfo ckSlotInfo = pkcs11LowLevel.C_GetSlotInfo(slotId);
            assertEquals("SafeNet Token JC 0                                              ", ckSlotInfo.slotDescription());
            assertEquals("SafeNet, Inc.                   ", ckSlotInfo.manufacturerId());
            assertEquals(7, ckSlotInfo.flags());
            CkVersion hardwareVersion = ckSlotInfo.hardwareVersion();
            assertNotNull(hardwareVersion);
            assertEquals(2, hardwareVersion.major());
            assertEquals(0, hardwareVersion.minor());
            CkVersion firmwareVersion = ckSlotInfo.firmwareVersion();
            assertNotNull(firmwareVersion);
            assertEquals(0, firmwareVersion.major());
            assertEquals(0, firmwareVersion.minor());
        }
    }

    @Test
    public void testGetTokenInfo() throws Pkcs11Exception {
        // Get the slot list
        boolean tokenPresent = true;
        int maxSlots = 100;
        List<Long> slotIds = pkcs11LowLevel.C_GetSlotList(tokenPresent, maxSlots);
        assertEquals(1, slotIds.size());
        assertEquals(0, slotIds.get(0));

        // Check all slots
        for (Long slotId : slotIds) {
            // Check the slot ID
            assertTrue(slotId >= 0);

            // Get the token information
            CkTokenInfo ckTokenInfo = pkcs11LowLevel.C_GetTokenInfo(slotId);
            assertEquals("Secacon Gygli Engineering GmbH  ", ckTokenInfo.label());
            assertEquals("SafeNet, Inc.                   ", ckTokenInfo.manufacturerId());
            assertEquals("eToken          ", ckTokenInfo.model());
            assertEquals("02aea1d3        ", ckTokenInfo.serialNumber());
            assertEquals(1549, ckTokenInfo.flags());
            assertEquals(0, ckTokenInfo.maxSessionCount());
            assertEquals(0, ckTokenInfo.sessionCount());
            assertEquals(0, ckTokenInfo.maxRwSessionCount());
            assertEquals(0, ckTokenInfo.rwSessionCount());
            assertEquals(20, ckTokenInfo.maxPinLen());
            assertEquals(6, ckTokenInfo.minPinLen());
            assertEquals(81920, ckTokenInfo.totalPublicMemory());
            assertEquals(32767, ckTokenInfo.freePublicMemory());
            assertEquals(81920, ckTokenInfo.totalPrivateMemory());
            assertEquals(32767, ckTokenInfo.freePrivateMemory());
            assertArrayEquals(new byte[16], ckTokenInfo.utcTime().getBytes(StandardCharsets.UTF_8));
        }
    }
}

package ch.swaechter.pkcs11;

import ch.swaechter.pkcs11.headers.*;
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
            assertTrue(ckSlotInfo.slotDescription().equals("SafeNet Token JC 0                                              ") || ckSlotInfo.slotDescription().equals("SafeNet eToken 5100 [eToken 5110 SC] 00 00                      "));
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
            CkVersion hardwareVersion = ckTokenInfo.hardwareVersion();
            assertNotNull(hardwareVersion);
            assertEquals(16, hardwareVersion.major());
            assertEquals(0, hardwareVersion.minor());
            CkVersion firmwareVersion = ckTokenInfo.firmwareVersion();
            assertNotNull(firmwareVersion);
            assertEquals(0, firmwareVersion.major());
            assertEquals(0, firmwareVersion.minor());
            assertArrayEquals(new byte[16], ckTokenInfo.utcTime().getBytes(StandardCharsets.UTF_8));
        }
    }

    @Test
    public void testSession() throws Pkcs11Exception {
        // Define the values
        long slotId = 0;
        long sessionInfoFlags = CkSessionInfoFlag.CKF_RW_SESSION.value | CkSessionInfoFlag.CKF_SERIAL_SESSION.value;

        // Open a new session
        long sessionId = pkcs11LowLevel.C_OpenSession(slotId, sessionInfoFlags);
        assertTrue(sessionId > 0);

        // Get the session information
        CkSessionInfo ckSessionInfo = pkcs11LowLevel.C_GetSessionInfo(sessionId);
        assertEquals(slotId, ckSessionInfo.slotId());
        assertEquals(CkSessionState.CKS_RW_PUBLIC_SESSION, ckSessionInfo.state());
        assertEquals(6, ckSessionInfo.flags());
        assertEquals(0, ckSessionInfo.deviceError());

        // Close the session
        pkcs11LowLevel.C_CloseSession(sessionId);

        // Close all sessions for the slot
        pkcs11LowLevel.C_CloseAllSessions(slotId);
    }

    @Test
    public void testLoginAndLogout() throws Pkcs11Exception {
        // Define the values
        long slotId = 0;
        long sessionInfoFlags = CkSessionInfoFlag.CKF_RW_SESSION.value | CkSessionInfoFlag.CKF_SERIAL_SESSION.value;

        // Open a new session
        long sessionId = pkcs11LowLevel.C_OpenSession(slotId, sessionInfoFlags);
        assertTrue(sessionId > 0);

        // Login and logout as user
        pkcs11LowLevel.C_Login(sessionId, CkUserType.CKU_USER, Pkcs11Template.PKCS11_TOKEN_PIN);
        pkcs11LowLevel.C_Logout(sessionId);

        // Login and logout as security officer
        pkcs11LowLevel.C_Login(sessionId, CkUserType.CKU_SO, Pkcs11Template.PKCS11_TOKEN_SO_PIN);
        pkcs11LowLevel.C_Logout(sessionId);

        // Try to log in via protected authentication path
        Pkcs11Exception pkcs11Exception = assertThrows(Pkcs11Exception.class, () -> pkcs11LowLevel.C_Login(sessionId, CkUserType.CKU_SO, null));
        assertTrue(pkcs11Exception.getMessage().contains("C_Login failed"));

        // Close the session
        pkcs11LowLevel.C_CloseSession(sessionId);
    }
}

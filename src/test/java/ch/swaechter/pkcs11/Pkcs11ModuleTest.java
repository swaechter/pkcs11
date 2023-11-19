package ch.swaechter.pkcs11;

import ch.swaechter.pkcs11.headers.*;
import ch.swaechter.pkcs11.objects.*;
import ch.swaechter.pkcs11.templates.AlignedLinuxTemplate;
import ch.swaechter.pkcs11.templates.PackedWindowsTemplate;
import ch.swaechter.pkcs11.templates.Template;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the PKCS11 module.
 *
 * @author Simon Wächter
 */
public class Pkcs11ModuleTest {

    @Test
    public void testWorkflow() throws Exception {
        // Create the template
        Template template = Template.detectTemplate();
        assertTrue(template instanceof PackedWindowsTemplate || template instanceof AlignedLinuxTemplate);

        // Work with the module
        try (Pkcs11Module pkcs11Module = new Pkcs11Module(Pkcs11Template.LIBRARY_NAME, template)) {
            // Get the library
            assertNotNull(pkcs11Module.getPkcs11Library());

            // Ensure the PKCS11 client is not initialized
            assertFalse(pkcs11Module.isInitialized());

            // Initialize the module
            pkcs11Module.initializeModule();

            // Get the information
            Pkcs11Info pkcs11Info = pkcs11Module.getInfo();

            // Check the information
            Pkcs11Version cryptokiVersion = pkcs11Info.getCryptokiVersion();
            assertNotNull(cryptokiVersion);
            assertEquals(2, cryptokiVersion.major());
            assertEquals(20, cryptokiVersion.minor());
            assertEquals("SafeNet, Inc.", pkcs11Info.getManufacturerId());
            assertEquals(0, pkcs11Info.getFlags());
            assertEquals("SafeNet eToken PKCS#11", pkcs11Info.getLibraryDescription());
            Pkcs11Version libraryVersion = pkcs11Info.getLibraryVersion();
            assertEquals(10, libraryVersion.major());
            assertTrue(libraryVersion.minor() == 7 || libraryVersion.minor() == 8);

            // Get the slots
            List<Pkcs11Slot> pkcs11Slots = pkcs11Module.getSlots(true);
            assertEquals(1, pkcs11Slots.size());

            // Iterate over all slots
            for (Pkcs11Slot pkcs11Slot : pkcs11Slots) {
                // Check the slot
                assertEquals(0, pkcs11Slot.getSlotId());

                // Get the slot
                pkcs11Module.getSlot(pkcs11Slot.getSlotId());

                // Get the slot info
                Pkcs11SlotInfo pkcs11SlotInfo = pkcs11Slot.getSlotInfo();
                assertNotNull(pkcs11SlotInfo);
                assertTrue(pkcs11SlotInfo.getSlotDescription().equals("SafeNet Token JC 0") || pkcs11SlotInfo.getSlotDescription().equals("SafeNet eToken 5100 [eToken 5110 SC] 00 00"));
                assertEquals("SafeNet, Inc.", pkcs11SlotInfo.getManufacturerId());
                assertEquals(7, pkcs11SlotInfo.getFlags());
                Pkcs11Version slotInfoHardwareVersion = pkcs11SlotInfo.getHardwareVersion();
                assertNotNull(slotInfoHardwareVersion);
                assertEquals(2, slotInfoHardwareVersion.major());
                assertEquals(0, slotInfoHardwareVersion.minor());
                Pkcs11Version slotInfoFirmwareVersion = pkcs11SlotInfo.getFirmwareVersion();
                assertNotNull(slotInfoFirmwareVersion);
                assertEquals(0, slotInfoFirmwareVersion.major());
                assertEquals(0, slotInfoFirmwareVersion.minor());
                assertTrue(pkcs11SlotInfo.isTokenPresent());
                assertTrue(pkcs11SlotInfo.isRemovableDevice());
                assertTrue(pkcs11SlotInfo.isHardwareSlot());

                if (pkcs11SlotInfo.isTokenPresent()) {
                    // Get the token
                    Pkcs11Token pkcs11Token = pkcs11Slot.getToken();
                    assertNotNull(pkcs11Token);
                    assertTrue(pkcs11Token.isLoginRequired());

                    // Get the token info
                    Pkcs11TokenInfo pkcs11TokenInfo = pkcs11Token.getTokenInfo();
                    assertNotNull(pkcs11TokenInfo);
                    assertEquals("Secacon Gygli Engineering GmbH", pkcs11TokenInfo.getLabel());
                    assertEquals("SafeNet, Inc.", pkcs11TokenInfo.getManufacturerId());
                    assertEquals("eToken", pkcs11TokenInfo.getModel());
                    assertEquals("02aea1d3", pkcs11TokenInfo.getSerialNumber());
                    assertEquals(1549, pkcs11TokenInfo.getFlags());
                    assertEquals(0, pkcs11TokenInfo.getMaxSessionCount());
                    assertEquals(0, pkcs11TokenInfo.getSessionCount());
                    assertEquals(0, pkcs11TokenInfo.getMaxRwSessionCount());
                    assertEquals(0, pkcs11TokenInfo.getRwSessionCount());
                    assertEquals(20, pkcs11TokenInfo.getMaxPinLen());
                    assertEquals(6, pkcs11TokenInfo.getMinPinLen());
                    assertEquals(81920, pkcs11TokenInfo.getTotalPublicMemory());
                    assertEquals(32767, pkcs11TokenInfo.getFreePublicMemory());
                    assertEquals(81920, pkcs11TokenInfo.getTotalPrivateMemory());
                    assertEquals(32767, pkcs11TokenInfo.getFreePrivateMemory());
                    Pkcs11Version tokenInfoHardwareVersion = pkcs11TokenInfo.getHardwareVersion();
                    assertNotNull(tokenInfoHardwareVersion);
                    assertEquals(16, tokenInfoHardwareVersion.major());
                    assertEquals(0, tokenInfoHardwareVersion.minor());
                    Pkcs11Version tokenInfoFirmwareVersion = pkcs11TokenInfo.getFirmwareVersion();
                    assertNotNull(tokenInfoFirmwareVersion);
                    assertEquals(0, tokenInfoFirmwareVersion.major());
                    assertEquals(0, tokenInfoFirmwareVersion.minor());
                    assertTrue(pkcs11TokenInfo.getUtcDate().isEmpty());
                    assertTrue(pkcs11TokenInfo.hasRng());
                    assertFalse(pkcs11TokenInfo.isWriteProtected());
                    assertTrue(pkcs11TokenInfo.isLoginRequired());
                    assertTrue(pkcs11TokenInfo.isUserPinInitialized());
                    assertFalse(pkcs11TokenInfo.isRestoreKeyNotNeeded());
                    assertFalse(pkcs11TokenInfo.hasClock());
                    assertFalse(pkcs11TokenInfo.hasProtectedAuthenticationPath());
                    assertTrue(pkcs11TokenInfo.hasDualCryptoOperations());
                    assertTrue(pkcs11TokenInfo.isTokenInitialized());
                    assertFalse(pkcs11TokenInfo.hasSecondaryAuthentication());
                    assertFalse(pkcs11TokenInfo.isUserPinCountLow());
                    assertFalse(pkcs11TokenInfo.isUserPinFinalTry());
                    assertFalse(pkcs11TokenInfo.isUserPinLocked());
                    assertFalse(pkcs11TokenInfo.isUserPinToBeChanged());
                    assertFalse(pkcs11TokenInfo.isSoPinCountLow());
                    assertFalse(pkcs11TokenInfo.isSoPinFinalTry());
                    assertFalse(pkcs11TokenInfo.isSoPinLocked());
                    assertFalse(pkcs11TokenInfo.isSoPinToBeChanged());
                    assertFalse(pkcs11TokenInfo.isInErrorState());

                    // Open a session
                    boolean rwSession = true;
                    boolean serialSession = true;
                    try (Pkcs11Session pkcs11Session = pkcs11Token.openSession(rwSession, serialSession)) {
                        // Ensure the session ID is larger than zero
                        assertTrue(pkcs11Session.getSessionId() > 0);

                        // Get the session info
                        Pkcs11SessionInfo pkcs11SessionInfo = pkcs11Session.getSessionInfo();
                        assertEquals(pkcs11Slot.getSlotId(), pkcs11SessionInfo.getSlotId());
                        assertEquals(CkSessionState.CKS_RW_PUBLIC_SESSION, pkcs11SessionInfo.getSessionState());
                        assertEquals(6, pkcs11SessionInfo.getFlags());
                        assertEquals(0, pkcs11SessionInfo.getDeviceError());
                        assertTrue(pkcs11SessionInfo.isRwSession());
                        assertTrue(pkcs11SessionInfo.isSerialSession());

                        // Login and logout as user
                        pkcs11Session.loginUser(CkUserType.CKU_USER, Pkcs11Template.PKCS11_TOKEN_PIN);
                        pkcs11Session.logoutUser();

                        // Login and logout as security officer
                        pkcs11Session.loginUser(CkUserType.CKU_SO, Pkcs11Template.PKCS11_TOKEN_SO_PIN);
                        pkcs11Session.logoutUser();

                        // Try to log in via protected authentication path
                        Pkcs11Exception pkcs11Exception = assertThrows(Pkcs11Exception.class, () -> pkcs11Session.loginUser(CkUserType.CKU_SO, null));
                        assertTrue(pkcs11Exception.getMessage().contains("C_Login failed"));
                    }

                    // Close all sessions on the token
                    pkcs11Token.closeAllSessions();
                }
            }

            // Finalize the module explicitly. The try-with-resource won't finalize the module another time
            pkcs11Module.finalizeModule();
        }
    }

    @Test
    public void testObjectsAndSign() throws Exception {
        // Create the template
        Template template = Template.detectTemplate();
        assertTrue(template instanceof PackedWindowsTemplate || template instanceof AlignedLinuxTemplate);

        // Work with the module
        try (Pkcs11Module pkcs11Module = new Pkcs11Module(Pkcs11Template.LIBRARY_NAME, template)) {
            // Get the slot and token
            Pkcs11Slot pkcs11Slot = pkcs11Module.getSlot(0);
            Pkcs11Token pkcs11Token = pkcs11Slot.getToken();

            // Open a session
            try (Pkcs11Session pkcs11Session = pkcs11Token.openSession(true, true)) {
                // Login
                pkcs11Session.loginUser(CkUserType.CKU_USER, Pkcs11Template.PKCS11_TOKEN_PIN);

                // Find the private key handle
                List<CkAttributeValue> privateKeyCkAttributeValues = new ArrayList<>();
                privateKeyCkAttributeValues.add(new CkAttributeValue(CkAttribute.CKA_CLASS, CkObjectClass.CKO_PRIVATE_KEY.value));
                List<Long> privateKeyObjectIds = pkcs11Session.findObjects(privateKeyCkAttributeValues);
                assertEquals(1, privateKeyObjectIds.size());
                assertTrue(privateKeyObjectIds.contains(43450373L) || privateKeyObjectIds.contains(206635013L));

                // Find the certificate handles
                List<CkAttributeValue> certificateCkAttributeValues = new ArrayList<>();
                certificateCkAttributeValues.add(new CkAttributeValue(CkAttribute.CKA_CLASS, CkObjectClass.CKO_CERTIFICATE.value));
                List<Long> certificateObjectIds = pkcs11Session.findObjects(certificateCkAttributeValues);
                assertEquals(3, certificateObjectIds.size());
                assertTrue(certificateObjectIds.contains(236257286L) || certificateObjectIds.contains(218038278L));
                assertTrue(certificateObjectIds.contains(11337735L) || certificateObjectIds.contains(71958535L));
                assertTrue(certificateObjectIds.contains(236781576L) || certificateObjectIds.contains(149684232L));

                // Read all certificate values
                List<CkAttributeValue> certificateValueCkAttributeValues = new ArrayList<>();
                certificateValueCkAttributeValues.add(new CkAttributeValue(CkAttribute.CKA_VALUE, null));
                for (long certificateObjectId : certificateObjectIds) {
                    List<byte[]> certificateAttributeValues = pkcs11Session.getAttributeValue(certificateObjectId, certificateValueCkAttributeValues);
                    assertEquals(1, certificateAttributeValues.size());
                }

                // Logout
                pkcs11Session.logoutUser();
            }
        }
    }

    @Test
    public void testRandom() throws Exception {
        // Create the template
        Template template = Template.detectTemplate();
        assertTrue(template instanceof PackedWindowsTemplate || template instanceof AlignedLinuxTemplate);

        // Work with the module
        try (Pkcs11Module pkcs11Module = new Pkcs11Module(Pkcs11Template.LIBRARY_NAME, template)) {
            // Initialize the module
            pkcs11Module.initializeModule();

            // Get all slots
            List<Pkcs11Slot> pkcs11Slots = pkcs11Module.getSlots(true);
            assertEquals(1, pkcs11Slots.size());
            Pkcs11Slot pkcs11Slot = pkcs11Slots.get(0);

            // Open a session
            try (Pkcs11Session pkcs11Session = pkcs11Slot.getToken().openSession(true, true)) {
                // Generate a first 100 byte random buffer
                byte[] firstRandomBuffer = pkcs11Session.generateRandom(100);
                assertNotNull(firstRandomBuffer);
                assertEquals(100, firstRandomBuffer.length);
                assertFalse(Pkcs11Utils.isEmptyByteArray(firstRandomBuffer));

                // Generate a second 100 byte random buffer
                byte[] secondRandomBuffer = pkcs11Session.generateRandom(100);
                assertNotNull(secondRandomBuffer);
                assertEquals(100, secondRandomBuffer.length);
                assertFalse(Pkcs11Utils.isEmptyByteArray(secondRandomBuffer));

                // Ensure they are not the same
                assertFalse(Arrays.equals(firstRandomBuffer, secondRandomBuffer));

                // Seed the RNG with the second buffer
                pkcs11Session.seedRandom(secondRandomBuffer);
            }
        }
    }
}

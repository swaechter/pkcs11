package ch.swaechter.pkcs11;

import ch.swaechter.pkcs11.objects.*;
import ch.swaechter.pkcs11.templates.AlignedLinuxTemplate;
import ch.swaechter.pkcs11.templates.PackedWindowsTemplate;
import ch.swaechter.pkcs11.templates.Template;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

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
            boolean tokenPresent = true;
            int maxSlots = 100;
            List<Pkcs11Slot> pkcs11Slots = pkcs11Module.getSlots(tokenPresent, maxSlots);
            assertEquals(1, pkcs11Slots.size());

            // Iterate over all slots
            for (Pkcs11Slot pkcs11Slot : pkcs11Slots) {
                // Check the slot
                assertEquals(0, pkcs11Slot.getSlotId());

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
                }
            }

            // Finalize the module explicitly. The try-with-resource won't finalize the module another time
            pkcs11Module.finalizeModule();
        }
    }
}

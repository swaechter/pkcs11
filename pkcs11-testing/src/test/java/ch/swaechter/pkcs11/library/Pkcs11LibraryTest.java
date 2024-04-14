package ch.swaechter.pkcs11.library;

import ch.swaechter.pkcs11.Pkcs11TestTemplate;
import ch.swaechter.pkcs11.library.headers.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the PKCS11 library.
 *
 * @author Simon Wächter
 */
public class Pkcs11LibraryTest {

    private static Pkcs11Library pkcs11Library;

    @BeforeAll
    public static void initializePkcs11LowLevel() throws Pkcs11Exception {
        // Create the client
        pkcs11Library = Pkcs11Library.detectPlatform(Pkcs11TestTemplate.LIBRARY_NAME);
        //pkcs11Library = Pkcs11Library.detectPlatform("softhsm2-x64");

        // Initialize the PKCS11 middleware
        pkcs11Library.C_Initialize();
    }

    @AfterAll
    public static void finalizePkcs11LowLevel() throws Pkcs11Exception {
        // Finalize the PKCS11 middleware
        pkcs11Library.C_Finalize();
    }

    @Test
    public void testGetInfo() throws Pkcs11Exception {
        // Get the information
        CkInfo ckInfo = pkcs11Library.C_GetInfo();

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
        List<Long> slotIds = pkcs11Library.C_GetSlotList(true);
        assertEquals(1, slotIds.size());
        assertEquals(0, slotIds.getFirst());
    }

    @Test
    public void testGetSlotInfo() throws Pkcs11Exception {
        // Get the slot list
        List<Long> slotIds = pkcs11Library.C_GetSlotList(true);
        assertEquals(1, slotIds.size());
        assertEquals(0, slotIds.getFirst());

        // Check all slots
        for (Long slotId : slotIds) {
            // Check the slot ID
            assertTrue(slotId >= 0);

            // Get the slot information
            CkSlotInfo ckSlotInfo = pkcs11Library.C_GetSlotInfo(slotId);
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
        List<Long> slotIds = pkcs11Library.C_GetSlotList(true);
        assertEquals(1, slotIds.size());
        assertEquals(0, slotIds.getFirst());

        // Check all slots
        for (Long slotId : slotIds) {
            // Check the slot ID
            assertTrue(slotId >= 0);

            // Get the token information
            CkTokenInfo ckTokenInfo = pkcs11Library.C_GetTokenInfo(slotId);
            assertEquals("Secacon Gygli Engineering GmbH  ", ckTokenInfo.label());
            assertEquals("SafeNet, Inc.                   ", ckTokenInfo.manufacturerId());
            assertEquals("eToken          ", ckTokenInfo.model());
            assertEquals("02c84d59        ", ckTokenInfo.serialNumber());
            assertEquals(1549, ckTokenInfo.flags());
            assertEquals(0, ckTokenInfo.maxSessionCount());
            assertEquals(0, ckTokenInfo.sessionCount());
            assertEquals(0, ckTokenInfo.maxRwSessionCount());
            assertEquals(0, ckTokenInfo.rwSessionCount());
            assertEquals(20, ckTokenInfo.maxPinLen());
            assertEquals(8, ckTokenInfo.minPinLen());
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
        long sessionId = pkcs11Library.C_OpenSession(slotId, sessionInfoFlags);
        assertTrue(sessionId > 0);

        // Get the session information
        CkSessionInfo ckSessionInfo = pkcs11Library.C_GetSessionInfo(sessionId);
        assertEquals(slotId, ckSessionInfo.slotId());
        assertEquals(CkSessionState.CKS_RW_PUBLIC_SESSION, ckSessionInfo.state());
        assertEquals(6, ckSessionInfo.flags());
        assertEquals(0, ckSessionInfo.deviceError());

        // Close the session
        pkcs11Library.C_CloseSession(sessionId);

        // Close all sessions for the slot
        pkcs11Library.C_CloseAllSessions(slotId);
    }

    @Test
    public void testLoginAndLogout() throws Pkcs11Exception {
        // Define the values
        long slotId = 0;
        long sessionInfoFlags = CkSessionInfoFlag.CKF_RW_SESSION.value | CkSessionInfoFlag.CKF_SERIAL_SESSION.value;

        // Open a new session
        long sessionId = pkcs11Library.C_OpenSession(slotId, sessionInfoFlags);
        assertTrue(sessionId > 0);

        // Login and logout as user
        pkcs11Library.C_Login(sessionId, CkUserType.CKU_USER, Pkcs11TestTemplate.PKCS11_TOKEN_PIN);
        pkcs11Library.C_Logout(sessionId);

        // Login and logout as security officer
        pkcs11Library.C_Login(sessionId, CkUserType.CKU_SO, Pkcs11TestTemplate.PKCS11_TOKEN_SO_PIN);
        pkcs11Library.C_Logout(sessionId);

        // Try to log in via protected authentication path
        Pkcs11Exception pkcs11Exception = Assertions.assertThrows(Pkcs11Exception.class, () -> pkcs11Library.C_Login(sessionId, CkUserType.CKU_SO, null));
        assertTrue(pkcs11Exception.getMessage().contains("C_Login failed"));

        // Close the session
        pkcs11Library.C_CloseSession(sessionId);
    }


    @Test
    public void testPinChangeAndUnlock() throws Pkcs11Exception {
        // Define the values
        long slotId = 0;
        long sessionInfoFlags = CkSessionInfoFlag.CKF_RW_SESSION.value | CkSessionInfoFlag.CKF_SERIAL_SESSION.value;
        String newPin = "11992288";

        // Open a new session
        long sessionId = pkcs11Library.C_OpenSession(slotId, sessionInfoFlags);
        assertTrue(sessionId > 0);

        // Login as user and change the user PIN
        pkcs11Library.C_Login(sessionId, CkUserType.CKU_USER, Pkcs11TestTemplate.PKCS11_TOKEN_PIN);
        pkcs11Library.C_SetPIN(sessionId, Pkcs11TestTemplate.PKCS11_TOKEN_PIN, newPin);
        pkcs11Library.C_Logout(sessionId);

        // Test the PIN
        pkcs11Library.C_Login(sessionId, CkUserType.CKU_USER, newPin);
        pkcs11Library.C_Logout(sessionId);

        // Login as SO and (re-)set a new user PIN
        pkcs11Library.C_Login(sessionId, CkUserType.CKU_SO, Pkcs11TestTemplate.PKCS11_TOKEN_SO_PIN);
        pkcs11Library.C_InitPIN(sessionId, Pkcs11TestTemplate.PKCS11_TOKEN_PIN);
        pkcs11Library.C_Logout(sessionId);

        // Close the session
        pkcs11Library.C_CloseSession(sessionId);
    }

    @Test
    public void testObjects() throws Pkcs11Exception {
        // Define the values
        long slotId = 0;
        long sessionInfoFlags = CkSessionInfoFlag.CKF_RW_SESSION.value | CkSessionInfoFlag.CKF_SERIAL_SESSION.value;
        int maxObjects = 10;

        // Open a new session
        long sessionId = pkcs11Library.C_OpenSession(slotId, sessionInfoFlags);

        // Login as user
        pkcs11Library.C_Login(sessionId, CkUserType.CKU_USER, Pkcs11TestTemplate.PKCS11_TOKEN_PIN);

        // Define the private key find object template
        List<CkAttributeValue> ckAttributeSearchTemplate = new ArrayList<>();
        ckAttributeSearchTemplate.add(new CkAttributeValue(CkAttribute.CKA_CLASS, CkObjectClass.CKO_PRIVATE_KEY.value));

        // Start the private key object finding
        pkcs11Library.C_FindObjectsInit(sessionId, ckAttributeSearchTemplate);

        // Search the objects
        List<Long> objectHandles = pkcs11Library.C_FindObjects(sessionId, maxObjects);
        assertEquals(1, objectHandles.size());
        assertTrue(objectHandles.contains(43450373L) || objectHandles.contains(206635013L));

        // Get the object size
        long objectSize = pkcs11Library.C_GetObjectSize(sessionId, objectHandles.getFirst());
        assertEquals(54, objectSize);

        // Finalize the object search
        pkcs11Library.C_FindObjectsFinal(sessionId);

        // Define the certificate find object template
        ckAttributeSearchTemplate.clear();
        ckAttributeSearchTemplate.add(new CkAttributeValue(CkAttribute.CKA_CLASS, CkObjectClass.CKO_CERTIFICATE.value));
        ckAttributeSearchTemplate.add(new CkAttributeValue(CkAttribute.CKA_VALUE, null));

        // Start the certificate object finding
        pkcs11Library.C_FindObjectsInit(sessionId, ckAttributeSearchTemplate);

        // Search the objects
        objectHandles = pkcs11Library.C_FindObjects(sessionId, maxObjects);
        assertEquals(3, objectHandles.size());
        assertTrue(objectHandles.contains(236257286L) || objectHandles.contains(218038278L));
        assertTrue(objectHandles.contains(11337735L) || objectHandles.contains(71958535L));
        assertTrue(objectHandles.contains(236781576L) || objectHandles.contains(149684232L));

        // Get the object sizes
        for (long objectHandle : objectHandles) {
            objectSize = pkcs11Library.C_GetObjectSize(sessionId, objectHandle);
            assertTrue(objectSize > 1300 && objectSize < 2000);
        }

        // Finalize the object search
        pkcs11Library.C_FindObjectsFinal(sessionId);

        // Get the attribute values
        for (long objectHandle : objectHandles) {
            List<byte[]> attributeValues = pkcs11Library.C_GetAttributeValue(sessionId, objectHandle, List.of(CkAttribute.CKA_VALUE));
            assertEquals(1, attributeValues.size());
            byte[] attributeValue = attributeValues.getFirst();
            assertTrue(attributeValue.length >= 1380 && attributeValue.length <= 1852);
        }

        // Logout
        pkcs11Library.C_Logout(sessionId);

        // Close the session
        pkcs11Library.C_CloseSession(sessionId);
    }

    @Test
    public void testDigesting() throws Pkcs11Exception {
        // Define the values
        long slotId = 0;
        long sessionInfoFlags = CkSessionInfoFlag.CKF_RW_SESSION.value | CkSessionInfoFlag.CKF_SERIAL_SESSION.value;

        // Define the data and the expected digest
        byte[] data = "Message to digest!".getBytes(StandardCharsets.UTF_8);
        String expectedDigest = "af79b3a4fe04eedf6cff6c10ebfde114158c1d250e8362f4307385050b2ba015";

        // Open a new session
        long sessionId = pkcs11Library.C_OpenSession(slotId, sessionInfoFlags);

        // Login as user
        pkcs11Library.C_Login(sessionId, CkUserType.CKU_USER, Pkcs11TestTemplate.PKCS11_TOKEN_PIN);

        // Digest a single block via single-part digest operation
        pkcs11Library.C_DigestInit(sessionId, CkMechanism.CKM_SHA256);
        byte[] digestedData = pkcs11Library.C_Digest(sessionId, data);
        String digestHash = Pkcs11Utils.bytesToHex(digestedData);
        assertEquals(expectedDigest, digestHash);

        // Digest a single block via multi-part digest operation
        pkcs11Library.C_DigestInit(sessionId, CkMechanism.CKM_SHA256);
        pkcs11Library.C_DigestUpdate(sessionId, data);
        digestedData = pkcs11Library.C_DigestFinal(sessionId);
        digestHash = Pkcs11Utils.bytesToHex(digestedData);
        assertEquals(expectedDigest, digestHash);

        // Digest multiple blocks via multi-part digest operation
        pkcs11Library.C_DigestInit(sessionId, CkMechanism.CKM_SHA256);
        for (int i = 0; i < 9; i++) {
            byte[] slice = Arrays.copyOfRange(data, i * 2, i * 2 + 2);
            pkcs11Library.C_DigestUpdate(sessionId, slice);
        }
        digestedData = pkcs11Library.C_DigestFinal(sessionId);
        digestHash = Pkcs11Utils.bytesToHex(digestedData);
        assertEquals(expectedDigest, digestHash);

        // Logout
        pkcs11Library.C_Logout(sessionId);

        // Close the session
        pkcs11Library.C_CloseSession(sessionId);
    }

    @Test
    public void testSigning() throws Pkcs11Exception {
        // Define the values
        long slotId = 0;
        long sessionInfoFlags = CkSessionInfoFlag.CKF_RW_SESSION.value | CkSessionInfoFlag.CKF_SERIAL_SESSION.value;
        int maxObjects = 10;
        byte[] message = "Message to sign!".getBytes(StandardCharsets.UTF_8);

        // Open a new session
        long sessionId = pkcs11Library.C_OpenSession(slotId, sessionInfoFlags);

        // Login as user
        pkcs11Library.C_Login(sessionId, CkUserType.CKU_USER, Pkcs11TestTemplate.PKCS11_TOKEN_PIN);

        // Define the private key find object template
        List<CkAttributeValue> ckAttributeSearchTemplate = new ArrayList<>();
        ckAttributeSearchTemplate.add(new CkAttributeValue(CkAttribute.CKA_CLASS, CkObjectClass.CKO_PRIVATE_KEY.value));

        // Start the private key object finding
        pkcs11Library.C_FindObjectsInit(sessionId, ckAttributeSearchTemplate);

        // Search the objects
        List<Long> objectHandles = pkcs11Library.C_FindObjects(sessionId, maxObjects);
        assertEquals(1, objectHandles.size());
        assertTrue(objectHandles.contains(43450373L) || objectHandles.contains(206635013L));
        long keyHandleId = objectHandles.getFirst();

        // Finalize the object search
        pkcs11Library.C_FindObjectsFinal(sessionId);

        // Initialize the signing
        pkcs11Library.C_SignInit(sessionId, CkMechanism.CKM_SHA256_RSA_PKCS, keyHandleId);

        // Sign the message
        byte[] signedMessage = pkcs11Library.C_Sign(sessionId, message, 1000);
        assertFalse(Pkcs11Utils.isEmptyByteArray(signedMessage));

        // Logout
        pkcs11Library.C_Logout(sessionId);

        // Close the session
        pkcs11Library.C_CloseSession(sessionId);
    }

    @Test
    public void testRandom() throws Pkcs11Exception {
        // Define the values
        long slotId = 0;
        long sessionInfoFlags = CkSessionInfoFlag.CKF_RW_SESSION.value | CkSessionInfoFlag.CKF_SERIAL_SESSION.value;

        // Open a new session
        long sessionId = pkcs11Library.C_OpenSession(slotId, sessionInfoFlags);

        // Generate a first 100 byte random buffer
        byte[] firstRandomBuffer = pkcs11Library.C_GenerateRandom(sessionId, 100);
        assertNotNull(firstRandomBuffer);
        assertEquals(100, firstRandomBuffer.length);
        assertFalse(Pkcs11Utils.isEmptyByteArray(firstRandomBuffer));

        // Generate a second 100 byte random buffer
        byte[] secondRandomBuffer = pkcs11Library.C_GenerateRandom(sessionId, 100);
        assertNotNull(secondRandomBuffer);
        assertEquals(100, secondRandomBuffer.length);
        assertFalse(Pkcs11Utils.isEmptyByteArray(secondRandomBuffer));

        // Ensure they are not the same
        assertFalse(Arrays.equals(firstRandomBuffer, secondRandomBuffer));

        // Seed the RNG with the second buffer
        pkcs11Library.C_SeedRandom(sessionId, secondRandomBuffer);

        // Close the session
        pkcs11Library.C_CloseSession(sessionId);
    }
}

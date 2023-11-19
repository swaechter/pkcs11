package ch.swaechter.pkcs11;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the util methods
 */
public class Pkcs11UtilsTest {

    @Test
    public void testIsEmptyString() {
        // Test all combinations
        assertTrue(Pkcs11Utils.isEmptyString(null));
        assertTrue(Pkcs11Utils.isEmptyString(""));
        assertTrue(Pkcs11Utils.isEmptyString("     "));
        assertFalse(Pkcs11Utils.isEmptyString("PKCS11"));
    }

    @Test
    public void testIsEmptyByteArray() {
        // Test all combinations
        assertTrue(Pkcs11Utils.isEmptyByteArray(null));
        assertTrue(Pkcs11Utils.isEmptyByteArray(new byte[5]));
        assertFalse(Pkcs11Utils.isEmptyByteArray(new byte[]{0x0, 0x0, 0x5, 0x0, 0x0}));
        assertFalse(Pkcs11Utils.isEmptyByteArray("PKCS11".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    public void testGetDate() throws Pkcs11Exception {
        // Test empty dates
        assertTrue(Pkcs11Utils.getDate(null).isEmpty());
        assertTrue(Pkcs11Utils.getDate("").isEmpty());
        assertTrue(Pkcs11Utils.getDate("                ").isEmpty());

        // Test wrong dates
        Pkcs11Exception exception = assertThrows(Pkcs11Exception.class, () -> Pkcs11Utils.getDate("PKCS11"));
        assertEquals("A UTC time has to be 16 characters long (YYYYMMDDhhmmssxx)", exception.getMessage());

        // Test a correct date
        Optional<Instant> optionalInstant = Pkcs11Utils.getDate("2023111217163000");
        assertTrue(optionalInstant.isPresent());
        Instant instant = optionalInstant.get();
        assertEquals(2023, instant.atZone(ZoneOffset.UTC).getYear());
        assertEquals(11, instant.atZone(ZoneOffset.UTC).getMonthValue());
        assertEquals(12, instant.atZone(ZoneOffset.UTC).getDayOfMonth());
        assertEquals(17, instant.atZone(ZoneOffset.UTC).getHour());
        assertEquals(16, instant.atZone(ZoneOffset.UTC).getMinute());
        assertEquals(30, instant.atZone(ZoneOffset.UTC).getSecond());
    }

    @Test
    public void testBytesToHex() {
        // Convert a hash
        String hexHash = Pkcs11Utils.bytesToHex(new byte[]{-81, 121, -77, -92, -2, 4, -18, -33, 108, -1, 108, 16, -21, -3, -31, 20, 21, -116, 29, 37, 14, -125, 98, -12, 48, 115, -123, 5, 11, 43, -96, 21});
        assertEquals("af79b3a4fe04eedf6cff6c10ebfde114158c1d250e8362f4307385050b2ba015", hexHash);
    }
}

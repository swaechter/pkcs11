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
}

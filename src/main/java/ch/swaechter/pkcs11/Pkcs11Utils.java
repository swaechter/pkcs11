package ch.swaechter.pkcs11;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

/**
 * Helper method for some PKCS11 methods.
 *
 * @author Simon Wächter
 */
public class Pkcs11Utils {

    /**
     * UTC date formatter.
     */
    private static final DateTimeFormatter UTC_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    /**
     * Private constructor.
     */
    private Pkcs11Utils() {
        throw new RuntimeException("Invalid constructor call");
    }

    /**
     * Check if a string is null, empty or contains only whitespaces.
     *
     * @param value String to check
     * @return String is empty or not
     */
    public static boolean isEmptyString(String value) {
        // Check if the string is null or blank
        return value == null || value.isBlank();
    }

    /**
     * Check if a byte array is null, empty or contains only zero values.
     *
     * @param values Byte array to check
     * @return Byte array is empty or not
     */
    public static boolean isEmptyByteArray(byte[] values) {
        // Check if the array is null or empty
        if (values == null || values.length == 0) {
            return true;
        }

        // Check all values
        boolean allEmpty = true;
        for (byte value : values) {
            if (value != 0x0) {
                allEmpty = false;
                break;
            }
        }
        return allEmpty;
    }

    /**
     * Parse an optional date and return it. An empty string will return empty.
     *
     * @param utcTime Date as UTC string or an empty string
     * @return Optional parsed date or empty if string is empty
     * @throws Pkcs11Exception Thrown if the date is malformed
     */
    public static Optional<Instant> getDate(String utcTime) throws Pkcs11Exception {
        // Return empty if time is not present
        if (isEmptyString(utcTime) || isEmptyByteArray(utcTime.getBytes(StandardCharsets.US_ASCII))) {
            return Optional.empty();
        }

        // Ensure the utc time is 16 characters long
        if (utcTime.length() != 16) {
            throw new Pkcs11Exception("A UTC time has to be 16 characters long (YYYYMMDDhhmmssxx)");
        }

        // Remove the two reserved trailing characters
        utcTime = utcTime.substring(0, 14);

        // Parse the date
        LocalDateTime localDateTime = LocalDateTime.parse(utcTime, UTC_FORMATTER);
        return Optional.of(localDateTime.toInstant(ZoneOffset.UTC));
    }
}

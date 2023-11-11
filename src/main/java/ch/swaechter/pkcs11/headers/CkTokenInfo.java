package ch.swaechter.pkcs11.headers;

/**
 * Provide information about a token.
 *
 * @param label              Application-defined label, assigned during token initialization
 * @param manufacturerId     ID of the device manufacturer
 * @param model              Model of the device
 * @param serialNumber       Character-string serial number of the device
 * @param flags              Bit flags indicating capabilities and status of the device
 * @param maxSessionCount    Maximum number of sessions that can be opened with the token at one time by a single application
 * @param sessionCount       Number of sessions that this application currently has open with the token
 * @param maxRwSessionCount  Maximum number of read/write sessions that can be opened with the token at one time by a single application
 * @param rwSessionCount     Number of read/write sessions that this application currently has open with the token
 * @param maxPinLen          Maximum length in bytes of the PIN
 * @param minPinLen          Minimum length in bytes of the PIN
 * @param totalPublicMemory  The total amount of memory on the token in bytes in which public objects may be stored
 * @param freePublicMemory   The amount of free (unused) memory on the token in bytes for public objects
 * @param totalPrivateMemory The total amount of memory on the token in bytes in which private objects may be stored
 * @param freePrivateMemory  The amount of free (unused) memory on the token in bytes for private objects
 * @param hardwareVersion    Version number of hardware
 * @param firmwareVersion    Version number of firmware
 * @param utcTime            Current time as a character-string of length 16, represented in the format YYYYMMDDhhmmssxx (4 characters for the year;  2 characters each for the month, the day, the hour, the minute, and the second; and 2 additional reserved ‘0’ characters).  The value of this field only makes sense for tokens equipped with a clock, as indicated in the token information flag
 * @author Simon Wächter
 */
public record CkTokenInfo(

    String label,

    String manufacturerId,

    String model,

    String serialNumber,

    Long flags,

    Long maxSessionCount,

    Long sessionCount,

    Long maxRwSessionCount,

    Long rwSessionCount,

    Long maxPinLen,

    Long minPinLen,

    Long totalPublicMemory,

    Long freePublicMemory,

    Long totalPrivateMemory,

    Long freePrivateMemory,

    CkVersion hardwareVersion,

    CkVersion firmwareVersion,

    String utcTime
) {
}

package ch.swaechter.pkcs11.headers;

/**
 * Provide information about a slot.
 *
 * @param slotDescription Character-string description of the slot
 * @param manufacturerId  ID of the slot manufacturer.
 * @param flags           Bits flags that provide capabilities of the slot
 * @param hardwareVersion Version number of the slot’s hardware
 * @param firmwareVersion Version number of the slot’s firmware
 * @author Simon Wächter
 */
public record CkSlotInfo(

    String slotDescription,

    String manufacturerId,

    Long flags,

    CkVersion hardwareVersion,

    CkVersion firmwareVersion
) {
}

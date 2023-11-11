package ch.swaechter.pkcs11.headers;

/**
 * Provide general information about the cryptoki device.
 *
 * @param cryptokiVersion    Cryptoki interface version number, for compatibility with future revisions of this interface
 * @param manufacturerId     ID of the Cryptoki library manufacturer. Must be padded with the blank character (' '). Should ''not'' be null-terminated.
 * @param flags              Bit flags reserved for future versions. Must be zero for this version
 * @param libraryDescription Character-string description of the library. Must be padded with the blank character (' '). Should ''not'' be null-terminated.
 * @param libraryVersion     Cryptoki library version number
 * @author Simon Wächter
 */
public record CkInfo(

    CkVersion cryptokiVersion,

    String manufacturerId,

    Long flags,

    String libraryDescription,

    CkVersion libraryVersion
) {
}

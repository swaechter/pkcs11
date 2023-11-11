package ch.swaechter.pkcs11.headers;

/**
 * Provide general information about the cryptoki device.
 *
 * @param cryptokiVersion    Cryptoki interface version number, for compatibility with future revisions of this interface
 * @param manufacturerId     ID of the Cryptoki library manufacturer
 * @param flags              Bit flags reserved for future versions
 * @param libraryDescription Character-string description of the library
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

package ch.swaechter.pkcs11.library.headers;

/**
 * Describe the version of a cryptoki interface, a library, a hardware version etc.
 *
 * @param major Major version number (the integer portion of the version)
 * @param minor Minor version number (the hundredths portion of the version)
 * @author Simon Wächter
 */
public record CkVersion(

    byte major,

    byte minor
) {
}

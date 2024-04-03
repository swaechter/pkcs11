package ch.swaechter.pkcs11.library.objects;

/**
 * Object that represents a version of cryptoki, a firmware or hardware etc. A version contains a major and minor
 * number.
 *
 * @param major Major version number
 * @param minor Minor version number
 * @author Simon Wächter
 */
public record Pkcs11Version(

    byte major,

    byte minor
) {
}

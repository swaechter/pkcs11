package ch.swaechter.pkcs11.headers;

/**
 * Define an attribute with a value for a search template.
 *
 * @param type   Attribute type
 * @param pValue Optional attribute value
 * @author Simon Wächter
 */
public record CkAttributeValue(

    CkAttribute type,

    Integer pValue
) {
}

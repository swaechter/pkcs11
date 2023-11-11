package ch.swaechter.pkcs11.objects;

import ch.swaechter.pkcs11.headers.CkInfo;

/**
 * Object that provides information about the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class Pkcs11Info {

    /**
     * Internal CK_INFO struct.
     */
    private final CkInfo ckInfo;

    /**
     * Create a new PKCS11 info object.
     *
     * @param ckInfo Internal CK_INFO struct
     */
    public Pkcs11Info(CkInfo ckInfo) {
        this.ckInfo = ckInfo;
    }

    /**
     * Get the PKCS11 version that the PKCS11 middleware support.
     *
     * @return Cryptoki version
     */
    public Pkcs11Version getCryptokiVersion() {
        return new Pkcs11Version(ckInfo.cryptokiVersion().major(), ckInfo.cryptokiVersion().minor());
    }

    /**
     * Get the trimmed PKCS11 device manufacturer identification.
     *
     * @return Manufacturer identification
     */
    public String getManufacturerId() {
        return ckInfo.manufacturerId().trim();
    }

    /**
     * Get the flags reserved for future use.
     *
     * @return Reserved flags
     */
    public long getFlags() {
        return ckInfo.flags();
    }

    /**
     * Get the trimmed PKCS11 middleware library description.
     *
     * @return Library description
     */
    public String getLibraryDescription() {
        return ckInfo.libraryDescription().trim();
    }

    /**
     * Get the version of the PKCS11 middleware library.
     *
     * @return Library version
     */
    public Pkcs11Version getLibraryVersion() {
        return new Pkcs11Version(ckInfo.libraryVersion().major(), ckInfo.libraryVersion().minor());
    }
}

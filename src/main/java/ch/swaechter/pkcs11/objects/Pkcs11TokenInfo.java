package ch.swaechter.pkcs11.objects;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.Pkcs11Utils;
import ch.swaechter.pkcs11.headers.CkTokenInfo;
import ch.swaechter.pkcs11.headers.CkTokenInfoFlag;

import java.time.Instant;
import java.util.Optional;

/**
 * Object that provides the token info from the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class Pkcs11TokenInfo {

    /**
     * Internal CK_TOKEN_INFO struct.
     */
    private final CkTokenInfo ckTokenInfo;

    /**
     * Create a new PKCS11 token info object.
     *
     * @param ckTokenInfo Internal CK_TOKEN_INFO struct
     */
    public Pkcs11TokenInfo(CkTokenInfo ckTokenInfo) {
        this.ckTokenInfo = ckTokenInfo;
    }

    /**
     * Get the application-defined label, assigned during token initialization.
     *
     * @return Label
     */
    public String getLabel() {
        return ckTokenInfo.label().trim();
    }

    /**
     * Get the identifier of the slot manufacturer.
     *
     * @return Slot manufacturer
     */
    public String getManufacturerId() {
        return ckTokenInfo.manufacturerId().trim();
    }

    /**
     * Get the model of the device.
     *
     * @return Device model
     */
    public String getModel() {
        return ckTokenInfo.model().trim();
    }

    /**
     * Get the character-string serial number of the device.
     *
     * @return Serial number
     */
    public String getSerialNumber() {
        return ckTokenInfo.serialNumber().trim();
    }

    /**
     * Get the bit flags indicating capabilities and status of the device.
     *
     * @return Bit flags
     */
    public long getFlags() {
        return ckTokenInfo.flags();
    }

    /**
     * Get the maximum number of sessions that can be opened with the token at one time by a single application.
     *
     * @return Maximum session number
     */
    public long getMaxSessionCount() {
        return ckTokenInfo.maxSessionCount();
    }

    /**
     * Get the number of sessions that this application currently has open with the token.
     *
     * @return Current session count
     */
    public long getSessionCount() {
        return ckTokenInfo.sessionCount();
    }

    /**
     * Get the maximum number of read/write sessions that can be opened with the token at one time by a single application.
     *
     * @return Maximum read/write session number
     */
    public long getMaxRwSessionCount() {
        return ckTokenInfo.maxRwSessionCount();
    }

    /**
     * Get the number of read/write sessions that this application currently has open with the token.
     *
     * @return Current read/write session count
     */
    public long getRwSessionCount() {
        return ckTokenInfo.rwSessionCount();
    }

    /**
     * Get the maximum length in bytes of the PIN.
     *
     * @return Maximum PIN length
     */
    public long getMaxPinLen() {
        return ckTokenInfo.maxPinLen();
    }

    /**
     * Get the minimum length in bytes of the PIN.
     *
     * @return Minimum PIN length
     */
    public long getMinPinLen() {
        return ckTokenInfo.minPinLen();
    }

    /**
     * Get the total amount of memory on the token in bytes in which public objects may be stored.
     *
     * @return Total public memory
     */
    public long getTotalPublicMemory() {
        return ckTokenInfo.totalPublicMemory();
    }

    /**
     * Get the amount of free (unused) memory on the token in bytes for public objects.
     *
     * @return Free public memory
     */
    public long getFreePublicMemory() {
        return ckTokenInfo.freePublicMemory();
    }

    /**
     * Get the total amount of memory on the token in bytes in which private objects may be stored.
     *
     * @return Total private memory
     */
    public long getTotalPrivateMemory() {
        return ckTokenInfo.totalPrivateMemory();
    }

    /**
     * Get the amount of free (unused) memory on the token in bytes for private objects.
     *
     * @return Free private memory
     */
    public long getFreePrivateMemory() {
        return ckTokenInfo.freePrivateMemory();
    }

    /**
     * Get the version number of the hardware.
     *
     * @return Hardware version number
     */
    public Pkcs11Version getHardwareVersion() {
        return new Pkcs11Version(ckTokenInfo.hardwareVersion().major(), ckTokenInfo.hardwareVersion().minor());
    }

    /**
     * Get the version number of the firmware.
     *
     * @return Firmware version number
     */
    public Pkcs11Version getFirmwareVersion() {
        return new Pkcs11Version(ckTokenInfo.firmwareVersion().major(), ckTokenInfo.firmwareVersion().minor());
    }

    /**
     * Get the current time if the device has a clock.
     *
     * @return Current time if available
     * @throws Pkcs11Exception Thrown if a time is present but can't be parsed
     */
    public Optional<Instant> getUtcDate() throws Pkcs11Exception {
        return Pkcs11Utils.getDate(ckTokenInfo.utcTime());
    }

    /**
     * Check if the token has its own random number generator.
     *
     * @return Token has an RNG or not
     */
    public boolean hasRng() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_RNG.value) != 0L;
    }

    /**
     * Check if the token is write-protected.
     *
     * @return Token is write-protected or not
     */
    public boolean isWriteProtected() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_WRITE_PROTECTED.value) != 0L;
    }

    /**
     * Check if the token requires a login to execute some other PKCS11 calls.
     *
     * @return Token requires a login or not
     */
    public boolean isLoginRequired() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_LOGIN_REQUIRED.value) != 0L;
    }

    /**
     * Check if the user PIN is initialized.
     *
     * @return User PIN is initialized or not
     */
    public boolean isUserPinInitialized() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_USER_PIN_INITIALIZED.value) != 0L;
    }

    /**
     * Check if a saved session via C_GetOperationState contains all used keys, and thus they don't have to be specified
     * when restoring the session via C_SetOperationState.
     *
     * @return Saved session contains all keys or not
     */
    public boolean isRestoreKeyNotNeeded() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_RESTORE_KEY_NOT_NEEDED.value) != 0L;
    }

    /**
     * Check if the token has an own clock.
     *
     * @return Token has an own clock or not
     */
    public boolean hasClock() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_CLOCK_ON_TOKEN.value) != 0L;
    }

    /**
     * Check if the token has a protected authentication path, e.g. a PIN pad. If true, a user may log in without PIN
     * while using this mechanism.
     *
     * @return Token has a protected authentication path or not
     */
    public boolean hasProtectedAuthenticationPath() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_PROTECTED_AUTHENTICATION_PATH.value) != 0L;
    }

    /**
     * Check if the token supports dual-cryptographic functions to prevent an additional function call.
     *
     * @return Token has dual-cryptographic functions
     */
    public boolean hasDualCryptoOperations() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_DUAL_CRYPTO_OPERATIONS.value) != 0L;
    }

    /**
     * Check if the token is initialized.
     *
     * @return Token is initialized or not
     */
    public boolean isTokenInitialized() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_TOKEN_INITIALIZED.value) != 0L;
    }

    /**
     * Check if the token supports secondary authentication for private key objects. This flag is deprecated.
     *
     * @return Token supports secondary authentication or not
     */
    public boolean hasSecondaryAuthentication() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_SECONDARY_AUTHENTICATION.value) != 0L;
    }

    /**
     * Check if an incorrect user PIN has been entered at least one since the last successful authentication.
     *
     * @return User has entered at least one wrong user PIN or not
     */
    public boolean isUserPinCountLow() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_USER_PIN_COUNT_LOW.value) != 0L;
    }

    /**
     * Check if supplying another incorrect user PIN will cause it to become locked.
     *
     * @return Token will be locked with the next incorrect user PIN
     */
    public boolean isUserPinFinalTry() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_USER_PIN_FINAL_TRY.value) != 0L;
    }

    /**
     * Check if the user PIN has been locked. User login to the token is not possible.
     *
     * @return User PIN is locked or not
     */
    public boolean isUserPinLocked() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_USER_PIN_LOCKED.value) != 0L;
    }

    /**
     * Check if the user PIN value is the default value set by token initialization or manufacturing, or the PIN has been expired by the card.
     *
     * @return User PIN needs to be changed or not
     */
    public boolean isUserPinToBeChanged() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_USER_PIN_TO_BE_CHANGED.value) != 0L;
    }

    /**
     * Check if an incorrect SO login PIN has been entered at least once since the last successful authentication.
     *
     * @return User has entered at least one wrong SO PIN or not
     */
    public boolean isSoPinCountLow() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_SO_PIN_COUNT_LOW.value) != 0L;
    }

    /**
     * Check if supplying another incorrect SO PIN will cause it to become locked.
     *
     * @return Token will be locked with the next incorrect user PIN
     */
    public boolean isSoPinFinalTry() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_SO_PIN_FINAL_TRY.value) != 0L;
    }

    /**
     * Check if the SO PIN has been locked. SO login to the token is not possible.
     *
     * @return SO PIN is locked or not
     */
    public boolean isSoPinLocked() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_SO_PIN_LOCKED.value) != 0L;
    }

    /**
     * Check if the SO PIN value is the default value set by token initialization or manufacturing, or the PIN has been expired by the card.
     *
     * @return SO PIN needs to be changed or not
     */
    public boolean isSoPinToBeChanged() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_SO_PIN_TO_BE_CHANGED.value) != 0L;
    }

    /**
     * Check if the token failed a FIPS 140-2 self-test and entered an error state.
     *
     * @return Token failed a self test or not
     */
    public boolean isInErrorState() {
        return (ckTokenInfo.flags() & CkTokenInfoFlag.CKF_ERROR_STATE.value) != 0L;
    }
}

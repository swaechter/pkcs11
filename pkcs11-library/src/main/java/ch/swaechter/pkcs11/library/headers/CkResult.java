package ch.swaechter.pkcs11.library.headers;

/**
 * Describes the result of a PKCS11 operation.
 *
 * @author Simon Wächter
 */
public enum CkResult {

    CKR_OK(0x00000000, "The function executed successfully."),
    CKR_CANCEL(0x00000001, "When a function executing in serial with an application decides to give the application a chance to do some work, it calls an application-supplied function with a `CKN_SURRENDER` callback. If the callback returns the value `CKR_CANCEL`, then the function aborts and returns `CKR_FUNCTION_CANCELED`."),
    CKR_HOST_MEMORY(0x00000002, "The computer that the Cryptoki library is running on has insufficient memory to perform the requested function."),
    CKR_SLOT_ID_INVALID(0x00000003, "The specified slot ID is not valid."),
    CKR_GENERAL_ERROR(0x00000005, "Some horrible, unrecoverable error has occurred. In the worst case, it is possible that the function only partially succeeded, and that the computer and/or token is in an inconsistent state."),
    CKR_FUNCTION_FAILED(0x00000006, "The requested function could not be performed, but detailed information about why not is not available in this error return. If the failed function uses a session, it is possible that the `CK_SESSION_INFO` structure that can be obtained by calling `C_GetSessionInfo` will hold useful information about what happened in its `ulDeviceError` field. In any event, although the function call failed, the situation is not necessarily totally hopeless, as it is likely to be when `CKR_GENERAL_ERROR` is returned. Depending on what the root cause of the error actually was, it is possible that an attempt to make the exact same function call again would succeed."),
    CKR_ARGUMENTS_BAD(0x00000007, "This is a rather generic error code which indicates that the arguments supplied to the Cryptoki function were in some way not appropriate."),
    CKR_NO_EVENT(0x00000008, "This value can only be returned by `C_GetSlotEvent`. It is returned when `C_GetSlotEvent` is called in non-blocking mode and there are no new slot events to return."),
    CKR_NEED_TO_CREATE_THREADS(0x00000009, "This value can only be returned by `C_Initialize`"),
    CKR_CANT_LOCK(0x0000000A, "This value can only be returned by `C_Initialize`. It means that the type of locking requested by the application for thread-safety is not available in this library, and so the application cannot make use of this library in the specified fashion."),
    CKR_ATTRIBUTE_READ_ONLY(0x00000010, "An attempt was made to set a value for an attribute which may not be set by the application, or which may not be modified by the application."),
    CKR_ATTRIBUTE_SENSITIVE(0x00000011, "An attempt was made to obtain the value of an attribute of an object which cannot be satisfied because the object is either sensitive or unextractable."),
    CKR_ATTRIBUTE_TYPE_INVALID(0x00000012, "An invalid attribute type was specified in a template."),
    CKR_ATTRIBUTE_VALUE_INVALID(0x00000013, "An invalid value was specified for a particular attribute in a template. See Section 10.1 for more information."),
    CKR_DATA_INVALID(0x00000020, "The plaintext input data to a cryptographic operation is invalid. This return value has lower priority than `CKR_DATA_LEN_RANGE`."),
    CKR_DATA_LEN_RANGE(0x00000021, "The plaintext input data to a cryptographic operation has a bad length. Depending on the operation's mechanism, this could mean that the plaintext data is too short, too long, or is not a multiple of some particular blocksize. This return value has higher priority than `CKR_DATA_INVALID`."),
    CKR_DEVICE_ERROR(0x00000030, "Some problem has occurred with the token and/or slot. This error code can be returned by more than just the functions mentioned above; in particular, it is possible for `C_GetSlotInfo` to return `CKR_DEVICE_ERROR`."),
    CKR_DEVICE_MEMORY(0x00000031, "The token does not have sufficient memory to perform the requested function."),
    CKR_DEVICE_REMOVED(0x00000032, "The token was removed from its slot `during the execution of the function`"),
    CKR_ENCRYPTED_DATA_INVALID(0x00000040, "The encrypted input to a decryption operation has been determined to be invalid ciphertext. This return value has lower priority than `CKR_ENCRYPTED_DATA_LEN_RANGE`."),
    CKR_ENCRYPTED_DATA_LEN_RANGE(0x00000041, "The ciphertext input to a decryption operation has been determined to be invalid ciphertext solely on the basis of its length. Depending on the operation's mechanism, this could mean that the ciphertext is too short, too long, or is not a multiple of some particular blocksize. This return value has higher priority than `CKR_ENCRYPTED_DATA_INVALID`."),
    CKR_FUNCTION_CANCELED(0x00000050, "The function was canceled in mid-execution. This happens to a cryptographic function if the function makes a `CKN_SURRENDER` application callback which returns `CKR_CANCEL` (see `CKR_CANCEL`). It also happens to a function that performs PIN entry through a protected path. The method used to cancel a protected path PIN entry operation is device dependent."),
    CKR_FUNCTION_NOT_PARALLEL(0x00000051, "There is currently no function executing in parallel in the specified session. This is a legacy error code which is only returned by the legacy functions `C_GetFunctionStatus` and `C_CancelFunction`."),
    CKR_FUNCTION_NOT_SUPPORTED(0x00000054, "The requested function is not supported by this Cryptoki library. Even unsupported functions in the Cryptoki API should have a 'stub' in the library; this stub should simply return the value `CKR_FUNCTION_NOT_SUPPORTED`."),
    CKR_KEY_HANDLE_INVALID(0x00000060, "The specified key handle is not valid. It may be the case that the specified handle is a valid handle for an object which is not a key. We reiterate here that 0 is never a valid key handle."),
    CKR_KEY_SIZE_RANGE(0x00000062, "Although the requested keyed cryptographic operation could in principle be carried out, this Cryptoki library (or the token) is unable to actually do it because the supplied key's size is outside the range of key sizes that it can handle."),
    CKR_KEY_TYPE_INCONSISTENT(0x00000063, "The specified key is not the correct type of key to use with the specified mechanism. This return value has a higher priority than `CKR_KEY_FUNCTION_NOT_PERMITTED`."),
    CKR_KEY_NOT_NEEDED(0x00000064, "An extraneous key was supplied to `C_SetOperationState`. For example, an attempt was made to restore a session that had been performing a message digesting operation, and an encryption key was supplied."),
    CKR_KEY_CHANGED(0x00000065, "This value is only returned by `C_SetOperationState`. It indicates that one of the keys specified is not the same key that was being used in the original saved session."),
    CKR_KEY_NEEDED(0x00000066, "This value is only returned by `C_SetOperationState`. It indicates that the session state cannot be restored because `C_SetOperationState` needs to be supplied with one or more keys that were being used in the original saved session."),
    CKR_KEY_INDIGESTIBLE(0x00000067, "This error code can only be returned by `C_DigestKey`. It indicates that the value of the specified key cannot be digested for some reason (perhaps the key isn't a secret key, or perhaps the token simply can't digest this kind of key)."),
    CKR_KEY_FUNCTION_NOT_PERMITTED(0x00000068, "An attempt has been made to use a key for a cryptographic purpose that the key's attributes are not set to allow it to do. For example, to use a key for performing encryption, that key must have its `CKA_ENCRYPT` attribute set to `CK_TRUE` (the fact that the key must have a `CKA_ENCRYPT` attribute implies that the key cannot be a private key). This return value has lower priority than `CKR_KEY_TYPE_INCONSISTENT`."),
    CKR_KEY_NOT_WRAPPABLE(0x00000069, "Although the specified private or secret key does not have its `CKA_EXTRACTABLE` attribute set to `CK_FALSE`, Cryptoki (or the token) is unable to wrap the key as requested (possibly the token can only wrap a given key with certain types of keys, and the wrapping key specified is not one of these types). Compare with `CKR_KEY_UNEXTRACTABLE`."),
    CKR_KEY_UNEXTRACTABLE(0x0000006A, "The specified private or secret key can't be wrapped because its `CKA_EXTRACTABLE` attribute is set to `CK_FALSE`. Compare with `CKR_KEY_NOT_WRAPPABLE`."),
    CKR_MECHANISM_INVALID(0x00000070, "An invalid mechanism was specified to the cryptographic operation. This error code is an appropriate return value if an unknown mechanism was specified or if the mechanism specified cannot be used in the selected token with the selected function."),
    CKR_MECHANISM_PARAM_INVALID(0x00000071, "Invalid parameters were supplied to the mechanism specified to the cryptographic operation. Which parameter values are supported by a given mechanism can vary from token to token."),
    CKR_OBJECT_HANDLE_INVALID(0x00000082, "The specified object handle is not valid. We reiterate here that 0 is never a valid object handle."),
    CKR_OPERATION_ACTIVE(0x00000090, "There is already an active operation (or combination of active operations) which prevents Cryptoki from activating the specified operation."),
    CKR_OPERATION_NOT_INITIALIZED(0x00000091, "There is no active operation of an appropriate type in the specified session. For example, an application cannot call `C_Encrypt` in a session without having called `C_EncryptInit` first to activate an encryption operation."),
    CKR_PIN_INCORRECT(0x000000A0, "The specified PIN is incorrect, i.e., does not match the PIN stored on the token. More generally-- when authentication to the token involves something other than a PIN-- the attempt to authenticate the user has failed."),
    CKR_PIN_INVALID(0x000000A1, "The specified PIN has invalid characters in it. This return code only applies to functions which attempt to set a PIN."),
    CKR_PIN_LEN_RANGE(0x000000A2, "The specified PIN is too long or too short. This return code only applies to functions which attempt to set a PIN."),
    CKR_PIN_EXPIRED(0x000000A3, "The specified PIN has expired, and the requested operation cannot be carried out unless `C_SetPIN` is called to change the PIN value. Whether or not the normal user's PIN on a token ever expires varies from token to token."),
    CKR_PIN_LOCKED(0x000000A4, "The specified PIN is 'locked', and cannot be used. That is, because some particular number of failed authentication attempts has been reached, the token is unwilling to permit further attempts at authentication. Depending on the token, the specified PIN may or may not remain locked indefinitely."),
    CKR_SESSION_CLOSED(0x000000B0, "The session was closed `during the execution of the function`. Note that, as stated in Section 6.7.6, the behavior of Cryptoki is `undefined` if multiple threads of an application attempt to access a common Cryptoki session simultaneously. Therefore, there is actually no guarantee that a function invocation could ever return the value `CKR_SESSION_CLOSED`if one thread is using a session when another thread closes that session, that is an instance of multiple threads accessing a common session simultaneously."),
    CKR_SESSION_COUNT(0x000000B1, "This value can only be returned by `C_OpenSession`. It indicates that the attempt to open a session failed, either because the token has too many sessions already open, or because the token has too many read/write sessions already open."),
    CKR_SESSION_HANDLE_INVALID(0x000000B3, "The specified session handle was invalid `at the time that the function was invoked`. Note that this can happen if the session's token is removed before the function invocation, since removing a token closes all sessions with it."),
    CKR_SESSION_PARALLEL_NOT_SUPPORTED(0x000000B4, "The specified token does not support parallel sessions. This is a legacy error code in Cryptoki Version 2.01 and up, `no` token supports parallel sessions. `CKR_SESSION_PARALLEL_NOT_SUPPORTED` can only be returned by `C_OpenSession`, and it is only returned when `C_OpenSession` is called in a particular [deprecated] way."),
    CKR_SESSION_READ_ONLY(0x000000B5, "The specified session was unable to accomplish the desired action because it is a read-only session. This return value has lower priority than `CKR_TOKEN_WRITE_PROTECTED`."),
    CKR_SESSION_EXISTS(0x000000B6, "This value can only be returned by `C_InitToken`. It indicates that a session with the token is already open, and so the token cannot be initialized."),
    CKR_SESSION_READ_ONLY_EXISTS(0x000000B7, "A read-only session already exists, and so the SO cannot be logged in."),
    CKR_SESSION_READ_WRITE_SO_EXISTS(0x000000B8, "A read/write SO session already exists, and so a read-only session cannot be opened."),
    CKR_SIGNATURE_INVALID(0x000000C0, "The provided signature/MAC is invalid. This return value has lower priority than `CKR_SIGNATURE_LEN_RANGE`."),
    CKR_SIGNATURE_LEN_RANGE(0x000000C1, "The provided signature/MAC can be seen to be invalid solely on the basis of its length. This return value has higher priority than `CKR_SIGNATURE_INVALID`."),
    CKR_TEMPLATE_INCOMPLETE(0x000000D0, "The template specified for creating an object is incomplete, and lacks some necessary attributes."),
    CKR_TEMPLATE_INCONSISTENT(0x000000D1, "The template specified for creating an object has conflicting attributes."),
    CKR_TOKEN_NOT_PRESENT(0x000000E0, "The token was not present in its slot `at the time that the function was invoked`."),
    CKR_TOKEN_NOT_RECOGNIZED(0x000000E1, "The Cryptoki library and/or slot does not recognize the token in the slot."),
    CKR_TOKEN_WRITE_PROTECTED(0x000000E2, "The requested action could not be performed because the token is write-protected. This return value has higher priority than CKR_SESSION_READ_ONLY."),
    CKR_UNWRAPPING_KEY_HANDLE_INVALID(0x000000F0, "This value can only be returned by `C_UnwrapKey`. It indicates that the key handle specified to be used to unwrap another key is not valid."),
    CKR_UNWRAPPING_KEY_SIZE_RANGE(0x000000F1, "This value can only be returned by `C_UnwrapKey`. It indicates that although the requested unwrapping operation could in principle be carried out, this Cryptoki library (or the token) is unable to actually do it because the supplied key's size is outside the range of key sizes that it can handle."),
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT(0x000000F2, "This value can only be returned by `C_UnwrapKey`. It indicates that the type of the key specified to unwrap another key is not consistent with the mechanism specified for unwrapping."),
    CKR_USER_ALREADY_LOGGED_IN(0x00000100, "This value can only be returned by `C_Login`. It indicates that the specified user cannot be logged into the session, because it is already logged into the session. For example, if an application has an open SO session, and it attempts to log the SO into it, it will receive this error code."),
    CKR_USER_NOT_LOGGED_IN(0x00000101, "The desired action cannot be performed because the appropriate user (or ''an'' appropriate user) is not logged in. One example is that a session cannot be logged out unless it is logged in. Another example is that a private object cannot be created on a token unless the session attempting to create it is logged in as the normal user. A final example is that cryptographic operations on certain tokens cannot be performed unless the normal user is logged in."),
    CKR_USER_PIN_NOT_INITIALIZED(0x00000102, "This value can only be returned by `C_Login`. It indicates that the normal user's PIN has not yet been initialized with `C_InitPIN`."),
    CKR_USER_TYPE_INVALID(0x00000103, "An invalid value was specified as a `CK_USER_TYPE`. Valid types are `CKU_SO`, `CKU_USER`, and `CKU_CONTEXT_SPECIFIC`."),
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN(0x00000104, "This value can only be returned by `C_Login`. It indicates that the specified user cannot be logged into the session, because another user is already logged into the session. For example, if an application has an open SO session, and it attempts to log the normal user into it, it will receive this error code."),
    CKR_USER_TOO_MANY_TYPES(0x00000105, "An attempt was made to have more distinct users simultaneously logged into the token than the token and/or library permits. For example, if some application has an open SO session, and another application attempts to log the normal user into a session, the attempt may return this error. It is not required to, however. Only if the simultaneous distinct users cannot be supported does `C_Login` have to return this value. Note that this error code generalizes to true multi-user tokens."),
    CKR_WRAPPED_KEY_INVALID(0x00000110, "This value can only be returned by `C_UnwrapKey`. It indicates that the provided wrapped key is not valid. If a call is made to `C_UnwrapKey` to unwrap a particular type of key (i.e., some particular key type is specified in the template provided to `C_UnwrapKey`), and the wrapped key provided to `C_UnwrapKey` is recognizably not a wrapped key of the proper type, then `C_UnwrapKey` should return `CKR_WRAPPED_KEY_INVALID`. This return value has lower priority than `CKR_WRAPPED_KEY_LEN_RANGE`."),
    CKR_WRAPPED_KEY_LEN_RANGE(0x00000112, "This value can only be returned by `C_UnwrapKey`. It indicates that the provided wrapped key can be seen to be invalid solely on the basis of its length. This return value has higher priority than `CKR_WRAPPED_KEY_INVALID`."),
    CKR_WRAPPING_KEY_HANDLE_INVALID(0x00000113, "This value can only be returned by `C_WrapKey`. It indicates that the key handle specified to be used to wrap another key is not valid."),
    CKR_WRAPPING_KEY_SIZE_RANGE(0x00000114, "This value can only be returned by `C_WrapKey`. It indicates that although the requested wrapping operation could in principle be carried out, this Cryptoki library (or the token) is unable to actually do it because the supplied wrapping key's size is outside the range of key sizes that it can handle."),
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT(0x00000115, "This value can only be returned by `C_WrapKey`. It indicates that the type of the key specified to wrap another key is not consistent with the mechanism specified for wrapping."),
    CKR_RANDOM_SEED_NOT_SUPPORTED(0x00000120, "This value can only be returned by `C_SeedRandom`. It indicates that the token's random number generator does not accept seeding from an application. This return value has lower priority than `CKR_RANDOM_NO_RNG`."),
    CKR_RANDOM_NO_RNG(0x00000121, "This value can be returned by `C_SeedRandom` and `C_GenerateRandom`. It indicates that the specified token doesn't have a random number generator. This return value has higher priority than `CKR_RANDOM_SEED_NOT_SUPPORTED`."),
    CKR_DOMAIN_PARAMS_INVALID(0x00000130, "Invalid or unsupported domain parameters were supplied to the function. Which representation methods of domain parameters are supported by a given mechanism can vary from token to token."),
    CKR_BUFFER_TOO_SMALL(0x00000150, "The output of the function is too large to fit in the supplied buffer."),
    CKR_SAVED_STATE_INVALID(0x00000160, "This value can only be returned by `C_SetOperationState`. It indicates that the supplied saved cryptographic operations state is invalid, and so it cannot be restored to the specified session."),
    CKR_INFORMATION_SENSITIVE(0x00000170, "The information requested could not be obtained because the token considers it sensitive, and is not able or willing to reveal it."),
    CKR_STATE_UNSAVEABLE(0x00000180, "The cryptographic operations state of the specified session cannot be saved for some reason (possibly the token is simply unable to save the current state). This return value has lower priority than `CKR_OPERATION_NOT_INITIALIZED`."),
    CKR_CRYPTOKI_NOT_INITIALIZED(0x00000190, "This value can be returned by any function other than `C_Initialize` and `C_GetFunctionList`. It indicates that the function cannot be executed because the Cryptoki library has not yet been initialized by a call to `C_Initialize`."),
    CKR_CRYPTOKI_ALREADY_INITIALIZED(0x00000191, "This value can only be returned by `C_Initialize`. It means that the Cryptoki library has already been initialized (by a previous call to `C_Initialize` which did not have a matching `C_Finalize` call)."),
    CKR_MUTEX_BAD(0x000001A0, "This error code can be returned by mutex-handling functions who are passed a bad mutex object as an argument. Unfortunately, it is possible for such a function not to recognize a bad mutex object. There is therefore no guarantee that such a function will successfully detect bad mutex objects and return this value."),
    CKR_MUTEX_NOT_LOCKED(0x000001A1, "This error code can be returned by mutex-unlocking functions. It indicates that the mutex supplied to the mutex-unlocking function was not locked."),
    CKR_NEW_PIN_MODE(0x000001B0, "The supplied OTP was not accepted and the library requests a new OTP computed using a new PIN. The new PIN is set through means out of scope for this document."),
    CKR_NEXT_OTP(0x000001B1, "The supplied OTP was correct but indicated a larger than normal drift in the token's internal state (e.g. clock, counter). To ensure this was not due to a temporary problem, the application should provide the next one-time password to the library for verification."),
    CKR_EXCEEDED_MAX_ITERATIONS(0x000001B5, "An iterative algorithm (for key pair generation, domain parameter generation etc.) failed because we have exceeded the maximum number of iterations. This error code has precedence over `CKR_FUNCTION_FAILED`. Examples of iterative algorithms include DSA signature generation (retry if either r = 0 or s = 0) and generation of DSA primes p and q specified in FIPS 186-2."),
    CKR_FIPS_SELF_TEST_FAILED(0x000001B6, "A FIPS 140-2 power-up self-test or conditional self-test failed. The token entered an error state. Future calls to cryptographic functions on the token will return `CKR_GENERAL_ERROR`. `CKR_FIPS_SELF_TEST_FAILED` has a higher precedence over `CKR_GENERAL_ERROR`. This error may be returned by `C_Initialize`, if a power-up self-test failed, by `C_GenerateRandom` or `C_SeedRandom`, if the continuous random number generator test failed, or by `C_GenerateKeyPair`, if the pair-wise consistency test failed."),
    CKR_LIBRARY_LOAD_FAILED(0x000001B7, "The Cryptoki library could not load a dependent shared library."),
    CKR_PIN_TOO_WEAK(0x000001B8, "The specified PIN is too weak so that it could be easy to guess. If the PIN is too short, `CKR_PIN_LEN_RANGE` should be returned instead. This return code only applies to functions which attempt to set a PIN."),
    CKR_PUBLIC_KEY_INVALID(0x000001B9, "The public key fails a public key validation."),
    CKR_FUNCTION_REJECTED(0x00000200, "The signature request is rejected by the user."),
    CKR_VENDOR_DEFINED(0x80000000, "Vendor defined results.");

    /**
     * Code of the result.
     */
    public final int value;

    /**
     * Message of the result. Mapped by the GitHub wiki.
     */
    public final String message;

    /**
     * Define a new result type.
     *
     * @param value   Code of the result
     * @param message Message of the result
     */
    CkResult(int value, String message) {
        this.value = value;
        this.message = message;
    }

    /**
     * Get the enum by value.
     *
     * @param value Value of the enum
     * @return Matching enum
     */
    public static CkResult valueOf(int value) {
        for (CkResult ckResult : values()) {
            if (ckResult.value == value) {
                return ckResult;
            }
        }
        return null;
    }
}

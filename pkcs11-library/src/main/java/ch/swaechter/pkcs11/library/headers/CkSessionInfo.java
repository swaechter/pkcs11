package ch.swaechter.pkcs11.library.headers;

/**
 * Describe the state of a session.
 *
 * @param slotId      ID of the slot that interfaces with the token
 * @param state       The state of the session
 * @param flags       The bit flags that define the type of session
 * @param deviceError An error code defined by the cryptographic device. Used for errors not covered by Cryptoki
 * @author Simon Wächter
 */
public record CkSessionInfo(

    Long slotId,

    CkSessionState state,

    Long flags,

    Long deviceError
) {
}

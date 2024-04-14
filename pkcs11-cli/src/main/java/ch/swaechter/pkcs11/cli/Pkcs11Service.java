package ch.swaechter.pkcs11.cli;

import ch.swaechter.pkcs11.library.Pkcs11Exception;
import ch.swaechter.pkcs11.library.Pkcs11Module;
import ch.swaechter.pkcs11.library.headers.CkUserType;
import ch.swaechter.pkcs11.library.objects.Pkcs11Session;
import ch.swaechter.pkcs11.library.objects.Pkcs11Slot;
import ch.swaechter.pkcs11.library.objects.Pkcs11Token;
import ch.swaechter.pkcs11.library.objects.Pkcs11TokenInfo;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

public class Pkcs11Service implements AutoCloseable {

    private final Pkcs11Module pkcs11Module;

    public Pkcs11Service(String libraryName) throws Pkcs11Exception {
        this.pkcs11Module = new Pkcs11Module(libraryName);
        this.pkcs11Module.initializeModule();
    }

    public List<Pkcs11Slot> getSlots() throws Pkcs11Exception {
        return pkcs11Module.getSlots(true);
    }

    private Pkcs11Slot getPkcs11Slot(long slotId) throws Pkcs11Exception {
        // Get all available slots and find the slot by ID
        List<Pkcs11Slot> pkcs11Slots = getSlots();
        Optional<Pkcs11Slot> optionalPkcs11SlotById = pkcs11Slots.stream().filter(pkcs11SlotElement -> pkcs11SlotElement.getSlotId() == slotId).findFirst();
        if (optionalPkcs11SlotById.isEmpty()) {
            throw new Pkcs11Exception(STR."Unable to find a slot with ID \{slotId}");
        }
        return optionalPkcs11SlotById.get();
    }

    public boolean isPinLocked(long slotId) throws Pkcs11Exception {
        // Get the slot
        Pkcs11Slot pkcs11Slot = getPkcs11Slot(slotId);

        // Check if the user PIN is locked
        Pkcs11TokenInfo pkcs11TokenInfo = pkcs11Slot.getToken().getTokenInfo();
        return pkcs11TokenInfo.isUserPinLocked();
    }

    public boolean isSoPinLocked(long slotId) throws Pkcs11Exception {
        // Get the slot
        Pkcs11Slot pkcs11Slot = getPkcs11Slot(slotId);

        // Check if the user PIN is locked
        Pkcs11TokenInfo pkcs11TokenInfo = pkcs11Slot.getToken().getTokenInfo();
        return pkcs11TokenInfo.isSoPinLocked();
    }

    public boolean login(long slotId, String pin) throws Pkcs11Exception {
        // Get the slot and token
        Pkcs11Slot pkcs11Slot = getPkcs11Slot(slotId);
        Pkcs11Token pkcs11Token = pkcs11Slot.getToken();

        // Open a session and try to log in
        try (Pkcs11Session pkcs11Session = pkcs11Token.openSession(true, true)) {
            // Login and print success
            pkcs11Session.loginUser(CkUserType.CKU_USER, pin);
            return true;
        } catch (Exception exception) {
            return false;
        }
    }

    public void changePin(long slotId, String currentPin, String newPin) throws Pkcs11Exception {
        // Get the slot and token
        Pkcs11Slot pkcs11Slot = getPkcs11Slot(slotId);
        Pkcs11Token pkcs11Token = pkcs11Slot.getToken();

        // Open a session and try to log in
        try (Pkcs11Session pkcs11Session = pkcs11Token.openSession(true, true)) {
            // Login
            pkcs11Session.loginUser(CkUserType.CKU_USER, currentPin);

            // Change the PIN
            pkcs11Session.changePin(currentPin, newPin);
        } catch (IOException exception) {
            throw new Pkcs11Exception(STR."Unable to login: \{exception.getMessage()}", exception);
        }
    }

    public void unlock(long slotId, String soPin, String newPin) throws Pkcs11Exception {
        // Get the slot and token
        Pkcs11Slot pkcs11Slot = getPkcs11Slot(slotId);
        Pkcs11Token pkcs11Token = pkcs11Slot.getToken();

        // Open a session and try to log in
        try (Pkcs11Session pkcs11Session = pkcs11Token.openSession(true, true)) {
            // Login
            pkcs11Session.loginUser(CkUserType.CKU_SO, soPin);

            // Init the PIN
            pkcs11Session.initPin(newPin);
        } catch (IOException exception) {
            throw new Pkcs11Exception(STR."Unable to unlock: \{exception.getMessage()}", exception);
        }
    }

    @Override
    public void close() throws Exception {
        pkcs11Module.finalizeModule();
    }
}

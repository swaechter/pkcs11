package ch.swaechter.pkcs11.cli;

import ch.swaechter.pkcs11.library.Pkcs11Library;
import ch.swaechter.pkcs11.library.objects.Pkcs11Slot;

import java.io.File;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

public class Pkcs11Application {

    public static void main(String[] arguments) {
        try {
            handleCommand(arguments);
        } catch (Exception exception) {
            System.err.println("An error occurred: " + exception.getMessage());
            System.exit(1);
        }
    }

    private static void handleCommand(String[] arguments) throws Exception {
        // Ensure there is a command
        if (arguments.length == 0) {
            handleHelp();
            return;
        }

        // Get the command and parameters
        String command = arguments[0];
        String[] parameters = Arrays.copyOfRange(arguments, 1, arguments.length);

        // Handle the commands
        if (command.equals("--help")) {
            handleHelp();
        } else if (command.equals("--version")) {
            handleVersion();
        } else {
            // Get the library name
            String libraryName = getLibraryName();

            // Create the PKCS11 module
            try (Pkcs11Service pkcs11Service = new Pkcs11Service(libraryName)) {
                switch (command) {
                    case "--list-slots" -> handleListSlots(pkcs11Service);
                    case "--is-locked" -> handleIsLocked(pkcs11Service, parameters);
                    case "--is-so-locked" -> handleIsSoLocked(pkcs11Service, parameters);
                    case "--login" -> handleLogin(pkcs11Service, parameters);
                    case "--change-pin" -> handleChangePin(pkcs11Service, parameters);
                    case "--unlock" -> handleUnlock(pkcs11Service, parameters);
                    case "--list-certificates" -> handleListCertificates(pkcs11Service, parameters);
                    case "--sign-pdf" -> handleSignPdf(pkcs11Service, parameters);
                    case "--verify-pdf" -> handleVerifyPdf(pkcs11Service, parameters);
                    default -> handleHelp();
                }
            }
        }
    }

    private static String getLibraryName() {
        String libraryName = System.getenv("JAVA_CRYPTOKI_NAME");
        return libraryName == null || libraryName.isBlank() ? "cryptoki" : libraryName;
    }

    private static void handleListSlots(Pkcs11Service pkcs11Service) throws Exception {
        // Get and print all available slots
        List<Pkcs11Slot> pkcs11Slots = pkcs11Service.getSlots();
        for (Pkcs11Slot pkcs11Slot : pkcs11Slots) {
            System.out.println(pkcs11Slot.getSlotId());
        }
    }

    private static void handleIsLocked(Pkcs11Service pkcs11Service, String[] parameters) throws Exception {
        // Check the arguments
        if (parameters.length != 1) {
            throw new Exception("Usage: pkcs11-cli --is-locked <SLOT_ID>");
        }
        long slotId = Long.parseLong(parameters[0]);

        // Check if the user PIN is locked
        boolean isLocked = pkcs11Service.isPinLocked(slotId);
        System.out.println(isLocked);
    }

    private static void handleIsSoLocked(Pkcs11Service pkcs11Service, String[] parameters) throws Exception {
        // Check the arguments
        if (parameters.length != 1) {
            throw new Exception("Usage: pkcs11-cli --is-so-locked <SLOT_ID>");
        }
        long slotId = Long.parseLong(parameters[0]);

        // Check if the SO PIN is locked
        boolean isLocked = pkcs11Service.isSoPinLocked(slotId);
        System.out.println(isLocked);
    }

    private static void handleLogin(Pkcs11Service pkcs11Service, String[] parameters) throws Exception {
        // Check the arguments
        if (parameters.length != 2) {
            throw new Exception("Usage: pkcs11-cli --login <SLOT_ID> <PIN>");
        }
        long slotId = Long.parseLong(parameters[0]);
        String pin = parameters[1];

        // Login
        boolean login = pkcs11Service.login(slotId, pin);
        System.out.println(login);
    }

    private static void handleChangePin(Pkcs11Service pkcs11Service, String[] parameters) throws Exception {
        // Check the arguments
        if (parameters.length != 3) {
            throw new Exception("Usage: pkcs11-cli --change-pin <SLOT_ID> <CURRENT_PIN> <NEW_PIN>");
        }
        long slotId = Long.parseLong(parameters[0]);
        String currentPin = parameters[1];
        String newPin = parameters[2];

        // Change the PIN
        pkcs11Service.changePin(slotId, currentPin, newPin);
    }

    private static void handleUnlock(Pkcs11Service pkcs11Service, String[] parameters) throws Exception {
        // Check the arguments
        if (parameters.length != 3) {
            throw new Exception("Usage: pkcs11-cli --unlock <SLOT_ID> <SO_PIN> <NEW_PIN>");
        }
        long slotId = Long.parseLong(parameters[0]);
        String soPin = parameters[1];
        String newPin = parameters[2];

        // Unlock
        pkcs11Service.unlock(slotId, soPin, newPin);
    }

    private static void handleListCertificates(Pkcs11Service pkcs11Service, String[] parameters) throws Exception {
        // Check the arguments
        if (parameters.length != 1) {
            throw new Exception("Usage: pkcs11-cli --list-certificates <SLOT_ID>");
        }
        long slotId = Long.parseLong(parameters[0]);

        // Get the certificates
        List<X509Certificate> certificates = pkcs11Service.getCertificates(slotId);

        // Print the certificates
        for (X509Certificate certificate : certificates) {
            String subject = certificate.getSubjectX500Principal().toString();
            String issuer = certificate.getIssuerX500Principal().toString();
            Instant fromDate = certificate.getNotBefore().toInstant();
            Instant toDate = certificate.getNotAfter().toInstant();
            System.out.println(STR."\{subject};\{issuer};\{fromDate};\{toDate}");
        }
    }

    private static void handleSignPdf(Pkcs11Service pkcs11Service, String[] parameters) throws Exception {
        // Check the arguments
        if (parameters.length != 4) {
            throw new Exception("Usage: pkcs11-cli --sign-pdf <SLOT_ID> <PIN> <INPUT_FILE> <OUTPUT_FILE>");
        }
        long slotId = Long.parseLong(parameters[0]);
        String pin = parameters[1];
        File inputFile = new File(parameters[2]);
        File outputFile = new File(parameters[3]);

        // Sign the PDF file
        pkcs11Service.signPdfFile(slotId, pin, inputFile, outputFile);
    }

    private static void handleVerifyPdf(Pkcs11Service pkcs11Service, String[] parameters) throws Exception {
        // Check the arguments
        if (parameters.length != 1) {
            throw new Exception("Usage: pkcs11-cli --verify-pdf <FILE>");
        }
        File file = new File(parameters[0]);

        // Verify the PDF file
        pkcs11Service.verifyPdfFile(file);
    }

    private static void handleHelp() {
        System.out.println("===== Available commands =====");
        System.out.println("--list-slots");
        System.out.println("--is-locked <SLOT_ID>");
        System.out.println("--is-so-locked <SLOT_ID>");
        System.out.println("--login <SLOT_ID> <PIN>");
        System.out.println("--change-pin <SLOT_ID> <CURRENT_PIN> <NEW_PIN>");
        System.out.println("--unlock <SLOT_ID> <SO_PIN> <NEW_PIN>");
        System.out.println("--list-certificates <SLOT_ID>");
        System.out.println("--sign-pdf <SLOT_ID> <PIN> <INPUT_FILE> <OUTPUT_FILE>");
        System.out.println("--verify-pdf <FILE>");
        System.out.println("--help");
        System.out.println("--version");
        System.out.println();
        System.out.println("===== Environment variables =====");
        System.out.println("JAVA_CRYPTOKI_NAME: Name of the PKCS11 middleware, by default cryptoki");
        System.out.println();
    }

    private static void handleVersion() {
        System.out.println("Java PKCS11 library " + Pkcs11Library.getVersion() + " (https://github.com/swaechter/pkcs11)");
        System.out.println("Copyright (c) 2023 - 2024 Simon Wächter");
    }
}

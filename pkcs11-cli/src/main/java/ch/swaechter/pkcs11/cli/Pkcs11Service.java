package ch.swaechter.pkcs11.cli;

import ch.swaechter.pkcs11.library.Pkcs11Exception;
import ch.swaechter.pkcs11.library.Pkcs11Module;
import ch.swaechter.pkcs11.library.headers.CkAttribute;
import ch.swaechter.pkcs11.library.headers.CkAttributeValue;
import ch.swaechter.pkcs11.library.headers.CkObjectClass;
import ch.swaechter.pkcs11.library.headers.CkUserType;
import ch.swaechter.pkcs11.library.objects.Pkcs11Session;
import ch.swaechter.pkcs11.library.objects.Pkcs11Slot;
import ch.swaechter.pkcs11.library.objects.Pkcs11Token;
import ch.swaechter.pkcs11.library.objects.Pkcs11TokenInfo;
import com.itextpdf.forms.fields.properties.SignedAppearanceText;
import com.itextpdf.forms.form.element.SignatureFieldAppearance;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;

import java.io.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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

    public List<X509Certificate> getCertificates(long slotId) throws Pkcs11Exception {
        // Get the slot and token
        Pkcs11Slot pkcs11Slot = getPkcs11Slot(slotId);
        Pkcs11Token pkcs11Token = pkcs11Slot.getToken();

        // Open a session
        try (Pkcs11Session pkcs11Session = pkcs11Token.openSession(true, true)) {
            // Search the certificate handle ID
            List<CkAttributeValue> ckAttributeSearchTemplate = new ArrayList<>();
            ckAttributeSearchTemplate.add(new CkAttributeValue(CkAttribute.CKA_CLASS, CkObjectClass.CKO_CERTIFICATE.value));
            List<Long> objectHandles = pkcs11Session.findObjects(ckAttributeSearchTemplate);

            // Ensure there are at least three certificates
            if (objectHandles.size() < 3) {
                throw new Pkcs11Exception(STR."At least 3 certificates are required for signing. Found: \{objectHandles.size()}");
            }

            // Get the value of each certificate
            List<X509Certificate> certificates = new ArrayList<>(objectHandles.size());
            for (int i = 0; i < objectHandles.size(); i++) {
                // Get the object handle
                long objectHandle = objectHandles.get(i);

                // Get the certificate value
                List<byte[]> attributeValues = pkcs11Session.getAttributeValue(objectHandle, List.of(CkAttribute.CKA_VALUE));
                byte[] value = attributeValues.getFirst();

                // Convert and add the certificate
                X509Certificate certificate = parseCertificate(value);
                certificates.add(certificate);
            }

            // Return the certificates
            return certificates;
        } catch (IOException exception) {
            throw new Pkcs11Exception(STR."Unable to list and parse certificates: \{exception.getMessage()}", exception);
        }
    }

    public void signPdfFile(long slotId, String pin, File inputFile, File outputFile) throws Pkcs11Exception {
        // Check the input file
        if (!inputFile.isFile()) {
            throw new Pkcs11Exception(STR."The input file \{inputFile.getAbsolutePath()} does not exist/is not a file.");
        }

        // Get the slot and token
        Pkcs11Slot pkcs11Slot = getPkcs11Slot(slotId);
        Pkcs11Token pkcs11Token = pkcs11Slot.getToken();

        // Open a session
        try (Pkcs11Session pkcs11Session = pkcs11Token.openSession(true, true)) {
            // Login
            pkcs11Session.loginUser(CkUserType.CKU_USER, pin);

            // Create the PKCS11 signature
            Pkcs11Signature pkcs11Signature = new Pkcs11Signature(pkcs11Session);

            // Create the PDF reader and signer
            StampingProperties stampingProperties = new StampingProperties();
            PdfReader pdfReader = new PdfReader(inputFile);
            PdfSigner pdfSigner = new PdfSigner(pdfReader, new FileOutputStream(outputFile), stampingProperties);

            // Define the visual signature description
            SignedAppearanceText signedAppearanceText = new SignedAppearanceText().setReasonLine("PKCS11 Test").setLocationLine("Basel").setSignedBy("Simon Wächter");
            SignatureFieldAppearance signatureFieldAppearance = new SignatureFieldAppearance("signature1").setContent(signedAppearanceText);

            // Set the signature information
            pdfSigner.setPageRect(new Rectangle(40, 650, 250, 100));
            pdfSigner.setSignatureAppearance(signatureFieldAppearance);
            pdfSigner.setPageNumber(1);

            // Sign the document
            IExternalDigest digest = new BouncyCastleDigest();
            pdfSigner.signDetached(digest, pkcs11Signature, pkcs11Signature.getChain(), null, null, null, 0, PdfSigner.CryptoStandard.CMS);

            // Logout
            pkcs11Session.logoutUser();
        } catch (Exception exception) {
            throw new Pkcs11Exception(STR."Unable to sign PDF file \{exception.getMessage()}", exception);
        }
    }

    public void verifyPdfFile(File file) throws Pkcs11Exception {
        // Check the file
        if (!file.isFile()) {
            throw new Pkcs11Exception(STR."The file \{file.getAbsolutePath()} does not exist/is not a file.");
        }

        // Verify the signed PDF document
        try (
            PdfReader pdfReader = new PdfReader(new FileInputStream(file));
            PdfDocument pdfDocument = new PdfDocument(pdfReader)
        ) {
            // Create the signature utils and get all signature names
            SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
            List<String> signatureNames = signatureUtil.getSignatureNames();

            // Check all signatures
            for (String signatureName : signatureNames) {
                // Read the signature
                PdfPKCS7 pdfPkcs7 = signatureUtil.readSignatureData(signatureName);

                // Check the signature
                if (!signatureUtil.signatureCoversWholeDocument(signatureName)) {
                    throw new Pkcs11Exception(STR."Signature \{signatureName} does not cover the full document.");
                }
                if (!pdfPkcs7.verifySignatureIntegrityAndAuthenticity()) {
                    throw new Pkcs11Exception(STR."Signature \{signatureName} is not valid.");
                }
            }
        } catch (Exception exception) {
            throw new Pkcs11Exception(STR."Unable to verify PDF or verification failed: \{exception.getMessage()}", exception);
        }
    }

    @Override
    public void close() throws Exception {
        pkcs11Module.finalizeModule();
    }

    public static X509Certificate parseCertificate(byte[] certificateValue) throws Pkcs11Exception {
        // Parse the certificate
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(certificateValue)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(new BufferedInputStream(byteArrayInputStream));
        } catch (Exception ex) {
            throw new Pkcs11Exception(STR."Unable to convert certificate: \{ex.getMessage()}", ex);
        }
    }
}

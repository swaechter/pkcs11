package ch.swaechter.pdf;

import ch.swaechter.pkcs11.Pkcs11Module;
import ch.swaechter.pkcs11.Pkcs11TestTemplate;
import ch.swaechter.pkcs11.headers.CkUserType;
import ch.swaechter.pkcs11.objects.Pkcs11Session;
import ch.swaechter.pkcs11.objects.Pkcs11Slot;
import ch.swaechter.pkcs11.objects.Pkcs11Token;
import com.itextpdf.forms.fields.properties.SignedAppearanceText;
import com.itextpdf.forms.form.element.SignatureFieldAppearance;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test the signing of a PDF file.
 *
 * @author Simon Wächter
 */
public class PdfSignTest {

    @Test
    public void testPdfSigning() throws Exception {
        // Get the file
        File inputFile = new File("src/test/resources/Document.pdf");
        File outputFile = new File("src/test/resources/Document_Signed.pdf");
        assertTrue(inputFile.isFile());

        // Create the PKCS11 module
        try (Pkcs11Module pkcs11Module = new Pkcs11Module(Pkcs11TestTemplate.LIBRARY_NAME)) {
            // Get the slot and token
            Pkcs11Slot pkcs11Slot = pkcs11Module.getSlot(0);
            Pkcs11Token pkcs11Token = pkcs11Slot.getToken();

            // Open a session
            try (Pkcs11Session pkcs11Session = pkcs11Token.openSession(true, true)) {
                // Login
                pkcs11Session.loginUser(CkUserType.CKU_USER, Pkcs11TestTemplate.PKCS11_TOKEN_PIN);

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
            }
        }

        // Verify the signed PDF document
        try (
            PdfReader pdfReader = new PdfReader(new FileInputStream(outputFile));
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
                assertTrue(signatureUtil.signatureCoversWholeDocument(signatureName));
                assertTrue(pdfPkcs7.verifySignatureIntegrityAndAuthenticity());
            }
        }
    }
}

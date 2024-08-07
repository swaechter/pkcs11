package ch.swaechter.pkcs11.cli;

import ch.swaechter.pkcs11.Pkcs11TestTemplate;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Test the PKCS11 service of the CLI application.
 *
 * @author Simon Wächter
 */
public class Pkcs11ServiceTest {

    @Test
    public void testPdfSigning() throws Exception {
        // Create the service
        try (Pkcs11Service pkcs11Service = new Pkcs11Service(Pkcs11TestTemplate.LIBRARY_NAME)) {
            // List the certificates
            List<X509Certificate> certificates = pkcs11Service.getCertificates(Pkcs11TestTemplate.PKCS_SLOT_ID);
            assertFalse(certificates.isEmpty());

            // Define the files
            File inputFile = new File("src/test/resources/Document.pdf");
            File outputFile = new File("src/test/resources/Document_Signed.pdf");

            // Sign the PDF file
            pkcs11Service.signPdfFile(Pkcs11TestTemplate.PKCS_SLOT_ID, Pkcs11TestTemplate.PKCS11_TOKEN_PIN, inputFile, outputFile);

            // Verify the PDF file
            pkcs11Service.verifyPdfFile(outputFile);
        }
    }
}

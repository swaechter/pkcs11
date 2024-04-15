package ch.swaechter.pkcs11.cli;

import ch.swaechter.pkcs11.library.Pkcs11Exception;
import ch.swaechter.pkcs11.library.Pkcs11Library;
import ch.swaechter.pkcs11.library.headers.CkAttribute;
import ch.swaechter.pkcs11.library.headers.CkAttributeValue;
import ch.swaechter.pkcs11.library.headers.CkMechanism;
import ch.swaechter.pkcs11.library.headers.CkObjectClass;
import ch.swaechter.pkcs11.library.objects.Pkcs11Session;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.ISignatureMechanismParams;

import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Implement the PKCS11 sign operation.
 *
 * @author Simon Wächter
 */
public class Pkcs11Signature implements IExternalSignature {

    private final Pkcs11Session pkcs11Session;

    private final long privateKeyObjectId;

    private final Certificate[] chain;

    public Pkcs11Signature(Pkcs11Session pkcs11Session) throws Pkcs11Exception {
        // Set the session
        this.pkcs11Session = pkcs11Session;

        // Get the private key object ID
        this.privateKeyObjectId = loadPrivateKeyObject();

        // Get the certificates
        this.chain = getPublicCertificates();
    }

    private long loadPrivateKeyObject() throws Pkcs11Exception {
        // Search the private key handle ID
        List<CkAttributeValue> ckAttributeSearchTemplate = new ArrayList<>();
        ckAttributeSearchTemplate.add(new CkAttributeValue(CkAttribute.CKA_CLASS, CkObjectClass.CKO_PRIVATE_KEY.value));
        List<Long> objectHandles = pkcs11Session.findObjects(ckAttributeSearchTemplate);

        // Ensure there is exactly one private key
        if (objectHandles.size() != 1) {
            throw new Pkcs11Exception(STR."For signing, exactly 1 private key is required. Found: \{objectHandles.size()}");
        }

        // Return the object ID
        return objectHandles.getFirst();
    }

    private Certificate[] getPublicCertificates() throws Pkcs11Exception {
        // Search the certificate handle ID
        List<CkAttributeValue> ckAttributeSearchTemplate = new ArrayList<>();
        ckAttributeSearchTemplate.add(new CkAttributeValue(CkAttribute.CKA_CLASS, CkObjectClass.CKO_CERTIFICATE.value));
        List<Long> objectHandles = pkcs11Session.findObjects(ckAttributeSearchTemplate);

        // Ensure there are at least three certificates
        if (objectHandles.size() < 3) {
            throw new Pkcs11Exception(STR."At least 3 certificates are required for signing. Found: \{objectHandles.size()}");
        }

        // Get the value of each certificate
        Certificate[] certificates = new Certificate[objectHandles.size()];
        for (int i = 0; i < objectHandles.size(); i++) {
            // Get the object handle
            long objectHandle = objectHandles.get(i);

            // Get the certificate value
            List<byte[]> attributeValues = pkcs11Session.getAttributeValue(objectHandle, List.of(CkAttribute.CKA_VALUE));
            byte[] value = attributeValues.getFirst();

            // Convert and add the certificate
            X509Certificate certificate = Pkcs11Service.parseCertificate(value);
            certificates[i] = certificate;
        }

        // Return the certificates
        return certificates;
    }

    public Certificate[] getChain() {
        return chain;
    }

    @Override
    public String getDigestAlgorithmName() {
        return DigestAlgorithms.SHA256;
    }

    @Override
    public String getSignatureAlgorithmName() {
        return "RSA";
    }

    @Override
    public ISignatureMechanismParams getSignatureMechanismParameters() {
        return null;
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        try {
            // TODO: Implement a method
            Pkcs11Library pkcs11Library = pkcs11Session.getPkcs11Library();
            pkcs11Library.C_SignInit(pkcs11Session.getSessionId(), CkMechanism.CKM_SHA256_RSA_PKCS, privateKeyObjectId);
            return pkcs11Library.C_Sign(pkcs11Session.getSessionId(), message, 8000);
        } catch (Exception exception) {
            throw new GeneralSecurityException(STR."Unable to sign: \{exception.getMessage()}", exception);
        }
    }
}

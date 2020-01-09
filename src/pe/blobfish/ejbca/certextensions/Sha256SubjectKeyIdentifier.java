package pe.blobfish.ejbca.certextensions;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

import java.io.IOException;
import java.security.PublicKey;

public class Sha256SubjectKeyIdentifier extends BaseSha256KeyIdentifier {

    public static final String DISPLAY_NAME = "SHA-256 SKI Certificate Extension";

    {
        // TODO check if this call to 'setDisplayName' could be moved to the superclass.
        setDisplayName(DISPLAY_NAME);
    }

    @Override
    protected byte[] internalGetValueEncoded(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey, PublicKey caPublicKey, CertificateValidity val) {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(userPublicKey.getEncoded());
        SubjectKeyIdentifier subjectKeyIdentifier = getSha256JcaX509ExtensionUtils().createSubjectKeyIdentifier(spki);
        try {
            return subjectKeyIdentifier.getEncoded();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected String getExpectedExtnID() {
        return Extension.subjectKeyIdentifier.getId();
    }
}

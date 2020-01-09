package pe.blobfish.ejbca.certextensions;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.standard.AuthorityKeyIdentifier;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class Sha256AuthorityKeyIdentifier extends BaseSha256KeyIdentifier {

    public static final String DISPLAY_NAME = "SHA-256 AKI Certificate Extension";

    {
        setDisplayName(DISPLAY_NAME);
    }

    @Override
    protected byte[] internalGetValueEncoded(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey, PublicKey caPublicKey, CertificateValidity val) {
        AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
        // NOTE that it is important to keep the following logic (specially the conditionals) in sync with the one at AuthorityKeyIdentifier.getValue.
        final X509Certificate cacert = getCACertificate(authorityKeyIdentifier, ca, caPublicKey);
        final boolean isRootCA = (certProfile.getType() == CertificateConstants.CERTTYPE_ROOTCA);
        if ((cacert != null) && (!isRootCA)) {
            byte[] akibytes;
            akibytes = CertTools.getSubjectKeyId(cacert);
            if (akibytes != null) {
                //region reusing existing logic in AuthorityKeyIdentifier.getValue instead of duplicating it.
                try {
                    ASN1Encodable value = authorityKeyIdentifier.getValue(userData, ca, certProfile, userPublicKey, caPublicKey, val);
                    return value.toASN1Primitive().getEncoded();
                } catch (CertificateExtensionException | IOException e) {
                    throw new RuntimeException(e);
                }
                //endregion
            }
        }
        try {
            return getSha256JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey).getEncoded();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * This method calls 'AuthorityKeyIdentifier#getCACertificate' by reflection instead of duplicating its logic.
     */
    private X509Certificate getCACertificate(AuthorityKeyIdentifier authorityKeyIdentifier, CA ca, PublicKey caPublicKey){
        try {
            Method getCACertificate = AuthorityKeyIdentifier.class.getDeclaredMethod("getCACertificate", CA.class, PublicKey.class);
            getCACertificate.setAccessible(true);
            return (X509Certificate) getCACertificate.invoke(authorityKeyIdentifier, ca, caPublicKey);
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected String getExpectedExtnID() {
        return Extension.authorityKeyIdentifier.getId();
    }
}

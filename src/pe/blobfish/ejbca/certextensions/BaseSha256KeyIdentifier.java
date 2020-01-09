package pe.blobfish.ejbca.certextensions;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CustomCertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.core.model.util.EjbLocalHelper;

import java.security.PublicKey;
import java.util.List;
import java.util.Properties;

/**
 * Given that DynamicCriticalityCertificateExtension has been taken as reference to write this class (and subclasses), TODOs in that class are relevant for this one.
 */
// TODO check if any of the other properties configured from the GUI have any relevance for the operation of the childs of this class, i.e. Encoding, Dynamic, Required, etc.
public abstract class BaseSha256KeyIdentifier extends BasicCertificateExtension {

    // TODO confirm if this is safe to overwrite this method like this, study the call to 'init' from org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration.getCertificateExtensionFromFile.
    @Override
    public void init(int id, String oID, String displayName, boolean criticalFlag, boolean requiredFlag, Properties extensionProperties) {
        String expectedExtnID = getExpectedExtnID();
        if (!oID.equals(expectedExtnID)){
            throw new IllegalStateException("This custom certificate extension can configured only with OID " + expectedExtnID);
        }
        super.init(id, oID, displayName, criticalFlag, requiredFlag, extensionProperties);
    }

    protected abstract String getExpectedExtnID();

    @Override
    public byte[] getValueEncoded(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey, PublicKey caPublicKey, CertificateValidity val) {
        if (!(isCustomCertificateExtensionEnabled(certProfile, Sha256AuthorityKeyIdentifier.class) && isCustomCertificateExtensionEnabled(certProfile, Sha256SubjectKeyIdentifier.class))) {
            throw new IllegalStateException(String.format("'%s' and '%s' both need to be active in the certificate profile", Sha256AuthorityKeyIdentifier.DISPLAY_NAME, Sha256SubjectKeyIdentifier.DISPLAY_NAME));
        }
        return internalGetValueEncoded(userData, ca, certProfile, userPublicKey, caPublicKey, val);
    }

    protected abstract byte[] internalGetValueEncoded(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey, PublicKey caPublicKey, CertificateValidity val);

    protected JcaX509ExtensionUtils getSha256JcaX509ExtensionUtils() {
        DigestCalculator digestCalculator;
        try {
            DigestCalculatorProvider build = new JcaDigestCalculatorProviderBuilder().build();
            // TODO check: maybe the creation of the DigestCalculator could be performed only one per instance of the current class. Just take any concurrency issue into account.
            digestCalculator = build.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
        return new JcaX509ExtensionUtils(digestCalculator);
    }

    private boolean isCustomCertificateExtensionEnabled(CertificateProfile certProfile, Class<?> customCertificateExtension) {
        GlobalConfigurationSessionLocal globalConfigurationSession = new EjbLocalHelper().getGlobalConfigurationSession();
        final AvailableCustomCertificateExtensionsConfiguration cceConfig = (AvailableCustomCertificateExtensionsConfiguration)
                globalConfigurationSession.getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
        for (Integer usedCertificateExtension : certProfile.getUsedCertificateExtensions()) {
            CustomCertificateExtension enabledCustomCertificateExtension = cceConfig.getCustomCertificateExtension(usedCertificateExtension);
            if (customCertificateExtension.isAssignableFrom(enabledCustomCertificateExtension.getClass())) {
                return true;
            }
        }
        return false;
    }
}

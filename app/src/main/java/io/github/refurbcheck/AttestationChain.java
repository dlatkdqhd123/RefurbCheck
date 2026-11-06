package io.github.refurbcheck;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Offline PKIX only. A valid result does NOT include revocation or off-device validation. */
public final class AttestationChain {
    public static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    public static final String PROVISIONING_OID = "1.3.6.1.4.1.11129.2.1.30";
    private AttestationChain() { }

    public static X509Certificate validate(List<X509Certificate> leafFirst,
            Collection<X509Certificate> pinnedRoots, Date time) throws GeneralSecurityException {
        if (leafFirst == null || leafFirst.isEmpty() || leafFirst.size() > 8)
            throw new GeneralSecurityException("Invalid certificate chain size");
        if (pinnedRoots == null || pinnedRoots.isEmpty()) throw new GeneralSecurityException("No pinned roots");
        Set<TrustAnchor> anchors = new HashSet<>();
        for (X509Certificate root : pinnedRoots) {
            try {
                root.checkValidity(time);
                anchors.add(new TrustAnchor(root, null));
            } catch (CertificateExpiredException | CertificateNotYetValidException unavailable) {
                // During root rotation, an unused expired/future anchor must not invalidate a valid path.
                // It is excluded entirely; the selected root and every presented certificate stay date-checked.
            }
        }
        if (anchors.isEmpty()) throw new GeneralSecurityException("No currently valid pinned roots");
        Set<X509Certificate> unique = new HashSet<>();
        for (int i = 0; i < leafFirst.size(); i++) {
            X509Certificate certificate = leafFirst.get(i);
            if (certificate.getEncoded().length > DerReader.MAX_BYTES || !unique.add(certificate))
                throw new GeneralSecurityException("Malformed certificate chain");
            certificate.checkValidity(time);
            if (i + 1 < leafFirst.size()) {
                X509Certificate issuer = leafFirst.get(i + 1);
                if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()))
                    throw new GeneralSecurityException("Unordered certificate chain");
                certificate.verify(issuer.getPublicKey());
            }
        }
        List<X509Certificate> pathCertificates = new ArrayList<>(leafFirst);
        X509Certificate last = pathCertificates.get(pathCertificates.size() - 1);
        for (X509Certificate root : pinnedRoots) {
            if (last.getSubjectX500Principal().equals(root.getSubjectX500Principal())
                    && Arrays.equals(last.getPublicKey().getEncoded(), root.getPublicKey().getEncoded())) {
                last.verify(root.getPublicKey());
                pathCertificates.remove(pathCertificates.size() - 1);
                break;
            }
        }
        if (pathCertificates.isEmpty()) throw new GeneralSecurityException("No attested leaf certificate");
        CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(pathCertificates);
        PKIXParameters parameters = new PKIXParameters(anchors);
        parameters.setDate(time);
        // There is deliberately no app network access. Never report this as full validation.
        parameters.setRevocationEnabled(false);
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)
                CertPathValidator.getInstance("PKIX").validate(path, parameters);
        return result.getTrustAnchor().getTrustedCert();
    }

    /** Find the FIRST extension from the root, rejecting an inconsistent RKP extension position. */
    public static int attestationIndex(List<X509Certificate> leafFirst) throws IOException {
        int attestation = -1;
        int provisioning = -1;
        for (int i = leafFirst.size() - 1; i >= 0; i--) {
            X509Certificate certificate = leafFirst.get(i);
            if (attestation < 0 && certificate.getExtensionValue(ATTESTATION_OID) != null) attestation = i;
            if (provisioning < 0 && certificate.getExtensionValue(PROVISIONING_OID) != null) provisioning = i;
        }
        if (provisioning >= 0 && attestation != provisioning - 1)
            throw new IOException("Attestation does not follow provisioning certificate");
        return attestation;
    }
}

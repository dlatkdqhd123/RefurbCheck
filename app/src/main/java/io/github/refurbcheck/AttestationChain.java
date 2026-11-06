package io.github.refurbcheck;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
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

/** Local PKIX only. A valid result does NOT include revocation or off-device validation. */
public final class AttestationChain {
    public static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    public static final String PROVISIONING_OID = "1.3.6.1.4.1.11129.2.1.30";
    // The key, not merely SERIALNUMBER=f92009e853b6b045, identifies Google's legacy
    // authority. Renewed Google root certificates retain this SubjectPublicKeyInfo.
    private static final String LEGACY_GOOGLE_SPKI_SHA256 =
            "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae";
    private AttestationChain() { }

    public static X509Certificate validate(List<X509Certificate> leafFirst,
            Collection<X509Certificate> pinnedRoots, Date time) throws GeneralSecurityException {
        return validateDetailed(leafFirst, pinnedRoots, time).trustAnchor;
    }

    /** Describes the actual date policy used; it is never a device integrity verdict. */
    public static final class Validation {
        public final X509Certificate trustAnchor;
        public final boolean legacyFactoryExpiryApplied, presentedRootReplaced;
        public final int expiredFactoryCaCount;
        public final long pkixValidationTimeMillis;
        private Validation(X509Certificate anchor, int expiredFactoryCaCount,
                boolean presentedRootReplaced, Date pkixTime) {
            trustAnchor = anchor;
            this.expiredFactoryCaCount = expiredFactoryCaCount;
            legacyFactoryExpiryApplied = expiredFactoryCaCount > 0;
            this.presentedRootReplaced = presentedRootReplaced;
            pkixValidationTimeMillis = pkixTime.getTime();
        }
    }

    /**
     * Recognizes only a narrow, authenticated legacy factory layout for expiry
     * compatibility. All signatures, CA/path constraints and not-before dates
     * remain checked. RKP, unknown layouts and the freshly requested leaf never
     * receive an expiry exception. A factory path without a common historical
     * validity instant remains unsupported rather than weakening PKIX further.
     *
     * Policy reference: android/keyattestation v0.4, KeyAttestationCertPath and
     * KeyAttestationCertPathValidator. This conservative implementation is not
     * a port of that verifier and does not claim identical acceptance coverage.
     */
    public static Validation validateDetailed(List<X509Certificate> leafFirst,
            Collection<X509Certificate> pinnedRoots, Date time) throws GeneralSecurityException {
        if (leafFirst == null || leafFirst.isEmpty() || leafFirst.size() > 8)
            throw new GeneralSecurityException("Invalid certificate chain size");
        if (pinnedRoots == null || pinnedRoots.isEmpty()) throw new GeneralSecurityException("No pinned roots");
        if (time == null) throw new GeneralSecurityException("Validation time unavailable");
        List<X509Certificate> currentRoots = new ArrayList<>();
        for (X509Certificate root : pinnedRoots) {
            if (root == null) throw new GeneralSecurityException("Null trust anchor");
            try {
                root.checkValidity(time);
                currentRoots.add(root);
            } catch (CertificateExpiredException | CertificateNotYetValidException unavailable) {
                // Unused expired/future anchors cannot invalidate another valid path.
            }
        }
        if (currentRoots.isEmpty()) throw new GeneralSecurityException("No currently valid pinned roots");
        Set<X509Certificate> unique = new HashSet<>();
        for (int i = 0; i < leafFirst.size(); i++) {
            X509Certificate certificate = leafFirst.get(i);
            if (certificate == null || certificate.getEncoded().length > DerReader.MAX_BYTES || !unique.add(certificate))
                throw new GeneralSecurityException("Malformed certificate chain");
            if (i + 1 < leafFirst.size()) {
                X509Certificate issuer = leafFirst.get(i + 1);
                if (issuer == null) throw new GeneralSecurityException("Null issuer");
                if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()))
                    throw new GeneralSecurityException("Unordered certificate chain");
                certificate.verify(issuer.getPublicKey());
            }
        }
        List<X509Certificate> pathCertificates = new ArrayList<>(leafFirst);
        X509Certificate last = pathCertificates.get(pathCertificates.size() - 1);
        X509Certificate presentedRoot = null;
        for (X509Certificate root : currentRoots) {
            if (sameAuthority(last, root)) {
                last.verify(root.getPublicKey());
                presentedRoot = last;
                pathCertificates.remove(pathCertificates.size() - 1);
                break;
            }
        }
        if (pathCertificates.isEmpty()) throw new GeneralSecurityException("No attested leaf certificate");
        // A supplied self-signed old root is not the trust anchor. The matching,
        // current pinned root is. Never fail a renewed root solely because the
        // device still supplies Google's expired certificate for the same key.
        GeneralSecurityException failure = null;
        for (X509Certificate root : currentRoots) {
            X509Certificate issuerChild = pathCertificates.get(pathCertificates.size() - 1);
            if (!issuerChild.getIssuerX500Principal().equals(root.getSubjectX500Principal())) continue;
            try {
                issuerChild.verify(root.getPublicKey());
                boolean legacy = recognizedFactoryPath(pathCertificates, root);
                int expiredCa = 0;
                long validationMillis = time.getTime();
                for (int i = 0; i < pathCertificates.size(); i++) {
                    X509Certificate certificate = pathCertificates.get(i);
                    try {
                        certificate.checkValidity(time);
                    } catch (CertificateExpiredException expired) {
                        if (!legacy || i == 0) throw expired;
                        expiredCa++;
                    }
                    // CertificateNotYetValidException is deliberately never relaxed.
                    validationMillis = Math.min(validationMillis, certificate.getNotAfter().getTime());
                }
                Date pkixTime = time;
                if (expiredCa > 0) {
                    for (X509Certificate certificate : pathCertificates) {
                        if (certificate.getNotBefore().getTime() > validationMillis)
                            throw new GeneralSecurityException("Legacy factory chain has no common PKIX validity instant");
                        requireModernAlgorithm(certificate);
                    }
                    requireStrongKey(root.getPublicKey());
                    pkixTime = new Date(validationMillis);
                }
                validatePkix(pathCertificates, root, pkixTime);
                return new Validation(root, expiredCa,
                        presentedRoot != null && !Arrays.equals(presentedRoot.getEncoded(), root.getEncoded()), pkixTime);
            } catch (GeneralSecurityException exception) {
                failure = exception;
            }
        }
        if (failure != null) throw failure;
        throw new GeneralSecurityException("No matching pinned trust anchor");
    }

    private static void validatePkix(List<X509Certificate> pathCertificates, X509Certificate root, Date time)
            throws GeneralSecurityException {
        CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(pathCertificates);
        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(root, null));
        PKIXParameters parameters = new PKIXParameters(anchors);
        parameters.setDate(time);
        // Revocation is reported separately; this function never does a live query.
        parameters.setRevocationEnabled(false);
        CertPathValidator.getInstance("PKIX").validate(path, parameters);
    }

    private static boolean sameAuthority(X509Certificate first, X509Certificate second) {
        return first.getSubjectX500Principal().equals(second.getSubjectX500Principal())
                && Arrays.equals(first.getPublicKey().getEncoded(), second.getPublicKey().getEncoded());
    }

    private static boolean recognizedFactoryPath(List<X509Certificate> path, X509Certificate root)
            throws GeneralSecurityException {
        if (!LEGACY_GOOGLE_SPKI_SHA256.equals(hex(MessageDigest.getInstance("SHA-256")
                .digest(root.getPublicKey().getEncoded()))) || path.size() != 3) return false;
        for (X509Certificate certificate : path)
            if (certificate.getExtensionValue(PROVISIONING_OID) != null) return false;
        try {
            if (attestationIndex(path) != 0) return false;
            // v0.4 identifies the factory intermediate by its serialNumber RDN.
            // Inspect encoded attributes rather than matching a substring of a DN.
            DerReader.Value name = DerReader.single(path.get(2).getSubjectX500Principal().getEncoded());
            name.require(0, 16, true);
            boolean serial = false;
            for (DerReader.Value rdn : name.children()) {
                rdn.require(0, 17, true);
                for (DerReader.Value attribute : rdn.children()) {
                    attribute.require(0, 16, true);
                    List<DerReader.Value> fields = attribute.children();
                    if (fields.size() != 2) return false;
                    fields.get(0).require(0, 6, false);
                    byte[] oid = fields.get(0).encoded();
                    if (Arrays.equals(oid, new byte[]{6, 3, 85, 4, 5})) serial = true;
                    // A remote-provisioning style name is ambiguous, even if it
                    // also carries a serialNumber. Do not extend the exception.
                    if (Arrays.equals(oid, new byte[]{6, 3, 85, 4, 3})
                            || Arrays.equals(oid, new byte[]{6, 3, 85, 4, 10})) return false;
                }
            }
            return serial;
        } catch (IOException malformed) {
            return false;
        }
    }

    private static void requireModernAlgorithm(X509Certificate certificate) throws GeneralSecurityException {
        String oid = certificate.getSigAlgOID();
        if (!Arrays.asList("1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13",
                "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4").contains(oid))
            throw new GeneralSecurityException("Unsupported legacy factory signature algorithm");
        requireStrongKey(certificate.getPublicKey());
    }

    private static void requireStrongKey(PublicKey key) throws GeneralSecurityException {
        if (key instanceof RSAPublicKey && ((RSAPublicKey) key).getModulus().bitLength() >= 2048) return;
        if (key instanceof ECPublicKey && ((ECPublicKey) key).getParams().getCurve().getField().getFieldSize() >= 256) return;
        throw new GeneralSecurityException("Unsupported legacy factory public key");
    }

    private static String hex(byte[] bytes) {
        char[] digits = "0123456789abcdef".toCharArray();
        char[] result = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            result[i * 2] = digits[(bytes[i] >>> 4) & 15]; result[i * 2 + 1] = digits[bytes[i] & 15];
        }
        return new String(result);
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

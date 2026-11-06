package io.github.refurbcheck;

import android.app.Instrumentation;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;

import com.android.apksig.ApkVerifier;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Separate test APK, never a production component. Uses the real target APK's
 * classes and its installed APK bytes, with isolated catalog test storage.
 * Public benign APK fixtures are verified as files, never installed or run.
 */
public final class V13Instrumentation extends Instrumentation {
    private final JSONArray assertions = new JSONArray();
    private final JSONObject observations = new JSONObject();
    private JSONObject config;
    private IsolatedContext isolated;
    private long start;

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        start();
    }

    @Override public void onStart() {
        start = SystemClock.elapsedRealtime();
        Throwable failure = null;
        try {
            Context target = getTargetContext();
            config = new JSONObject(new String(asset("smoke-config.json", 32768), "UTF-8"));
            require("io.github.refurbcheck".equals(target.getPackageName()), "correct production target package");
            isolated = new IsolatedContext(target);
            phase("Live package metadata");
            ScanReport report = liveInventory(target);
            phase("Management and post-reset policy");
            ManagementInspection.inspect(target, report);
            JSONObject management = report.evidence.getJSONObject("management");
            require(!management.getBoolean("allDeviceProfilesVerified"), "management never claims complete cross-profile inspection");
            require(management.has("activeAdminEnumerationComplete") && management.has("roles"), "management completeness and roles are explicit");
            if (Build.VERSION.SDK_INT < 30)
                require("UNSUPPORTED_API".equals(management.getString("organizationOwnedQueryStatus")), "API26 organization-owned query guarded");
            else require(!"UNSUPPORTED_API".equals(management.getString("organizationOwnedQueryStatus")), "modern management API branch reached");
            FactoryResetPolicy.inspect(report, target.getPackageName(), true);
            ManifestRiskInspection.inspect(report, target.getPackageName());
            JSONObject self = report.inventory.getJSONObject(0);
            require("EXCLUDED_SELF".equals(self.getJSONObject("factoryResetPolicy").getString("outcome")), "post-reset policy excludes scanner itself");
            require(!report.evidence.getJSONObject("factoryResetPolicy").getBoolean("automaticRemovalAuthorized"), "policy does not authorize removal");
            require("EXCLUDED_SELF".equals(self.getJSONObject("capabilityRiskReview").getString("outcome")), "manifest risk review excludes scanner itself");
            observations.put("management", management);
            phase("Signed data channel and failed update retention");
            catalogUpdates();
            phase("Installed target APK hashing and signature verification");
            ApkInspection.inspect(isolated, report, null, new AtomicBoolean(false));
            require(self.getBoolean("apkInspectionComplete"), "installed target APK inspection completes");
            JSONArray files = self.getJSONArray("apkFiles");
            require(files.length() >= 1, "installed base APK is present");
            boolean baseSeen = false;
            for (int i = 0; i < files.length(); i++) {
                JSONObject file = files.getJSONObject(i);
                require("HASHED".equals(file.getString("hashStatus")) && file.getBoolean("fileStable"), "stable APK hash " + file.getString("fileId"));
                require("VERIFIED".equals(file.getString("signatureStatus")), "current runtime APK signature model " + file.getString("fileId"));
                require(file.getBoolean("signatureCryptographicVerified") && file.getBoolean("signerMetadataMatch"), "cryptographic signer matches PackageManager " + file.getString("fileId"));
                require(file.getInt("signatureCheckedApi") == Build.VERSION.SDK_INT, "runtime API is actually covered by APK model");
                if ("base".equals(file.getString("fileId"))) {
                    baseSeen = true;
                    require(config.getString("appSha256").equals(file.getString("sha256")), "scanner hashed the exact APK supplied to CI");
                }
            }
            require(baseSeen, "base APK identity checked against build artifact");
            require(!self.getBoolean("confirmedIoc") && self.getInt("malwareReferenceMatchCount") == 0, "benign own APK has no bundled reference match");
            require(!RemediationRules.eligible(self, target.getPackageName()) && !MalwareRemediationRules.eligible(self, target.getPackageName()), "neither remediation path can remove the scanner");
            observations.put("ownApkFiles", files);
            observations.put("malwareDatabase", report.evidence.opt("malwareDatabase"));
            require(!report.toJson().getBoolean("factoryOriginalVerified") && !report.toJson().getBoolean("malwareAbsenceVerified"), "scan JSON keeps unverified assurance domains false");
            phase("Benign upstream v3.1 and ECDSA files on Android crypto providers");
            apkSignatureFixtures();
            phase("Attestation date-policy fixtures and live guarded probe");
            attestationFixtures(target);
            AttestationProbe.check(target, report);
            boolean externalLimit = false;
            for (Finding finding : report.findings) {
                if (finding.id.startsWith("attestation_"))
                    require(finding.status != Finding.Status.PASS, "attestation never makes a clean-device PASS claim: " + finding.id);
                if ("attestation_external".equals(finding.id)) externalLimit = finding.status == Finding.Status.UNKNOWN;
            }
            require(externalLimit, "live probe retains external-verification UNKNOWN");
            JSONObject attestation = report.evidence.optJSONObject("attestation");
            if (attestation != null) {
                require(!attestation.getBoolean("fullAttestationTrusted") && !attestation.getBoolean("offDeviceVerified"), "live probe does not certify itself");
                if (attestation.has("devicePropertiesRequested"))
                    require(attestation.getBoolean("devicePropertiesRequested") == (Build.VERSION.SDK_INT >= 31), "device-property API31 guard executed correctly");
                observations.put("attestationRequestStatus", attestation.optString("devicePropertiesRequestStatus", "UNAVAILABLE_BEFORE_REQUEST"));
                observations.put("attestationProbeError", attestation.optString("probeError", ""));
                observations.put("localAttestationChainValid", attestation.optBoolean("localChainValid", false));
            }
        } catch (Throwable error) {
            failure = error;
        } finally {
            if (isolated != null) {
                try { isolated.cleanup(); }
                catch (Exception cleanupFailure) { if (failure == null) failure = cleanupFailure; }
            }
        }
        JSONObject summary = new JSONObject();
        try {
            summary.put("schema", "refurbcheck-android-v13-smoke-v1").put("passed", failure == null)
                    .put("apiLevel", Build.VERSION.SDK_INT).put("androidRelease", Build.VERSION.RELEASE)
                    .put("assertionCount", assertions.length()).put("assertions", assertions)
                    .put("elapsedMillis", SystemClock.elapsedRealtime() - start).put("observations", observations)
                    .put("actualGalaxyTest", false).put("malwareDetectionRateMeasured", false)
                    .put("hardwareIntegrityCertified", false).put("fixtureApksInstalled", false);
            if (failure != null) {
                StringWriter trace = new StringWriter(); failure.printStackTrace(new PrintWriter(trace));
                String value = trace.toString();
                summary.put("failureType", failure.getClass().getName()).put("failureMessage", String.valueOf(failure.getMessage()))
                        .put("failureTrace", value.substring(0, Math.min(5000, value.length())));
            }
        } catch (Exception serializationFailure) {
            failure = serializationFailure;
        }
        Bundle result = new Bundle();
        result.putString("summary", summary.toString());
        result.putString("stream", "\nREFURBCHECK_SMOKE=" + summary + "\n");
        finish(failure == null ? 0 : 1, result);
    }

    @SuppressWarnings("deprecation")
    private ScanReport liveInventory(Context target) throws Exception {
        PackageManager pm = target.getPackageManager();
        int flags = PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES
                | (Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES);
        PackageInfo info = pm.getPackageInfo(target.getPackageName(), flags);
        require(info.applicationInfo != null, "own ApplicationInfo accessible");
        require(config.getString("appSha256").equals(fileSha256(new File(info.applicationInfo.sourceDir))), "installed artifact SHA256 independently matches build");
        JSONObject row = new JSONObject().put("packageName", info.packageName).put("label", "RefurbCheck")
                .put("system", (info.applicationInfo.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0)
                .put("versionCode", Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : ((long) info.versionCode & 0xffffffffL))
                .put("versionName", info.versionName).put("lastUpdateTime", info.lastUpdateTime);
        PackageProvenance.collect(pm, info, row);
        ManifestRiskInspection.collectDeclared(info, row);
        require(row.getBoolean("signingReadable") && row.getJSONArray("signingSha256").length() == 1, "own signer collected on this runtime");
        JSONObject source = row.getJSONObject("installProvenance");
        require(!source.getBoolean("authenticatedDistribution"), "installer metadata not treated as authenticated distribution");
        require(!"ERROR".equals(source.getString("queryStatus")), "live install-source API does not throw");
        if (Build.VERSION.SDK_INT < 28) {
            require("LEGACY".equals(row.getString("signingMode")), "API26 uses legacy signer API");
            require("UNSUPPORTED_API".equals(row.getString("signingHistoryStatus")), "API26 unavailable signer history remains explicit");
        } else {
            require("SINGLE".equals(row.getString("signingMode")) && row.getBoolean("signingHistoryReadable"), "modern single-signer history is readable");
        }
        require(Build.VERSION.SDK_INT < 30 ? "LEGACY_API".equals(source.getString("queryStatus"))
                : "COLLECTED".equals(source.getString("queryStatus")), "install-source branch matches runtime API");
        require(Build.VERSION.SDK_INT < 33 ? "UNSUPPORTED_API".equals(source.getString("packageSourceStatus"))
                : "COLLECTED".equals(source.getString("packageSourceStatus")), "package-source API33 guard correct");
        require(Build.VERSION.SDK_INT < 34 ? "UNSUPPORTED_API".equals(source.getString("updateOwnerPackageStatus"))
                : !"UNSUPPORTED_API".equals(source.getString("updateOwnerPackageStatus"))
                && !"ERROR".equals(source.getString("updateOwnerPackageStatus")), "update-owner API34 guard correct");
        observations.put("installProvenance", source).put("signingMode", row.getString("signingMode"));
        ScanReport report = new ScanReport(); report.inventory.put(row);
        // This is a one-package sample, never a complete phone inventory.
        report.inventoryComplete = false;
        JSONObject device = new JSONObject().put("androidRelease", Build.VERSION.RELEASE).put("securityPatch", Build.VERSION.SECURITY_PATCH)
                .put("brand", Build.BRAND).put("device", Build.DEVICE).put("product", Build.PRODUCT)
                .put("manufacturer", Build.MANUFACTURER).put("model", Build.MODEL);
        report.evidence.put("device", device).put("runtimeTestScope", "INSTALLED_SCANNER_PACKAGE_ONLY");
        return report;
    }

    private void catalogUpdates() throws Exception {
        CatalogUpdateManager.Selection before = CatalogUpdateManager.current(isolated, budget());
        require("bundled".equals(before.origin), "isolated catalog starts with bundled data");
        require(before.snapshot.entryCount == MalwareCatalog.ENTRY_COUNT, "runtime bundled catalog verifies pinned count");
        byte[] bundle = asset("catalog-update.zip", CatalogUpdateVerifier.MAX_BUNDLE_BYTES);
        CatalogUpdateManager.Result installed = CatalogUpdateManager.importUpdate(isolated,
                new ByteArrayInputStream(bundle), new AtomicBoolean(false));
        require(installed.changed, "first signed catalog accepted in isolated store");
        CatalogUpdateManager.Selection accepted = CatalogUpdateManager.current(isolated, budget());
        require("signed-update".equals(accepted.origin) && accepted.snapshot.signedUpdate, "runtime uses authenticated active catalog");
        require(ApkEvidence.sha256(bundle).equals(accepted.snapshot.bundleSha256), "active catalog has exact signed bundle hash");
        File active = new File(isolated.getNoBackupFilesDir(), "catalog-updates/active.zip");
        String previousFile = fileSha256(active);
        boolean rejected = false;
        try {
            CatalogUpdateManager.importUpdate(isolated, new ByteArrayInputStream(
                    asset("catalog-invalid-signature.zip", CatalogUpdateVerifier.MAX_BUNDLE_BYTES)), new AtomicBoolean(false));
        } catch (IOException expected) {
            rejected = true;
            require(expected.getMessage() != null && expected.getMessage().contains("SIGNATURE"), "tampered signature rejected by crypto verification");
        }
        require(rejected, "tampered signed update cannot install");
        CatalogUpdateManager.Selection retained = CatalogUpdateManager.current(isolated, budget());
        require(retained.snapshot.sequence == accepted.snapshot.sequence
                && retained.snapshot.bundleSha256.equals(accepted.snapshot.bundleSha256), "failed update retains prior catalog identity");
        require(fileSha256(active).equals(previousFile), "failed update leaves active bytes unchanged");
        require("CHECK_FAILED".equals(CatalogUpdateManager.lastCheck(isolated).getString("state")), "failed update is visible in diagnostics");
        observations.put("catalog", retained.diagnostics());
    }

    private void apkSignatureFixtures() throws Exception {
        File good = copyFixture("v2-only-with-ecdsa-sha256-p256.apk");
        File bad = copyFixture("v2-only-with-ecdsa-sha256-p256-digest-mismatch.apk");
        File rotation = copyFixture("v31-rsa-2048_2-tgt-34-1-tgt-28.apk");
        File stripped = copyFixture("v31-block-stripped-v3-attr-value-33.apk");
        for (int api : new int[]{26, 36}) {
            require(verify(good, api).isVerified(), "Android provider verifies ECDSA fixture using API" + api + " model");
            require(!verify(bad, api).isVerified(), "Android provider rejects changed ECDSA content using API" + api + " model");
        }
        ApkVerifier.Result pre = verify(rotation, 32), post = verify(rotation, 36);
        require(pre.isVerified() && post.isVerified(), "v3.1 rotated APK verifies before and after target API");
        require(post.isVerifiedUsingV31Scheme(), "API36 model actually verifies the v3.1 block");
        require(pre.getSignerCertificates().size() == 1 && post.getSignerCertificates().size() == 1,
                "v3.1 selected signer is unambiguous");
        require(!ApkEvidence.sha256(pre.getSignerCertificates().get(0).getEncoded()).equals(
                ApkEvidence.sha256(post.getSignerCertificates().get(0).getEncoded())), "v3.1 rotation changes selected certificate");
        require(!verify(stripped, 36).isVerified(), "stripped v3.1 block rejected by API36 model");
    }

    private void attestationFixtures(Context target) throws Exception {
        List<X509Certificate> roots;
        try (InputStream input = target.getAssets().open("google_attestation_roots.pem")) { roots = certificates(input); }
        List<X509Certificate> factory = certificates(new ByteArrayInputStream(asset("google-v04-factory-blueline.pem", 32768)));
        List<X509Certificate> rkp = certificates(new ByteArrayInputStream(asset("google-v04-rkp-caiman.pem", 32768)));
        Date later = new Date(1893456000000L); // 2030-01-01T00:00:00Z, independent of emulator wall time.
        AttestationChain.Validation validation = AttestationChain.validateDetailed(factory, roots, later);
        require(validation.legacyFactoryExpiryApplied && validation.expiredFactoryCaCount == 2,
                "Android PKIX provider supports constrained official factory expiry fixture");
        boolean rejected = false;
        try { AttestationChain.validateDetailed(rkp, roots, later); }
        catch (java.security.GeneralSecurityException expected) { rejected = true; }
        require(rejected, "Android PKIX provider still rejects expired official RKP fixture");
    }

    private static List<X509Certificate> certificates(InputStream input) throws Exception {
        List<X509Certificate> result = new ArrayList<>();
        for (Certificate certificate : CertificateFactory.getInstance("X.509").generateCertificates(input))
            result.add((X509Certificate) certificate);
        return result;
    }
    private static ApkVerifier.Result verify(File apk, int api) throws Exception {
        return new ApkVerifier.Builder(apk).setMinCheckedPlatformVersion(api).setMaxCheckedPlatformVersion(api).build().verify();
    }
    private File copyFixture(String name) throws Exception {
        byte[] bytes = asset("apk-fixtures/" + name, 4 * 1024 * 1024);
        require(config.getJSONObject("fixtureSha256").getString(name).equals(ApkEvidence.sha256(bytes)), "exact upstream fixture bytes: " + name);
        File file = new File(isolated.directory, name);
        try (FileOutputStream output = new FileOutputStream(file)) { output.write(bytes); }
        return file;
    }
    private byte[] asset(String name, int maximum) throws IOException {
        try (InputStream input = getContext().getAssets().open(name)) {
            return CatalogUpdateVerifier.readBounded(input, maximum, budget());
        }
    }
    private static ApkEvidence.Budget budget() {
        return new ApkEvidence.Budget(new AtomicBoolean(false), 30000, 64L * 1024 * 1024, System::nanoTime);
    }
    private static String fileSha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[32768]; int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return ApkEvidence.hex(digest.digest());
    }
    private void require(boolean value, String label) throws Exception {
        assertions.put(new JSONObject().put("check", label).put("passed", value));
        if (!value) throw new AssertionError(label);
    }
    private void phase(String name) {
        Bundle progress = new Bundle(); progress.putString("stream", "RefurbCheck smoke: " + name + "\n");
        sendStatus(0, progress);
    }

    /** Catalog writes are redirected into a unique test cache directory/pref namespace. */
    private static final class IsolatedContext extends ContextWrapper {
        final File directory;
        final String prefix = "v13-smoke-" + UUID.randomUUID() + "-";
        final Set<String> preferenceNames = new HashSet<>();
        IsolatedContext(Context base) throws IOException {
            super(base);
            directory = new File(base.getCacheDir(), prefix + "data");
            if (!directory.mkdirs()) throw new IOException("Could not create isolated test directory");
        }
        @Override public File getNoBackupFilesDir() { return directory; }
        @Override public SharedPreferences getSharedPreferences(String name, int mode) {
            String isolatedName = prefix + name; preferenceNames.add(isolatedName);
            return getBaseContext().getSharedPreferences(isolatedName, mode);
        }
        void cleanup() throws IOException {
            for (String name : preferenceNames) {
                // Drain this namespace's pending apply() writes before deleting it.
                getBaseContext().getSharedPreferences(name, Context.MODE_PRIVATE).edit().clear().commit();
                getBaseContext().deleteSharedPreferences(name);
            }
            remove(directory);
        }
        private static void remove(File file) throws IOException {
            if (file.isDirectory()) {
                File[] children = file.listFiles();
                if (children == null) throw new IOException("Cannot enumerate own test directory");
                for (File child : children) remove(child);
            }
            if (!file.delete() && file.exists()) throw new IOException("Cannot delete own test file");
        }
    }
}

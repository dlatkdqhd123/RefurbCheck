package io.github.refurbcheck;

import android.annotation.TargetApi;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;

/** Version-guarded metadata collection. Installer names are not trust anchors. */
public final class PackageProvenance {
    private static final int MAX_CERTIFICATES = 32, MAX_CERTIFICATE_BYTES = 64 * 1024;
    private PackageProvenance() { }

    /** Retains v1.2 current-signer/installer fields for existing APK checks. */
    @SuppressWarnings("deprecation")
    public static void collect(PackageManager pm, PackageInfo info, JSONObject row) throws JSONException {
        JSONObject signing = emptySigning("UNAVAILABLE");
        try {
            if (Build.VERSION.SDK_INT >= 28) signing = Api28.signing(info.signingInfo);
            else {
                signing.put("signingMode", "LEGACY");
                signing.put("signingHistoryStatus", "UNSUPPORTED_API");
                JSONArray current = digests(info.signatures);
                signing.put("signingSha256", current).put("signingReadable", true);
            }
        } catch (Exception | LinkageError error) { signing.put("signingError", error.getClass().getSimpleName()); }
        for (String key : new String[]{"signingSha256", "signingReadable", "signingMode",
                "signingHistorySha256", "signingHistoryReadable", "signingHistoryStatus", "signingError"}) {
            if (signing.has(key)) row.put(key, signing.get(key));
        }
        row.put("signingMetadataSource", "OS_REPORTED; not an independent APK signature verification");

        JSONObject source = new JSONObject();
        source.put("schema", "refurbcheck-install-provenance-v1");
        source.put("apiLevel", Build.VERSION.SDK_INT);
        source.put("evidenceSource", "OS_REPORTED");
        source.put("authenticatedDistribution", false);
        source.put("queryStatus", "NOT_QUERIED");
        source.put("installingPackageName", JSONObject.NULL).put("installingPackageStatus", "UNAVAILABLE");
        source.put("initiatingPackageName", JSONObject.NULL).put("initiatingPackageStatus", "UNSUPPORTED_API");
        source.put("initiatingPackageSigningInfo", emptySigning(Build.VERSION.SDK_INT >= 30 ? "UNAVAILABLE" : "UNSUPPORTED_API"));
        source.put("packageSource", JSONObject.NULL).put("packageSourceStatus", "UNSUPPORTED_API");
        source.put("updateOwnerPackageName", JSONObject.NULL).put("updateOwnerPackageStatus", "UNSUPPORTED_API");
        // The originating name is installer-supplied, unverified, and restricted
        // to INSTALL_PACKAGES callers. Do not request that privileged permission.
        source.put("originatingPackageStatus", "NOT_REQUESTED_RESTRICTED_UNVERIFIED");
        try {
            if (Build.VERSION.SDK_INT >= 30) Api30.collect(pm, info.packageName, source);
            else {
                putName(source, "installingPackage", pm.getInstallerPackageName(info.packageName));
                source.put("queryStatus", "LEGACY_API");
            }
        } catch (Exception | LinkageError error) {
            source.put("queryStatus", "ERROR").put("queryError", error.getClass().getSimpleName());
            source.put("installingPackageStatus", "ERROR");
            if (Build.VERSION.SDK_INT >= 30) source.put("initiatingPackageStatus", "ERROR");
            if (Build.VERSION.SDK_INT >= 33) source.put("packageSourceStatus", "ERROR");
            if (Build.VERSION.SDK_INT >= 34) source.put("updateOwnerPackageStatus", "ERROR");
        }
        boolean knownInstaller = "KNOWN".equals(source.opt("installingPackageStatus"));
        row.put("installer", knownInstaller ? source.optString("installingPackageName", "") : "");
        row.put("installerReadable", knownInstaller);
        row.put("installProvenance", source);
    }

    private static JSONObject emptySigning(String status) throws JSONException {
        return new JSONObject().put("signingSha256", new JSONArray()).put("signingReadable", false)
                .put("signingMode", "UNKNOWN").put("signingHistorySha256", new JSONArray())
                .put("signingHistoryReadable", false).put("signingHistoryStatus", status);
    }

    private static void putName(JSONObject out, String key, String value) throws JSONException {
        if (value == null || value.isEmpty()) {
            out.put(key + "Name", JSONObject.NULL).put(key + "Status", "NOT_AVAILABLE");
        } else if (value.length() > 255 || !value.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)*")) {
            out.put(key + "Name", JSONObject.NULL).put(key + "Status", "INVALID_METADATA");
        } else out.put(key + "Name", value).put(key + "Status", "KNOWN");
    }

    private static JSONArray digests(Signature[] signatures) throws Exception {
        if (signatures == null || signatures.length == 0 || signatures.length > MAX_CERTIFICATES)
            throw new IOException("Signer array missing or outside bounds");
        JSONArray values = new JSONArray(); Set<String> unique = new HashSet<>();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (Signature signature : signatures) {
            if (signature == null) throw new IOException("Null signing certificate");
            byte[] bytes = signature.toByteArray();
            if (bytes.length == 0 || bytes.length > MAX_CERTIFICATE_BYTES)
                throw new IOException("Signing certificate outside bounds");
            StringBuilder hash = new StringBuilder(64);
            for (byte value : digest.digest(bytes)) {
                hash.append(Character.forDigit((value >>> 4) & 15, 16));
                hash.append(Character.forDigit(value & 15, 16));
            }
            if (!unique.add(hash.toString())) throw new IOException("Duplicate signing certificate");
            values.put(hash.toString());
        }
        return values;
    }

    @TargetApi(28)
    private static final class Api28 {
        static JSONObject signing(SigningInfo info) throws JSONException {
            JSONObject out = emptySigning("UNAVAILABLE");
            if (info == null) return out;
            try {
                boolean multiple = info.hasMultipleSigners();
                // Keep current signers separate from the full authorization
                // history. Both are needed for inventory and rotation analysis.
                JSONArray current = digests(info.getApkContentsSigners());
                if (multiple ? current.length() < 2 : current.length() != 1)
                    throw new IOException("Inconsistent signer count");
                out.put("signingSha256", current).put("signingReadable", true)
                        .put("signingMode", multiple ? "MULTIPLE" : "SINGLE");
                if (multiple) {
                    out.put("signingHistoryStatus", "NOT_APPLICABLE_MULTIPLE_SIGNERS");
                } else {
                    try {
                        JSONArray history = digests(info.getSigningCertificateHistory());
                        if (!current.getString(0).equals(history.getString(history.length() - 1)))
                            throw new IOException("History does not end at current signer");
                        out.put("signingHistorySha256", history).put("signingHistoryReadable", true)
                                .put("signingHistoryStatus", "COLLECTED");
                    } catch (Exception | LinkageError error) {
                        out.put("signingHistoryStatus", "ERROR_OR_INCONSISTENT")
                                .put("signingError", error.getClass().getSimpleName());
                    }
                }
            } catch (Exception | LinkageError error) {
                out.put("signingError", error.getClass().getSimpleName());
            }
            return out;
        }
    }

    @TargetApi(30)
    private static final class Api30 {
        static void collect(PackageManager pm, String packageName, JSONObject out) throws Exception {
            InstallSourceInfo source = pm.getInstallSourceInfo(packageName);
            if (source == null) throw new IOException("Null install-source response");
            out.put("queryStatus", "COLLECTED");
            putName(out, "installingPackage", source.getInstallingPackageName());
            putName(out, "initiatingPackage", source.getInitiatingPackageName());
            try { out.put("initiatingPackageSigningInfo", Api28.signing(source.getInitiatingPackageSigningInfo())); }
            catch (Exception | LinkageError error) {
                JSONObject failed = emptySigning("ERROR");
                failed.put("signingError", error.getClass().getSimpleName());
                out.put("initiatingPackageSigningInfo", failed);
            }
            if ("KNOWN".equals(out.opt("installingPackageStatus")) && "KNOWN".equals(out.opt("initiatingPackageStatus")))
                out.put("installerDiffersFromInitiator", !out.getString("installingPackageName").equals(out.getString("initiatingPackageName")));
            if (Build.VERSION.SDK_INT >= 33) Api33.collect(source, out);
            if (Build.VERSION.SDK_INT >= 34) Api34.collect(source, out);
        }
    }

    @TargetApi(33)
    private static final class Api33 {
        static void collect(InstallSourceInfo source, JSONObject out) throws JSONException {
            try {
                int value = source.getPackageSource(); String name;
                switch (value) {
                    case PackageInstaller.PACKAGE_SOURCE_UNSPECIFIED: name = "UNSPECIFIED"; break;
                    case PackageInstaller.PACKAGE_SOURCE_STORE: name = "STORE"; break;
                    case PackageInstaller.PACKAGE_SOURCE_LOCAL_FILE: name = "LOCAL_FILE"; break;
                    case PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE: name = "DOWNLOADED_FILE"; break;
                    case PackageInstaller.PACKAGE_SOURCE_OTHER: name = "OTHER"; break;
                    default: name = "UNRECOGNIZED"; break;
                }
                out.put("packageSource", value).put("packageSourceName", name)
                        .put("packageSourceStatus", "UNRECOGNIZED".equals(name) ? "UNKNOWN_ENUM" : "COLLECTED");
            } catch (Exception | LinkageError error) {
                out.put("packageSourceStatus", "ERROR").put("packageSourceError", error.getClass().getSimpleName());
            }
        }
    }

    @TargetApi(34)
    private static final class Api34 {
        static void collect(InstallSourceInfo source, JSONObject out) throws JSONException {
            try { putName(out, "updateOwnerPackage", source.getUpdateOwnerPackageName()); }
            catch (Exception | LinkageError error) {
                out.put("updateOwnerPackageStatus", "ERROR").put("updateOwnerPackageError", error.getClass().getSimpleName());
            }
        }
    }
}

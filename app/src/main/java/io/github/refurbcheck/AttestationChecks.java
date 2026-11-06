package io.github.refurbcheck;

import java.security.MessageDigest;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.YearMonth;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Pure decision rules. Matching local observations is evidence consistency, not remote trust. */
public final class AttestationChecks {
    private AttestationChecks() { }

    public enum ApplicationBinding {
        MATCH, MISSING, MISPLACED_ENFORCEMENT, EXPECTATION_UNAVAILABLE,
        SHARED_UID_UNSUPPORTED, PACKAGE_MISMATCH, VERSION_MISMATCH, SIGNER_MISMATCH
    }

    public static ApplicationBinding bindApplication(AttestationRecord record, String expectedPackage,
            long expectedVersion, List<byte[]> expectedSigners, boolean exclusiveUid) {
        if (record.hardwareApplicationIdPresent) return ApplicationBinding.MISPLACED_ENFORCEMENT;
        if (record.applicationId == null) return ApplicationBinding.MISSING;
        if (expectedPackage == null || expectedPackage.isEmpty() || expectedVersion < 0
                || !validExpectedSigners(expectedSigners)) return ApplicationBinding.EXPECTATION_UNAVAILABLE;
        if (!exclusiveUid || record.applicationId.packages.size() != 1)
            return ApplicationBinding.SHARED_UID_UNSUPPORTED;
        AttestationRecord.PackageIdentity identity = record.applicationId.packages.get(0);
        if (!identity.packageName.equals(expectedPackage)) return ApplicationBinding.PACKAGE_MISMATCH;
        if (identity.versionCode != expectedVersion) return ApplicationBinding.VERSION_MISMATCH;
        if (!sameDigestSet(expectedSigners, record.applicationId.signerSha256)) return ApplicationBinding.SIGNER_MISMATCH;
        return ApplicationBinding.MATCH;
    }

    private static boolean validExpectedSigners(List<byte[]> values) {
        if (values == null || values.isEmpty() || values.size() > 32) return false;
        for (int i = 0; i < values.size(); i++) {
            if (values.get(i) == null || values.get(i).length != 32) return false;
            for (int j = 0; j < i; j++) if (MessageDigest.isEqual(values.get(i), values.get(j))) return false;
        }
        return true;
    }

    public static boolean sameDigestSet(List<byte[]> expected, List<byte[]> actual) {
        if (!validExpectedSigners(expected) || !validExpectedSigners(actual) || expected.size() != actual.size()) return false;
        for (byte[] digest : expected) {
            boolean found = false;
            for (byte[] other : actual) found |= MessageDigest.isEqual(digest, other);
            if (!found) return false;
        }
        return true;
    }

    public static boolean requestBound(byte[] challenge, byte[] generatedPublicKey,
            byte[] attestedPublicKey, AttestationRecord record, boolean possessionVerified) {
        return challenge != null && challenge.length == 32 && MessageDigest.isEqual(challenge, record.challenge)
                && generatedPublicKey != null && generatedPublicKey.length > 0 && attestedPublicKey != null
                && MessageDigest.isEqual(generatedPublicKey, attestedPublicKey) && possessionVerified;
    }

    /** This result must never be promoted to full attestation trust or a PASS status. */
    public static boolean supportsLocalHardwareEvidence(boolean chainValid, boolean requestBound,
            boolean appBound, boolean hardwareBacked, boolean knownRevokedOrSuspended) {
        return chainValid && requestBound && appBound && hardwareBacked && !knownRevokedOrSuspended;
    }

    public enum ComparisonState { MATCH, MISMATCH, NOT_COMPARABLE }

    public static final class Comparison {
        public final String field, attested, observed, explanation;
        public final ComparisonState state;
        private Comparison(String field, String attested, String observed, ComparisonState state, String explanation) {
            this.field = field; this.attested = attested; this.observed = observed;
            this.state = state; this.explanation = explanation;
        }
    }

    public static List<Comparison> correlate(AttestationRecord record, String androidRelease,
            String securityPatch, Map<String, String> properties) {
        List<Comparison> results = new ArrayList<>();
        Long release = androidVersion(androidRelease);
        Long hardwareVersion = record.hardwareOsVersion;
        if (hardwareVersion != null && (hardwareVersion < 10000 || hardwareVersion > 999999)) hardwareVersion = null;
        results.add(compare("androidRelease", text(record.hardwareOsVersion), androidRelease,
                hardwareVersion, release, "MMmmss 형식의 OS 버전 비교"));
        Long patchMonth = patchMonth(record.hardwareOsPatchLevel);
        LocalDate buildDate = date(securityPatch);
        Long observedMonth = buildDate == null ? null : buildDate.getYear() * 100L + buildDate.getMonthValue();
        results.add(compare("securityPatchMonth", text(record.hardwareOsPatchLevel), securityPatch,
                patchMonth, observedMonth, "OS 증명은 연월 단위이므로 패치 날짜의 일자는 비교하지 않음"));
        compareDay(results, "vendorPatchLevel", record.vendorPatchLevel, property(properties, "ro.vendor.build.security_patch"));
        compareDay(results, "bootPatchLevel", record.bootPatchLevel, property(properties, "ro.bootimage.build.version.security_patch"));
        AttestationRecord.RootOfTrust root = record.hardwareRoot;
        String bootProperty = property(properties, "ro.boot.verifiedbootstate");
        Long observedBoot = bootState(bootProperty);
        results.add(compare("verifiedBootState", root == null ? "" : Integer.toString(root.verifiedBootState),
                bootProperty, root == null ? null : (long) root.verifiedBootState, observedBoot,
                "RootOfTrust와 OS가 반환한 Verified Boot 속성 비교"));
        String flashLocked = property(properties, "ro.boot.flash.locked");
        results.add(compare("flashLocked", root == null ? "" : Boolean.toString(root.deviceLocked), flashLocked,
                root == null ? null : root.deviceLocked ? 1L : 0L,
                lockValue(flashLocked, "1", "0"),
                "하드웨어 증명과 OS의 flash.locked 속성 비교"));
        String vbmetaLocked = property(properties, "ro.boot.vbmeta.device_state");
        results.add(compare("vbmetaDeviceState", root == null ? "" : Boolean.toString(root.deviceLocked), vbmetaLocked,
                root == null ? null : root.deviceLocked ? 1L : 0L,
                lockValue(vbmetaLocked, "locked", "unlocked"),
                "하드웨어 증명과 OS의 vbmeta.device_state 속성 비교"));
        return results;
    }

    /** Exact non-unique property comparisons; software-enforced values never substitute for hardware. */
    public static List<Comparison> correlateDeviceProperties(AttestationRecord record,
            Map<String, String> observedProperties) {
        List<Comparison> results = new ArrayList<>();
        for (String field : AttestationRecord.DeviceProperties.NAMES) {
            String attested = record.hardwareDeviceProperties.get(field);
            String observed = observedProperties == null ? null : observedProperties.get(field);
            boolean comparable = usableDeviceProperty(attested) && usableDeviceProperty(observed);
            ComparisonState state = !comparable ? ComparisonState.NOT_COMPARABLE
                    : attested.equals(observed) ? ComparisonState.MATCH : ComparisonState.MISMATCH;
            String explanation = "하드웨어 영역의 비고유 기기 속성과 Build 관측값을 대소문자 포함 그대로 비교";
            if (record.softwareDeviceProperties.get(field) != null)
                explanation = "소프트웨어 영역의 속성은 하드웨어 기기 신원 증거로 대체하지 않음";
            results.add(new Comparison("device." + field, attested == null ? "" : attested,
                    observed == null ? "" : observed, state, explanation));
        }
        return results;
    }

    private static boolean usableDeviceProperty(String value) {
        if (value == null || value.length() > 512 || value.trim().isEmpty()
                || "unknown".equalsIgnoreCase(value.trim()) || "null".equalsIgnoreCase(value.trim())) return false;
        for (int i = 0; i < value.length(); i++) if (Character.isISOControl(value.charAt(i))) return false;
        return true;
    }

    private static void compareDay(List<Comparison> results, String field, Long attested, String observed) {
        LocalDate hardwareDate = attested == null ? null : compactDate(attested);
        LocalDate osDate = date(observed);
        results.add(compare(field, text(attested), observed,
                hardwareDate == null ? null : hardwareDate.toEpochDay(),
                osDate == null ? null : osDate.toEpochDay(), "유효한 날짜 형식일 때만 일자 단위 비교"));
    }

    private static Comparison compare(String field, String attested, String observed,
            Long normalizedAttested, Long normalizedObserved, String explanation) {
        ComparisonState state = normalizedAttested == null || normalizedObserved == null ? ComparisonState.NOT_COMPARABLE
                : normalizedAttested.equals(normalizedObserved) ? ComparisonState.MATCH : ComparisonState.MISMATCH;
        return new Comparison(field, attested, observed == null ? "" : observed, state, explanation);
    }

    private static String property(Map<String, String> properties, String name) {
        String value = properties == null ? null : properties.get(name);
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
    private static String text(Long value) { return value == null ? "" : value.toString(); }
    private static Long bootState(String value) {
        if ("green".equals(value)) return 0L;
        if ("yellow".equals(value)) return 1L;
        if ("orange".equals(value)) return 2L;
        if ("red".equals(value)) return 3L;
        return null;
    }
    private static Long lockValue(String value, String locked, String unlocked) {
        if (locked.equals(value)) return 1L;
        if (unlocked.equals(value)) return 0L;
        return null;
    }
    private static Long androidVersion(String value) {
        if (value == null || !value.matches("[1-9][0-9]?(\\.[0-9]{1,2}){0,2}")) return null;
        String[] fields = value.split("\\.");
        return Long.parseLong(fields[0]) * 10000
                + (fields.length > 1 ? Long.parseLong(fields[1]) * 100 : 0)
                + (fields.length > 2 ? Long.parseLong(fields[2]) : 0);
    }
    private static Long patchMonth(Long value) {
        if (value == null || value < 200001 || value > 999912) return null;
        try { YearMonth.of((int) (value / 100), (int) (value % 100)); return value; }
        catch (DateTimeException exception) { return null; }
    }
    private static LocalDate compactDate(long value) {
        if (value < 20000101 || value > 99991231) return null;
        try { return LocalDate.of((int) (value / 10000), (int) ((value / 100) % 100), (int) (value % 100)); }
        catch (DateTimeException exception) { return null; }
    }
    private static LocalDate date(String value) {
        if (value == null || !value.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}")) return null;
        try { return LocalDate.parse(value); }
        catch (DateTimeException exception) { return null; }
    }
}

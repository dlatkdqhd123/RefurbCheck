package io.github.refurbcheck;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/** Host regression tests for malformed input and trust-boundary failures. No phone or private keys required. */
public final class AttestationTests {
    private static int assertions;
    private interface Checked { void run() throws Exception; }
    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
    private static void rejects(Class<? extends Exception> type, Checked code, String message) throws Exception {
        assertions++;
        try { code.run(); }
        catch (Exception exception) {
            if (type.isInstance(exception)) return;
            throw new AssertionError(message + ": wrong exception " + exception.getClass().getName(), exception);
        }
        throw new AssertionError(message + ": accepted invalid input");
    }
    private static byte[] join(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) out.write(part, 0, part.length);
        return out.toByteArray();
    }
    private static byte[] tlv(byte[] tag, byte[] payload) {
        byte[] length = payload.length < 128 ? new byte[]{(byte) payload.length}
                : payload.length < 256 ? new byte[]{(byte) 0x81, (byte) payload.length}
                : new byte[]{(byte) 0x82, (byte) (payload.length >>> 8), (byte) payload.length};
        return join(tag, length, payload);
    }
    private static byte[] tlv(int tag, byte[] payload) { return tlv(new byte[]{(byte) tag}, payload); }
    private static byte[] integer(long value) { return tlv(2, BigInteger.valueOf(value).toByteArray()); }
    private static byte[] enumerated(int value) { return tlv(10, new byte[]{(byte) value}); }
    private static byte[] tagged(int suffix, byte[] payload) {
        return tlv(new byte[]{(byte) 0xbf, (byte) 0x85, (byte) suffix}, payload);
    }
    private static byte[] root(boolean locked, int state, boolean nonzero, boolean includeHash) {
        byte[] key = new byte[32];
        byte[] hash = new byte[32]; hash[0] = 2;
        if (nonzero) key[0] = 1;
        return tagged(0x40, tlv(0x30, join(tlv(4, key), tlv(1, new byte[]{locked ? (byte) 0xff : 0}),
                enumerated(state), includeHash ? tlv(4, hash) : new byte[0])));
    }
    private static byte[] record(int level, int keyLevel, byte[] software, byte[] hardware, byte[] challenge) {
        return recordVersion(300, 300, level, keyLevel, software, hardware, challenge);
    }
    private static byte[] recordVersion(long version, long keyVersion, int level, int keyLevel,
            byte[] software, byte[] hardware, byte[] challenge) {
        return tlv(4, tlv(0x30, join(integer(version), enumerated(level), integer(keyVersion), enumerated(keyLevel),
                tlv(4, challenge), tlv(4, new byte[0]), tlv(0x30, software), tlv(0x30, hardware))));
    }
    private static byte[] record(int level, int keyLevel, byte[] software, byte[] hardware) {
        return record(level, keyLevel, software, hardware, new byte[32]);
    }

    private static void testDer() throws Exception {
        byte[] none = new byte[0];
        byte[] boot = root(true, 0, true, true);
        byte[] good = record(1, 1, none, join(boot, tagged(0x42, integer(202611)),
                tagged(0x4e, integer(20261105)), tagged(0x4f, integer(20261105))));
        AttestationRecord value = AttestationRecord.parseExtension(good);
        check(value.hardwareBacked(), "TEE levels accepted");
        check(value.hardwareRoot != null && value.hardwareRoot.deviceLocked, "hardware root read");
        check(value.hardwareRoot.verifiedBootState == 0, "Verified state parsed");
        check(value.hardwareRoot.hasNonzeroBootKey(), "nonzero boot digest observed");
        check(value.hardwareOsPatchLevel == 202611L, "high-tag OS patch parsed");
        check(value.vendorPatchLevel == 20261105L && value.bootPatchLevel == 20261105L, "patch tags parsed");
        check(value.challenge.length == 32, "challenge preserved");
        AttestationRecord onlySoftware = AttestationRecord.parseExtension(record(1, 1, boot, none));
        check(onlySoftware.hardwareRoot == null && onlySoftware.softwareRootPresent, "software RootOfTrust cannot replace hardware");
        check(!AttestationRecord.parseExtension(record(0, 1, none, boot)).hardwareBacked(), "software attestation level rejected");
        check(!AttestationRecord.parseExtension(record(1, 0, none, boot)).hardwareBacked(), "software key level rejected");
        check(AttestationRecord.parseExtension(record(2, 2, none, boot)).hardwareBacked(), "StrongBox levels parsed");
        check(!AttestationRecord.parseExtension(record(1, 1, none, root(true, 0, false, true))).hardwareRoot.hasNonzeroBootKey(), "all-zero digest remains unusable");
        check(AttestationRecord.parseExtension(recordVersion(2, 3, 1, 1, none, root(true, 0, true, false), new byte[32])).hardwareRoot.verifiedBootHash == null, "version 2 no-hash RootOfTrust represented as absent");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(1, 1, none, root(true, 0, true, false))), "modern RootOfTrust must contain a hash field");
        check(value.hardwareRoot.hasRecognizedBootDigests(value.attestationVersion), "standard nonzero boot digests accepted as local evidence");
        byte[] tinyKey = tagged(0x40, tlv(0x30, join(tlv(4, new byte[]{1}), tlv(1, new byte[]{(byte) 0xff}), enumerated(0), tlv(4, new byte[32]))));
        check(!AttestationRecord.parseExtension(record(1, 1, none, tinyKey)).hardwareRoot.hasRecognizedBootDigests(300), "one-byte boot key cannot support Verified evidence");
        byte[] recognizedKey = new byte[32]; recognizedKey[0] = 1;
        byte[] zeroHash = tagged(0x40, tlv(0x30, join(tlv(4, recognizedKey), tlv(1, new byte[]{(byte) 0xff}), enumerated(0), tlv(4, new byte[32]))));
        check(!AttestationRecord.parseExtension(record(1, 1, none, zeroHash)).hardwareRoot.hasRecognizedBootDigests(300), "zero boot-image hash cannot support Verified evidence despite nonzero key");
        check(value.recognizedVersionPair(), "known KeyMint version pair accepted");
        check(!AttestationRecord.parseExtension(recordVersion(300, 200, 1, 1, none, boot, new byte[32])).recognizedVersionPair(), "inconsistent KeyMint version pair not supported");
        check(!AttestationRecord.parseExtension(recordVersion(600, 600, 1, 1, none, boot, new byte[32])).recognizedVersionPair(), "future schema requires explicit support");
        check(!AttestationRecord.parseExtension(recordVersion(2, 3, 2, 2, none, root(true, 0, true, false), new byte[32])).recognizedVersionPair(), "legacy schema cannot claim StrongBox");
        check(AttestationRecord.parseExtension(record(1, 1, none, root(false, 2, false, true))).hardwareRoot.verifiedBootState == 2, "unverified state retained");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(1, 1, none, join(boot, boot))), "duplicate hardware root");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(1, 1, join(boot, boot), none)), "duplicate software root");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(1, 1, none, root(true, 4, true, true))), "unknown boot state");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(3, 1, none, boot)), "unknown security level");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(1, 1, none, boot, new byte[129])), "oversized challenge");
        rejects(IOException.class, () -> DerReader.single(new byte[]{0x30, (byte) 0x80, 0, 0}), "indefinite length");
        rejects(IOException.class, () -> DerReader.single(new byte[]{4, (byte) 0x81, 0}), "non-minimal length");
        rejects(IOException.class, () -> DerReader.single(new byte[]{4, (byte) 0x82, 0, (byte) 0x80}), "leading-zero long length");
        rejects(IOException.class, () -> DerReader.single(new byte[]{(byte) 0xbf, (byte) 0x80, (byte) 0x85, 0x40, 0}), "non-minimal high tag");
        rejects(IOException.class, () -> DerReader.single(new byte[]{(byte) 0xbf, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x7f, 0}), "tag overflow");
        rejects(IOException.class, () -> DerReader.single(tlv(1, new byte[]{1})).bool(), "noncanonical boolean");
        rejects(IOException.class, () -> DerReader.single(tlv(2, new byte[]{(byte) 0xff})).unsigned(2), "negative integer");
        rejects(IOException.class, () -> DerReader.single(tlv(2, new byte[]{0, 1})).unsigned(2), "overlong integer");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(join(good, new byte[]{0})), "trailing extension bytes");
        rejects(IOException.class, () -> DerReader.single(new byte[DerReader.MAX_BYTES + 1]), "size cap");
        for (int cut = 0; cut < good.length; cut++) {
            final byte[] truncated = Arrays.copyOf(good, cut);
            rejects(IOException.class, () -> AttestationRecord.parseExtension(truncated), "truncated valid packet at " + cut);
        }
        Random random = new Random(0xA77E57);
        for (int i = 0; i < 2000; i++) {
            byte[] fuzz = new byte[random.nextInt(160)]; random.nextBytes(fuzz);
            try { AttestationRecord.parseExtension(fuzz); } catch (IOException expected) { }
        }
        check(true, "2,000 malformed packets did not trigger unchecked failures");
    }

    private static byte[] packageInfo(String name, long version) {
        return tlv(0x30, join(tlv(4, name.getBytes(StandardCharsets.UTF_8)), integer(version)));
    }
    private static byte[] canonicalSet(byte[]... members) {
        List<byte[]> values = new ArrayList<>(Arrays.asList(members));
        values.sort((a, b) -> {
            for (int i = 0; i < Math.min(a.length, b.length); i++) {
                int delta = (a[i] & 255) - (b[i] & 255); if (delta != 0) return delta;
            }
            return a.length - b.length;
        });
        return tlv(0x31, join(values.toArray(new byte[0][])));
    }
    private static byte[] application(byte[] packages, byte[] signers) {
        return tagged(0x45, tlv(4, tlv(0x30, join(packages, signers))));
    }
    private static AttestationRecord withApplication(byte[] id) throws Exception {
        return AttestationRecord.parseExtension(record(1, 1, id, root(true, 0, true, true)));
    }
    private static void testApplicationAndBinding() throws Exception {
        String own = "io.github.refurbcheck";
        byte[] signer = new byte[32]; signer[0] = 11;
        byte[] other = new byte[32]; other[0] = 22;
        byte[] packages = canonicalSet(packageInfo(own, 2));
        byte[] signers = canonicalSet(tlv(4, signer));
        byte[] app = application(packages, signers);
        AttestationRecord valid = withApplication(app);
        check(valid.applicationId.packages.get(0).packageName.equals(own), "application package name parsed");
        check(valid.applicationId.packages.get(0).versionCode == 2, "application version parsed");
        check(AttestationChecks.bindApplication(valid, own, 2, Arrays.asList(signer), true) == AttestationChecks.ApplicationBinding.MATCH, "exact application binding");
        check(AttestationChecks.bindApplication(valid, own, 3, Arrays.asList(signer), true) == AttestationChecks.ApplicationBinding.VERSION_MISMATCH, "installed version must match attested version");
        check(AttestationChecks.bindApplication(valid, "io.github.unapproved", 2, Arrays.asList(signer), true) == AttestationChecks.ApplicationBinding.PACKAGE_MISMATCH, "different package not accepted");
        check(AttestationChecks.bindApplication(valid, own, 2, Arrays.asList(other), true) == AttestationChecks.ApplicationBinding.SIGNER_MISMATCH, "different signing certificate not accepted");
        check(AttestationChecks.bindApplication(valid, own, 2, Arrays.asList(signer), false) == AttestationChecks.ApplicationBinding.SHARED_UID_UNSUPPORTED, "shared UID expectation is not silently trusted");
        check(AttestationChecks.bindApplication(valid, own, 2, null, true) == AttestationChecks.ApplicationBinding.EXPECTATION_UNAVAILABLE, "missing expected signers is unknown");
        check(AttestationChecks.bindApplication(withApplication(new byte[0]), own, 2, Arrays.asList(signer), true) == AttestationChecks.ApplicationBinding.MISSING, "missing [709] is not matched");
        AttestationRecord multiplePackages = withApplication(application(canonicalSet(packageInfo(own, 2), packageInfo("io.github.peer", 1)), signers));
        check(AttestationChecks.bindApplication(multiplePackages, own, 2, Arrays.asList(signer), true) == AttestationChecks.ApplicationBinding.SHARED_UID_UNSUPPORTED, "own package inside larger app set is insufficient");
        AttestationRecord multipleSigners = withApplication(application(packages, canonicalSet(tlv(4, signer), tlv(4, other))));
        check(AttestationChecks.bindApplication(multipleSigners, own, 2, Arrays.asList(signer), true) == AttestationChecks.ApplicationBinding.SIGNER_MISMATCH, "unexpected extra signer is not ignored");
        check(AttestationChecks.bindApplication(multipleSigners, own, 2, Arrays.asList(other, signer), true) == AttestationChecks.ApplicationBinding.MATCH, "exact signer set can be in different order");
        long longVersion = 0x100000002L;
        AttestationRecord largeVersion = withApplication(application(canonicalSet(packageInfo(own, longVersion)), signers));
        check(AttestationChecks.bindApplication(largeVersion, own, longVersion, Arrays.asList(signer), true) == AttestationChecks.ApplicationBinding.MATCH, "long version code preserved");
        check(AttestationChecks.bindApplication(largeVersion, own, 2, Arrays.asList(signer), true) == AttestationChecks.ApplicationBinding.VERSION_MISMATCH, "long version code cannot truncate to old version");
        AttestationRecord misplaced = AttestationRecord.parseExtension(record(1, 1, new byte[0], join(root(true, 0, true, true), app)));
        check(AttestationChecks.bindApplication(misplaced, own, 2, Arrays.asList(signer), true) == AttestationChecks.ApplicationBinding.MISPLACED_ENFORCEMENT, "hardware [709] does not replace software identity");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(1, 1, app, join(root(true, 0, true, true), app))), "duplicate application ID across lists");
        rejects(IOException.class, () -> withApplication(join(app, app)), "duplicate [709] tag");
        rejects(IOException.class, () -> withApplication(application(canonicalSet(packageInfo(own, 2), packageInfo(own, 3)), signers)), "duplicate package with different version");
        rejects(IOException.class, () -> withApplication(application(canonicalSet(packageInfo(own, 2), packageInfo(own, 2)), signers)), "duplicate package set member");
        rejects(IOException.class, () -> withApplication(application(packages, canonicalSet(tlv(4, signer), tlv(4, signer)))), "duplicate signer set member");
        rejects(IOException.class, () -> withApplication(application(tlv(0x30, packageInfo(own, 2)), signers)), "package infos must be a SET");
        rejects(IOException.class, () -> withApplication(application(packages, tlv(0x30, tlv(4, signer)))), "signature digests must be a SET");
        rejects(IOException.class, () -> withApplication(application(canonicalSet(), signers)), "empty packages");
        rejects(IOException.class, () -> withApplication(application(packages, canonicalSet())), "empty signer set");
        rejects(IOException.class, () -> withApplication(application(packages, canonicalSet(tlv(4, new byte[31])))), "short SHA-256 signer");
        rejects(IOException.class, () -> withApplication(application(packages, canonicalSet(tlv(4, new byte[64])))), "long SHA-256 signer");
        rejects(IOException.class, () -> withApplication(application(canonicalSet(tlv(0x30, join(tlv(4, new byte[]{(byte) 0xc3, 0x28}), integer(2)))), signers)), "malformed UTF-8 name");
        rejects(IOException.class, () -> withApplication(application(canonicalSet(packageInfo("", 2)), signers)), "empty package name");
        rejects(IOException.class, () -> withApplication(application(canonicalSet(packageInfo("io.github.\u0000refurbcheck", 2)), signers)), "embedded NUL package name");
        rejects(IOException.class, () -> withApplication(application(canonicalSet(tlv(0x30, join(tlv(4, own.getBytes(StandardCharsets.UTF_8)), tlv(4, new byte[]{2})))), signers)), "wrong version type");
        rejects(IOException.class, () -> withApplication(application(canonicalSet(packageInfo(own, -1)), signers)), "negative version");
        rejects(IOException.class, () -> withApplication(tagged(0x45, tlv(0x30, join(packages, signers)))), "application ID must have OCTET wrapper");
        rejects(IOException.class, () -> withApplication(tagged(0x45, tlv(4, join(tlv(0x30, join(packages, signers)), new byte[]{0})))), "trailing application ID bytes");
        rejects(IOException.class, () -> withApplication(tagged(0x45, tlv(4, new byte[1025]))), "application ID 1 KiB limit");
        rejects(IOException.class, () -> withApplication(application(packages, tlv(0x31, join(tlv(4, other), tlv(4, signer))))), "noncanonical SET ordering");

        byte[] publicKey = new byte[]{1, 2, 3};
        check(AttestationChecks.requestBound(new byte[32], publicKey, publicKey, valid, true), "challenge, public key and possession all bind");
        byte[] newChallenge = new byte[32]; newChallenge[0] = 1;
        check(!AttestationChecks.requestBound(newChallenge, publicKey, publicKey, valid, true), "replayed challenge cannot bind");
        check(!AttestationChecks.requestBound(new byte[32], publicKey, new byte[]{1, 2, 4}, valid, true), "different attested key cannot bind");
        check(!AttestationChecks.requestBound(new byte[32], publicKey, publicKey, valid, false), "failed possession cannot bind");
        check(!AttestationChecks.requestBound(new byte[0], publicKey, publicKey, valid, true), "empty expected challenge cannot bind");
        check(!AttestationChecks.requestBound(new byte[32], new byte[0], new byte[0], valid, true), "empty key pair cannot bind");
        check(AttestationChecks.supportsLocalHardwareEvidence(true, true, true, true, false), "all local prerequisites required");
        for (int missing = 0; missing < 4; missing++) {
            boolean[] flags = {true, true, true, true}; flags[missing] = false;
            check(!AttestationChecks.supportsLocalHardwareEvidence(flags[0], flags[1], flags[2], flags[3], false), "missing local prerequisite " + missing);
        }
        check(!AttestationChecks.supportsLocalHardwareEvidence(true, true, true, true, true), "known revoked key cannot support boot evidence");
    }

    private static AttestationChecks.ComparisonState state(List<AttestationChecks.Comparison> values, String field) {
        for (AttestationChecks.Comparison value : values) if (field.equals(value.field)) return value.state;
        throw new AssertionError("Missing comparison " + field);
    }
    private static void testCorrelations() throws Exception {
        byte[] hardware = join(root(true, 0, true, true), tagged(0x41, integer(150000)), tagged(0x42, integer(202611)),
                tagged(0x4e, integer(20261105)), tagged(0x4f, integer(20261105)));
        AttestationRecord value = AttestationRecord.parseExtension(record(1, 1, new byte[0], hardware));
        Map<String, String> props = new HashMap<>();
        props.put("ro.boot.verifiedbootstate", "green"); props.put("ro.boot.flash.locked", "1");
        props.put("ro.boot.vbmeta.device_state", "locked"); props.put("ro.vendor.build.security_patch", "2026-11-05");
        props.put("ro.bootimage.build.version.security_patch", "2026-11-05");
        List<AttestationChecks.Comparison> matches = AttestationChecks.correlate(value, "15", "2026-11-01", props);
        for (AttestationChecks.Comparison match : matches) check(match.state == AttestationChecks.ComparisonState.MATCH, "equivalent normalized fact " + match.field);
        check(state(AttestationChecks.correlate(value, "15.0.1", "2026-11-05", props), "androidRelease") == AttestationChecks.ComparisonState.MISMATCH, "OS patch version difference visible");
        check(state(AttestationChecks.correlate(value, "15.0.0", "2026-11-30", props), "securityPatchMonth") == AttestationChecks.ComparisonState.MATCH, "month-only attestation never claims exact patch day");
        check(state(AttestationChecks.correlate(value, "15", "2026-10-05", props), "securityPatchMonth") == AttestationChecks.ComparisonState.MISMATCH, "different patch month visible");
        check(state(AttestationChecks.correlate(value, "15 Beta", "2026-02-29", props), "androidRelease") == AttestationChecks.ComparisonState.NOT_COMPARABLE, "preview release text not forced into numeric version");
        check(state(AttestationChecks.correlate(value, "15", "2026-02-29", props), "securityPatchMonth") == AttestationChecks.ComparisonState.NOT_COMPARABLE, "invalid leap-day date not compared");
        props.put("ro.boot.flash.locked", "0");
        List<AttestationChecks.Comparison> lockConflict = AttestationChecks.correlate(value, "15", "2026-11-05", props);
        check(state(lockConflict, "flashLocked") == AttestationChecks.ComparisonState.MISMATCH, "flash lock conflict visible independently");
        check(state(lockConflict, "vbmetaDeviceState") == AttestationChecks.ComparisonState.MATCH, "matching second lock property does not mask first conflict");
        props.put("ro.boot.verifiedbootstate", "red");
        check(state(AttestationChecks.correlate(value, "15", "2026-11-05", props), "verifiedBootState") == AttestationChecks.ComparisonState.MISMATCH, "boot color conflict visible");
        for (AttestationChecks.Comparison item : AttestationChecks.correlate(value, "", "", new HashMap<>()))
            check(item.state == AttestationChecks.ComparisonState.NOT_COMPARABLE, "missing OS observation remains unknown " + item.field);
        AttestationRecord missing = AttestationRecord.parseExtension(record(1, 1, new byte[0], new byte[0]));
        for (AttestationChecks.Comparison item : AttestationChecks.correlate(missing, "15", "2026-11-05", props))
            check(item.state == AttestationChecks.ComparisonState.NOT_COMPARABLE, "missing hardware observation remains unknown " + item.field);
        AttestationRecord invalidMonth = AttestationRecord.parseExtension(record(1, 1, new byte[0], tagged(0x42, integer(202613))));
        check(state(AttestationChecks.correlate(invalidMonth, "15", "2026-11-05", props), "securityPatchMonth") == AttestationChecks.ComparisonState.NOT_COMPARABLE, "invalid attested month not compared");
    }

    private static byte[] deviceProperty(int suffix, String value) {
        return tagged(suffix, tlv(4, utf8(value)));
    }
    private static void testDeviceProperties() throws Exception {
        Map<String, String> observed = new HashMap<>();
        observed.put("brand", "samsung"); observed.put("device", "testdevice");
        observed.put("product", "testproduct"); observed.put("manufacturer", "samsung");
        observed.put("model", "SM-TEST");
        byte[] properties = join(deviceProperty(0x46, "samsung"), deviceProperty(0x47, "testdevice"),
                deviceProperty(0x48, "testproduct"), deviceProperty(0x4c, "samsung"), deviceProperty(0x4d, "SM-TEST"));
        AttestationRecord complete = AttestationRecord.parseExtension(record(1, 1, new byte[0],
                join(root(true, 0, true, true), properties)));
        check(complete.hardwareDeviceProperties.hasAny() && !complete.softwareDeviceProperties.hasAny(),
                "five non-unique device fields retained from hardware only");
        List<AttestationChecks.Comparison> comparisons = AttestationChecks.correlateDeviceProperties(complete, observed);
        check(comparisons.size() == 5, "all five device property comparisons are explicit");
        for (AttestationChecks.Comparison comparison : comparisons)
            check(comparison.state == AttestationChecks.ComparisonState.MATCH, "matching non-unique device field " + comparison.field);
        observed.put("model", "SM-DIFFERENT");
        check(state(AttestationChecks.correlateDeviceProperties(complete, observed), "device.model")
                == AttestationChecks.ComparisonState.MISMATCH, "different attested model not ignored");
        observed.put("model", "sm-test");
        check(state(AttestationChecks.correlateDeviceProperties(complete, observed), "device.model")
                == AttestationChecks.ComparisonState.MISMATCH, "model spelling and case not normalized into false agreement");
        observed.put("model", "unknown");
        check(state(AttestationChecks.correlateDeviceProperties(complete, observed), "device.model")
                == AttestationChecks.ComparisonState.NOT_COMPARABLE, "unknown Build model is not an identity observation");
        observed.put("model", "SM-TEST");
        for (AttestationChecks.Comparison comparison : AttestationChecks.correlateDeviceProperties(complete, null))
            check(comparison.state == AttestationChecks.ComparisonState.NOT_COMPARABLE, "missing Build field is unknown " + comparison.field);
        AttestationRecord missing = AttestationRecord.parseExtension(record(1, 1, new byte[0], new byte[0]));
        for (AttestationChecks.Comparison comparison : AttestationChecks.correlateDeviceProperties(missing, observed))
            check(comparison.state == AttestationChecks.ComparisonState.NOT_COMPARABLE, "missing hardware field cannot pass " + comparison.field);
        AttestationRecord software = AttestationRecord.parseExtension(record(1, 1, properties, new byte[0]));
        check(software.softwareDeviceProperties.hasAny(), "misplaced software fields remain visible");
        for (AttestationChecks.Comparison comparison : AttestationChecks.correlateDeviceProperties(software, observed))
            check(comparison.state == AttestationChecks.ComparisonState.NOT_COMPARABLE, "software property is not hardware identity " + comparison.field);
        AttestationRecord empty = AttestationRecord.parseExtension(record(1, 1, new byte[0], deviceProperty(0x46, "")));
        observed.put("brand", "");
        check(state(AttestationChecks.correlateDeviceProperties(empty, observed), "device.brand")
                == AttestationChecks.ComparisonState.NOT_COMPARABLE, "two empty properties never match");
        observed.put("brand", "samsung");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(1, 1, properties, properties)),
                "duplicate device property across enforcement lists rejected");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(1, 1, new byte[0], join(properties, deviceProperty(0x4d, "SM-OTHER")))),
                "duplicate property tag rejected");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(1, 1, new byte[0], tagged(0x4d, integer(1)))),
                "device property requires OCTET STRING");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(1, 1, new byte[0], tagged(0x4d, tlv(4, new byte[]{(byte) 0xc3, 0x28})))),
                "device property invalid UTF-8 rejected");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(1, 1, new byte[0], deviceProperty(0x4d, "SM-\u0000TEST"))),
                "device property embedded NUL rejected");
        rejects(IOException.class, () -> AttestationRecord.parseExtension(record(1, 1, new byte[0], tagged(0x4d, tlv(4, new byte[513])))),
                "device property size bounded before decoding");
        AttestationRecord unknown = AttestationRecord.parseExtension(record(1, 1, new byte[0], deviceProperty(0x4d, "unknown")));
        observed.put("model", "unknown");
        check(state(AttestationChecks.correlateDeviceProperties(unknown, observed), "device.model")
                == AttestationChecks.ComparisonState.NOT_COMPARABLE, "two unknown models do not establish identity");
    }

    private static byte[] utf8(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static void testRevocations(Path project) throws Exception {
        Path fixtures = project.resolve("tests/attestation-fixtures");
        X509Certificate root = certificate(fixtures.resolve("trusted-root.pem"));
        X509Certificate leaf = certificate(fixtures.resolve("valid-leaf.pem"));
        List<X509Certificate> chain = Arrays.asList(leaf, root);
        String serial = root.getSerialNumber().toString(16);
        long now = 1793923200000L;
        String metadata = "{\"source\":\"" + AttestationRevocations.SOURCE + "\",\"retrievedAtEpochMillis\":" + now + ",\"maxAgeSeconds\":3600}";
        String revoked = "{\"entries\":{\"" + serial + "\":{\"status\":\"REVOKED\",\"reason\":\"KEY_COMPROMISE\"}}}";
        AttestationRevocations.Result result = AttestationRevocations.check(utf8(revoked), utf8(metadata), chain, now);
        check(result.knownRevokedOrSuspended(), "known revoked serial detected");
        check(result.matches.size() == 1 && result.matches.get(0).certificateIndex == 1, "entire chain checked, not just leaf");
        check(result.age == AttestationRevocations.Age.CURRENT_BY_LOCAL_CLOCK, "snapshot age tracked using local clock only");
        check(result.snapshotSha256.length() == 64, "exact status snapshot fingerprint exported");
        check(AttestationRevocations.check(utf8(revoked.replace("REVOKED", "SUSPENDED")), utf8(metadata), chain, now).knownRevokedOrSuspended(), "suspended certificate also blocked");
        AttestationRevocations.Result stale = AttestationRevocations.check(utf8(revoked), utf8(metadata), chain, now + 3601000);
        check(stale.age == AttestationRevocations.Age.STALE && stale.knownRevokedOrSuspended(), "stale snapshot retains known adverse matches");
        check(AttestationRevocations.check(utf8(revoked), utf8(metadata), chain, now - 1).age == AttestationRevocations.Age.UNKNOWN, "future collection time cannot look fresh");
        check(AttestationRevocations.check(utf8(revoked), null, chain, now).age == AttestationRevocations.Age.UNKNOWN, "missing metadata cannot look fresh");
        check(!AttestationRevocations.check(utf8("{\"entries\":{}}"), utf8(metadata), chain, now).knownRevokedOrSuspended(), "empty status map provides absence only");
        rejects(IOException.class, () -> AttestationRevocations.check(utf8("{}"), null, chain, now), "missing entries is not empty clearance");
        rejects(IOException.class, () -> AttestationRevocations.check(utf8("{\"entries\":[]}"), null, chain, now), "wrong entries type");
        rejects(IOException.class, () -> AttestationRevocations.check(utf8(revoked.replace("REVOKED", "OK")), null, chain, now), "unknown status cannot mean unrevoked");
        rejects(IOException.class, () -> AttestationRevocations.check(utf8("{\"entries\":{\"01\":{\"status\":\"REVOKED\"}}}"), null, chain, now), "noncanonical leading-zero serial");
        rejects(IOException.class, () -> AttestationRevocations.check(utf8("{\"entries\":{\"AB\":{\"status\":\"REVOKED\"}}}"), null, chain, now), "noncanonical uppercase serial");
        rejects(IOException.class, () -> AttestationRevocations.check(utf8("{\"entries\":{\"1\":{}}}"), null, chain, now), "missing status does not imply normal");
        rejects(IOException.class, () -> AttestationRevocations.check(utf8(revoked), utf8(metadata.replace(AttestationRevocations.SOURCE, "https://untrusted.invalid/status")), chain, now), "metadata source must be official endpoint");
        rejects(IOException.class, () -> AttestationRevocations.check(utf8(revoked), utf8(metadata.substring(0, metadata.length() - 1) + ",\"sha256\":\"bad\"}"), chain, now), "snapshot body hash must match supplied metadata");
        rejects(IOException.class, () -> AttestationRevocations.check(utf8(revoked + "{}"), null, chain, now), "trailing JSON ignored by neither parser");
        rejects(IOException.class, () -> AttestationRevocations.check(utf8("{\"entries\":[[[[[[[[[[]]]]]]]]]]}"), null, chain, now), "deeply nested JSON rejected before recursive parse");
        rejects(IOException.class, () -> AttestationRevocations.check(new byte[AttestationRevocations.MAX_SNAPSHOT_BYTES + 1], null, chain, now), "snapshot size cap");
        byte[] bundledSnapshot = Files.readAllBytes(project.resolve("app/src/main/assets/attestation_revocations.json"));
        byte[] bundledMetadata = Files.readAllBytes(project.resolve("app/src/main/assets/attestation_revocations_meta.json"));
        AttestationRevocations.Result bundled = AttestationRevocations.check(bundledSnapshot, bundledMetadata, chain, System.currentTimeMillis());
        check(bundled.entryCount > 0, "bundled official snapshot parses and is not silently empty");
        check(bundled.snapshotSha256.equals("4110236d8d47b35e7a7f124d5325b4c997a07a4a3b5ecb134eb903b2240fd695"), "bundled snapshot has independently recorded release hash");
    }

    private static X509Certificate certificate(Path file) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(file)));
    }
    private static List<X509Certificate> certificates(Path file) throws Exception {
        List<X509Certificate> result = new ArrayList<>();
        for (Certificate certificate : CertificateFactory.getInstance("X.509").generateCertificates(
                new ByteArrayInputStream(Files.readAllBytes(file)))) result.add((X509Certificate) certificate);
        return result;
    }
    private static void testFactoryExpiryCompatibility(Path project) throws Exception {
        Path fixtures = project.resolve("tests/attestation-fixtures");
        List<X509Certificate> googleRoots = certificates(project.resolve("app/src/main/assets/google_attestation_roots.pem"));
        List<X509Certificate> factory = certificates(fixtures.resolve("google-v04-factory-blueline.pem"));
        List<X509Certificate> rkp = certificates(fixtures.resolve("google-v04-rkp-caiman.pem"));
        Date now = Date.from(Instant.parse("2026-11-07T00:00:00Z"));
        Date later = Date.from(Instant.parse("2030-01-01T00:00:00Z"));
        AttestationChain.Validation current = AttestationChain.validateDetailed(factory, googleRoots, now);
        check(current.presentedRootReplaced, "expired supplied Google root connects to renewed pinned root with same key");
        check(!current.legacyFactoryExpiryApplied, "unexpired factory intermediates retain current-time policy");
        check(current.pkixValidationTimeMillis == now.getTime(), "ordinary PKIX uses caller time");
        AttestationChain.Validation legacy = AttestationChain.validateDetailed(factory, googleRoots, later);
        check(legacy.legacyFactoryExpiryApplied && legacy.expiredFactoryCaCount == 2,
                "official v0.4 factory fixture accepts only its two expired CAs");
        check(legacy.pkixValidationTimeMillis < later.getTime(), "legacy historical validation date exported");
        check(legacy.trustAnchor.equals(current.trustAnchor), "legacy compatibility never substitutes a different trust key");
        AttestationChain.Validation omitted = AttestationChain.validateDetailed(factory.subList(0, factory.size() - 1), googleRoots, later);
        check(omitted.legacyFactoryExpiryApplied && !omitted.presentedRootReplaced, "same authenticated factory policy when root is omitted");
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(rkp, googleRoots, later),
                "official v0.4 RKP fixture must still reject expired intermediates");
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(rkp.subList(0, rkp.size() - 1), googleRoots, later),
                "omitting RKP root cannot activate factory exception");
        Date rkpValidDate = Date.from(Instant.parse("2025-09-26T00:00:00Z"));
        check(!AttestationChain.validateDetailed(rkp, googleRoots, rkpValidDate).legacyFactoryExpiryApplied,
                "valid official RKP fixture uses strict current-time policy");
        Date tooEarly = Date.from(Instant.parse("2018-01-01T00:00:00Z"));
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(factory,
                Arrays.asList(factory.get(factory.size() - 1)), tooEarly), "future factory CAs are not relaxed");
        List<X509Certificate> broken = new ArrayList<>(factory);
        byte[] corrupt = factory.get(1).getEncoded(); corrupt[corrupt.length - 1] ^= 1;
        broken.set(1, (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(corrupt)));
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(broken, googleRoots, later),
                "factory expiry exception never accepts invalid signatures");
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(Arrays.asList(factory.get(0), factory.get(2)), googleRoots, later),
                "removing a factory intermediate cannot skip its signature relationship");
        List<X509Certificate> impostor = certificates(fixtures.resolve("factory-lookalike-chain.pem"));
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(impostor,
                Arrays.asList(impostor.get(impostor.size() - 1)), later),
                "matching serialNumber subjects on a different root key do not enable factory expiry exception");
        String revokedSerial = factory.get(1).getSerialNumber().toString(16);
        AttestationRevocations.Result revoked = AttestationRevocations.check(
                utf8("{\"entries\":{\"" + revokedSerial + "\":{\"status\":\"REVOKED\"}}}"), null, factory, later.getTime());
        check(revoked.knownRevokedOrSuspended(), "expiry-compatible factory CA is still checked against revocations");
        check(!AttestationChecks.supportsLocalHardwareEvidence(true, true, true, true, revoked.knownRevokedOrSuspended()),
                "known revoked factory chain cannot support local boot evidence");
    }
    private static void testTrust(Path project) throws Exception {
        Path fixtures = project.resolve("tests/attestation-fixtures");
        X509Certificate root = certificate(fixtures.resolve("trusted-root.pem"));
        X509Certificate leaf = certificate(fixtures.resolve("valid-leaf.pem"));
        X509Certificate expired = certificate(fixtures.resolve("expired-leaf.pem"));
        X509Certificate fakeRoot = certificate(fixtures.resolve("impostor-root.pem"));
        X509Certificate fakeLeaf = certificate(fixtures.resolve("impostor-leaf.pem"));
        Date time = Date.from(Instant.parse("2026-11-06T00:00:00Z"));
        List<X509Certificate> anchors = Arrays.asList(root);
        check(AttestationChain.validate(Arrays.asList(leaf, root), anchors, time).equals(root), "pinned valid chain");
        check(AttestationChain.validate(Arrays.asList(leaf), anchors, time).equals(root), "omitted root with known anchor");
        check(AttestationChain.validate(Arrays.asList(leaf, root), Arrays.asList(root, expired), time).equals(root), "unused expired pinned candidate cannot invalidate valid path");
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(Arrays.asList(leaf), Arrays.asList(expired), time), "expired candidate cannot become a selected trust anchor");
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(Arrays.asList(fakeLeaf, fakeRoot), anchors, time), "same-subject impostor root");
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(Arrays.asList(fakeLeaf, root), anchors, time), "invalid leaf signature");
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(Arrays.asList(expired, root), anchors, time), "expired certificate is not silently accepted");
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(Arrays.asList(root), anchors, time), "anchor only is no attested leaf");
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(Arrays.asList(leaf, root, root), anchors, time), "duplicate certificate");
        rejects(GeneralSecurityException.class, () -> AttestationChain.validate(Arrays.asList(root, leaf), anchors, time), "wrong chain order");
        check(AttestationChain.attestationIndex(Arrays.asList(leaf, root)) == -1, "no extension is unavailable");
        X509Certificate attested = certificate(fixtures.resolve("attested-ca.pem"));
        X509Certificate extended = certificate(fixtures.resolve("extended-leaf.pem"));
        check(AttestationChain.attestationIndex(Arrays.asList(extended, attested, root)) == 1, "select extension nearest root, not attacker leaf");
        X509Certificate provisioned = certificate(fixtures.resolve("provisioned-leaf.pem"));
        X509Certificate provisioning = certificate(fixtures.resolve("provisioning-ca.pem"));
        check(AttestationChain.attestationIndex(Arrays.asList(provisioned, provisioning, root)) == 0, "RKP adjacency accepted");
        rejects(IOException.class, () -> AttestationChain.attestationIndex(Arrays.asList(leaf, provisioning, root)), "RKP missing subsequent extension");
        Collection<? extends Certificate> rawRoots = CertificateFactory.getInstance("X.509").generateCertificates(
                new ByteArrayInputStream(Files.readAllBytes(project.resolve("app/src/main/assets/google_attestation_roots.pem"))));
        check(rawRoots.size() == 2, "two official Google roots including 2026 rotation");
        List<String> expected = Arrays.asList("cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc",
                "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0");
        for (Certificate cert : rawRoots) {
            X509Certificate google = (X509Certificate) cert;
            google.verify(google.getPublicKey()); google.checkValidity(time);
            StringBuilder hex = new StringBuilder();
            for (byte b : MessageDigest.getInstance("SHA-256").digest(google.getEncoded())) hex.append(String.format("%02x", b));
            check(expected.contains(hex.toString()), "official Google root fingerprint");
        }
    }
    public static void main(String[] args) throws Exception {
        Path project = args.length == 0 ? Paths.get(".") : Paths.get(args[0]);
        testDer(); testApplicationAndBinding(); testCorrelations(); testDeviceProperties();
        testTrust(project); testFactoryExpiryCompatibility(project); testRevocations(project);
        System.out.println("Attestation checks passed: " + assertions + " assertions, including truncation sweep and 2,000 malformed DER inputs.");
    }
}

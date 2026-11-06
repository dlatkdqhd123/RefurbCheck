package io.github.refurbcheck;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/** Parsed fields are untrusted observations until chain, challenge and public-key binding are checked. */
public final class AttestationRecord {
    public final long attestationVersion, keymasterVersion;
    public final int attestationSecurityLevel, keymasterSecurityLevel;
    public final byte[] challenge;
    public final RootOfTrust hardwareRoot;
    public final boolean softwareRootPresent;
    public final Long hardwareOsVersion, hardwareOsPatchLevel, vendorPatchLevel, bootPatchLevel;
    /** [709] is platform-supplied, software-enforced data; never call it hardware-proven identity. */
    public final ApplicationId applicationId;
    public final boolean hardwareApplicationIdPresent;
    /** Non-unique properties only. IMEI, serial number, MEID and uniqueId are not parsed. */
    public final DeviceProperties hardwareDeviceProperties, softwareDeviceProperties;

    private AttestationRecord(List<DerReader.Value> fields) throws IOException {
        if (fields.size() != 8) throw new IOException("Unexpected KeyDescription field count");
        attestationVersion = fields.get(0).unsigned(2);
        attestationSecurityLevel = enumInt(fields.get(1), 2);
        keymasterVersion = fields.get(2).unsigned(2);
        keymasterSecurityLevel = enumInt(fields.get(3), 2);
        challenge = fields.get(4).octets();
        if (challenge.length > 128) throw new IOException("Attestation challenge too long");
        fields.get(5).require(0, 4, false); // uniqueId is deliberately not retained or exported.
        Map<Integer, DerReader.Value> software = authorizations(fields.get(6));
        Map<Integer, DerReader.Value> hardware = authorizations(fields.get(7));
        softwareRootPresent = software.containsKey(704);
        hardwareRoot = hardware.containsKey(704) ? new RootOfTrust(hardware.get(704), attestationVersion) : null;
        hardwareOsVersion = optionalInteger(hardware, 705);
        hardwareOsPatchLevel = optionalInteger(hardware, 706);
        vendorPatchLevel = optionalInteger(hardware, 718);
        bootPatchLevel = optionalInteger(hardware, 719);
        hardwareApplicationIdPresent = hardware.containsKey(709);
        if (software.containsKey(709) && hardwareApplicationIdPresent)
            throw new IOException("Application ID appears in both enforcement lists");
        applicationId = software.containsKey(709) ? new ApplicationId(software.get(709).octets()) : null;
        // Preserve a misplaced field as an unsupported observation, but still reject malformed DER.
        if (hardwareApplicationIdPresent) new ApplicationId(hardware.get(709).octets());
        hardwareDeviceProperties = new DeviceProperties(hardware);
        softwareDeviceProperties = new DeviceProperties(software);
        for (String field : DeviceProperties.NAMES)
            if (hardwareDeviceProperties.get(field) != null && softwareDeviceProperties.get(field) != null)
                throw new IOException("Device property appears in both enforcement lists");
    }

    public static AttestationRecord parseExtension(byte[] x509ExtensionValue) throws IOException {
        byte[] sequence = DerReader.single(x509ExtensionValue).octets();
        DerReader.Value value = DerReader.single(sequence);
        value.require(0, 16, true);
        return new AttestationRecord(value.children());
    }

    public boolean hardwareBacked() {
        return (attestationSecurityLevel == 1 || attestationSecurityLevel == 2)
                && (keymasterSecurityLevel == 1 || keymasterSecurityLevel == 2);
    }
    public boolean recognizedVersionPair() {
        if (attestationVersion == 1) return keymasterVersion == 2 && attestationSecurityLevel <= 1 && keymasterSecurityLevel <= 1;
        if (attestationVersion == 2) return keymasterVersion == 3 && attestationSecurityLevel <= 1 && keymasterSecurityLevel <= 1;
        if (attestationVersion == 3) return keymasterVersion == 4;
        if (attestationVersion == 4) return keymasterVersion == 41;
        return (attestationVersion == 100 || attestationVersion == 200 || attestationVersion == 300
                || attestationVersion == 400 || attestationVersion == 500) && keymasterVersion == attestationVersion;
    }

    private static int enumInt(DerReader.Value field, int maximum) throws IOException {
        long value = field.unsigned(10);
        if (value > maximum) throw new IOException("Unknown attestation enumeration");
        return (int) value;
    }

    private static Map<Integer, DerReader.Value> authorizations(DerReader.Value value) throws IOException {
        value.require(0, 16, true);
        Map<Integer, DerReader.Value> result = new HashMap<>();
        for (DerReader.Value field : value.children()) {
            if (field.tagClass != 2 || !field.constructed) throw new IOException("Invalid authorization tag");
            if (result.put(field.tag, field.explicit()) != null) throw new IOException("Duplicate authorization tag");
        }
        return result;
    }

    private static Long optionalInteger(Map<Integer, DerReader.Value> fields, int tag) throws IOException {
        return fields.containsKey(tag) ? fields.get(tag).unsigned(2) : null;
    }

    public static final class DeviceProperties {
        public static final List<String> NAMES = Collections.unmodifiableList(
                Arrays.asList("brand", "device", "product", "manufacturer", "model"));
        private static final int[] TAGS = {710, 711, 712, 716, 717};
        private final Map<String, String> values;
        private DeviceProperties(Map<Integer, DerReader.Value> authorizations) throws IOException {
            Map<String, String> parsed = new HashMap<>();
            for (int i = 0; i < NAMES.size(); i++) {
                DerReader.Value value = authorizations.get(TAGS[i]);
                if (value == null) continue;
                byte[] encoded = value.octets();
                if (encoded.length > 512) throw new IOException("Device property size limit");
                String text;
                try {
                    text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(encoded)).toString();
                } catch (CharacterCodingException exception) {
                    throw new IOException("Invalid device property UTF-8", exception);
                }
                for (int j = 0; j < text.length(); j++)
                    if (Character.isISOControl(text.charAt(j))) throw new IOException("Device property control character");
                // Empty values are preserved as incomplete evidence, not an identity match.
                parsed.put(NAMES.get(i), text);
            }
            values = Collections.unmodifiableMap(parsed);
        }
        public String get(String field) { return values.get(field); }
        public boolean hasAny() { return !values.isEmpty(); }
    }

    public static final class ApplicationId {
        public final List<PackageIdentity> packages;
        public final List<byte[]> signerSha256;
        private ApplicationId(byte[] encoded) throws IOException {
            if (encoded.length == 0 || encoded.length > 1024) throw new IOException("Application ID size limit");
            DerReader.Value value = DerReader.single(encoded);
            value.require(0, 16, true);
            List<DerReader.Value> fields = value.children();
            if (fields.size() != 2) throw new IOException("Invalid Application ID field count");
            List<DerReader.Value> packageValues = setMembers(fields.get(0));
            List<DerReader.Value> signerValues = setMembers(fields.get(1));
            if (packageValues.isEmpty() || signerValues.isEmpty()) throw new IOException("Empty Application ID set");
            List<PackageIdentity> parsedPackages = new ArrayList<>();
            HashSet<String> names = new HashSet<>();
            for (DerReader.Value packageValue : packageValues) {
                packageValue.require(0, 16, true);
                List<DerReader.Value> packageFields = packageValue.children();
                if (packageFields.size() != 2) throw new IOException("Invalid package identity field count");
                byte[] nameBytes = packageFields.get(0).octets();
                if (nameBytes.length == 0 || nameBytes.length > 255) throw new IOException("Invalid package name length");
                String name;
                try {
                    name = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(nameBytes)).toString();
                } catch (CharacterCodingException exception) { throw new IOException("Invalid package name UTF-8", exception); }
                for (int i = 0; i < name.length(); i++) {
                    char c = name.charAt(i);
                    if (Character.isISOControl(c) || Character.isWhitespace(c)) throw new IOException("Invalid package name character");
                }
                if (!names.add(name)) throw new IOException("Duplicate package name");
                parsedPackages.add(new PackageIdentity(name, packageFields.get(1).unsigned(2)));
            }
            List<byte[]> parsedSigners = new ArrayList<>();
            for (DerReader.Value signerValue : signerValues) {
                byte[] digest = signerValue.octets();
                if (digest.length != 32) throw new IOException("Signer digest must be SHA-256");
                for (byte[] previous : parsedSigners)
                    if (Arrays.equals(previous, digest)) throw new IOException("Duplicate signer digest");
                parsedSigners.add(digest);
            }
            packages = Collections.unmodifiableList(parsedPackages);
            signerSha256 = Collections.unmodifiableList(parsedSigners);
        }
        private static List<DerReader.Value> setMembers(DerReader.Value set) throws IOException {
            set.require(0, 17, true);
            List<DerReader.Value> members = set.children();
            if (members.size() > 32) throw new IOException("Too many Application ID set members");
            byte[] previous = null;
            for (DerReader.Value member : members) {
                byte[] current = member.encoded();
                if (previous != null && compareUnsigned(previous, current) >= 0)
                    throw new IOException("Unsorted or duplicate DER set member");
                previous = current;
            }
            return members;
        }
        private static int compareUnsigned(byte[] a, byte[] b) {
            for (int i = 0; i < Math.min(a.length, b.length); i++) {
                int comparison = (a[i] & 255) - (b[i] & 255);
                if (comparison != 0) return comparison;
            }
            return a.length - b.length;
        }
    }

    public static final class PackageIdentity {
        public final String packageName;
        public final long versionCode;
        private PackageIdentity(String packageName, long versionCode) {
            this.packageName = packageName; this.versionCode = versionCode;
        }
    }

    public static final class RootOfTrust {
        public final byte[] verifiedBootKey, verifiedBootHash;
        public final boolean deviceLocked;
        public final int verifiedBootState;
        private RootOfTrust(DerReader.Value value, long attestationVersion) throws IOException {
            value.require(0, 16, true);
            List<DerReader.Value> fields = value.children();
            int expectedFields = attestationVersion >= 3 ? 4 : 3;
            if (fields.size() != expectedFields) throw new IOException("Invalid RootOfTrust field count for attestation version");
            verifiedBootKey = fields.get(0).octets();
            deviceLocked = fields.get(1).bool();
            verifiedBootState = enumInt(fields.get(2), 3);
            verifiedBootHash = fields.size() == 4 ? fields.get(3).octets() : null;
            if (verifiedBootKey.length > 128 || (verifiedBootHash != null && verifiedBootHash.length > 128))
                throw new IOException("Unrecognized boot digest length");
        }
        public boolean hasNonzeroBootKey() {
            for (byte b : verifiedBootKey) if (b != 0) return true;
            return false;
        }
        public boolean hasRecognizedBootDigests(long attestationVersion) {
            return recognizedDigest(verifiedBootKey) && hasNonzeroBootKey()
                    && (attestationVersion < 3 || recognizedDigest(verifiedBootHash) && nonzero(verifiedBootHash));
        }
        private static boolean recognizedDigest(byte[] digest) {
            // SHA-256 is recommended by Android; SHA-384/512 are also meaningful hash lengths.
            return digest != null && (digest.length == 32 || digest.length == 48 || digest.length == 64);
        }
        private static boolean nonzero(byte[] bytes) {
            for (byte value : bytes) if (value != 0) return true;
            return false;
        }
    }
}

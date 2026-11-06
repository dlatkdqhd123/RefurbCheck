package io.github.refurbcheck;

import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/** A bundled status snapshot can identify known bad serials; absence is never a live clearance. */
public final class AttestationRevocations {
    public static final String SOURCE = "https://android.googleapis.com/attestation/status";
    public static final int MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024;
    public enum Age { UNKNOWN, STALE, CURRENT_BY_LOCAL_CLOCK }
    private AttestationRevocations() { }

    public static final class Match {
        public final int certificateIndex;
        public final String serial, status, reason;
        private Match(int index, String serial, String status, String reason) {
            this.certificateIndex = index; this.serial = serial; this.status = status; this.reason = reason;
        }
    }
    public static final class Result {
        public final List<Match> matches;
        public final int entryCount;
        public final String snapshotSha256;
        public final long retrievedAtEpochMillis, maxAgeSeconds;
        public final Age age;
        private Result(List<Match> matches, int entryCount, String digest, long retrieved, long maxAge, Age age) {
            this.matches = Collections.unmodifiableList(matches); this.entryCount = entryCount;
            this.snapshotSha256 = digest; this.retrievedAtEpochMillis = retrieved; this.maxAgeSeconds = maxAge; this.age = age;
        }
        public boolean knownRevokedOrSuspended() { return !matches.isEmpty(); }
    }

    public static Result check(byte[] snapshot, byte[] metadata, List<X509Certificate> chain, long now) throws IOException {
        if (snapshot == null || snapshot.length == 0 || snapshot.length > MAX_SNAPSHOT_BYTES)
            throw new IOException("Revocation snapshot size limit");
        // The probe accepts at most eight presented certs, plus an omitted pinned root if necessary.
        if (chain == null || chain.isEmpty() || chain.size() > 9) throw new IOException("Invalid revocation chain size");
        JSONObject data = object(snapshot);
        Object rawEntries = data.opt("entries");
        if (!(rawEntries instanceof JSONObject)) throw new IOException("Missing revocation entries object");
        JSONObject entries = (JSONObject) rawEntries;
        if (entries.length() > 50000) throw new IOException("Too many revocation entries");
        Iterator<String> serials = entries.keys();
        while (serials.hasNext()) {
            String serial = serials.next();
            if (!serial.matches("[a-f1-9][a-f0-9]{0,79}")) throw new IOException("Noncanonical revocation serial");
            Object rawEntry = entries.opt(serial);
            if (!(rawEntry instanceof JSONObject)) throw new IOException("Invalid revocation entry");
            JSONObject entry = (JSONObject) rawEntry;
            Object status = entry.opt("status");
            if (!(status instanceof String) || (!"REVOKED".equals(status) && !"SUSPENDED".equals(status)))
                throw new IOException("Unknown revocation entry status");
            if (entry.has("reason") && (!(entry.opt("reason") instanceof String)
                    || ((String) entry.opt("reason")).length() > 128)) throw new IOException("Invalid revocation reason");
        }
        String digest = sha256(snapshot);
        long retrieved = 0, maxAge = 0;
        Age age = Age.UNKNOWN;
        if (metadata != null) {
            if (metadata.length == 0 || metadata.length > 16384) throw new IOException("Revocation metadata size limit");
            JSONObject meta = object(metadata);
            if (!SOURCE.equals(meta.opt("source"))) throw new IOException("Unrecognized revocation snapshot source");
            if (meta.has("sha256") && !digest.equals(meta.opt("sha256"))) throw new IOException("Revocation snapshot digest mismatch");
            retrieved = integer(meta.opt("retrievedAtEpochMillis"));
            maxAge = integer(meta.opt("maxAgeSeconds"));
            // The local clock cannot establish trusted freshness; this is only cache age accounting.
            if (retrieved > 0 && now >= retrieved && maxAge > 0 && maxAge <= 604800)
                age = now - retrieved <= maxAge * 1000L ? Age.CURRENT_BY_LOCAL_CLOCK : Age.STALE;
        }
        List<Match> matches = new ArrayList<>();
        for (int i = 0; i < chain.size(); i++) {
            if (chain.get(i).getSerialNumber().signum() <= 0) throw new IOException("Invalid certificate serial");
            String serial = chain.get(i).getSerialNumber().toString(16);
            JSONObject entry = entries.optJSONObject(serial);
            if (entry != null) matches.add(new Match(i, serial, (String) entry.opt("status"),
                    entry.has("reason") ? (String) entry.opt("reason") : "UNSPECIFIED"));
        }
        return new Result(matches, entries.length(), digest, retrieved, maxAge, age);
    }
    private static JSONObject object(byte[] data) throws IOException {
        int depth = 0; boolean inString = false, escaped = false;
        for (byte value : data) {
            if (inString) {
                if (escaped) escaped = false;
                else if (value == '\\') escaped = true;
                else if (value == '"') inString = false;
            } else if (value == '"') inString = true;
            else if (value == '{' || value == '[') { if (++depth > 8) throw new IOException("Revocation JSON depth limit"); }
            else if (value == '}' || value == ']') { if (--depth < 0) throw new IOException("Unbalanced revocation JSON"); }
        }
        if (inString || depth != 0) throw new IOException("Unterminated revocation JSON");
        try {
            JSONTokener parser = new JSONTokener(new String(data, StandardCharsets.UTF_8));
            Object value = parser.nextValue();
            if (!(value instanceof JSONObject) || parser.nextClean() != 0) throw new IOException("Invalid revocation JSON object");
            return (JSONObject) value;
        } catch (Exception exception) { throw new IOException("Invalid revocation JSON", exception); }
    }
    private static long integer(Object value) {
        return value instanceof Integer || value instanceof Long ? ((Number) value).longValue() : 0;
    }
    private static String sha256(byte[] input) throws IOException {
        try {
            StringBuilder hex = new StringBuilder();
            for (byte b : MessageDigest.getInstance("SHA-256").digest(input)) {
                hex.append(Character.forDigit((b >>> 4) & 15, 16)); hex.append(Character.forDigit(b & 15, 16));
            }
            return hex.toString();
        } catch (Exception exception) { throw new IOException("SHA-256 unavailable", exception); }
    }
}

package io.github.refurbcheck;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Read-only comparisons of reported signer metadata. Neither imported JSON nor
 * PackageManager's own report is an independent APK signature verification.
 */
public final class SignatureLineage {
    public enum Relation {
        SAME_SIGNERS, FORWARD_ROTATION_REPORTED, BACKWARD_ROTATION_REPORTED,
        CONFLICTING_LINEAGE_REPORTED, DIFFERENT_SIGNERS, UNKNOWN
    }
    private static final int MAX_SIGNERS = 32;
    private SignatureLineage() { }

    public static Relation compare(JSONObject previous, JSONObject current) {
        List<String> oldSigners = currentSigners(previous), newSigners = currentSigners(current);
        if (oldSigners == null || newSigners == null) return Relation.UNKNOWN;
        if (oldSigners.equals(newSigners)) return Relation.SAME_SIGNERS;
        // Multiple signers identify an app by the entire set. One overlapping
        // certificate, a forged history field, or a subset is never a rotation.
        if (oldSigners.size() != 1 || newSigners.size() != 1)
            return Relation.DIFFERENT_SIGNERS;
        List<String> oldHistory = history(previous, oldSigners.get(0));
        List<String> newHistory = history(current, newSigners.get(0));
        if (newHistory != null) {
            int index = newHistory.indexOf(oldSigners.get(0));
            if (index >= 0 && index < newHistory.size() - 1) {
                if (oldHistory != null && !oldHistory.equals(newHistory.subList(0, index + 1)))
                    return Relation.CONFLICTING_LINEAGE_REPORTED;
                // A malformed explicit history is not the same as an older
                // report that did not collect history at all.
                if (claimsReadableHistory(previous) && oldHistory == null)
                    return Relation.CONFLICTING_LINEAGE_REPORTED;
                return Relation.FORWARD_ROTATION_REPORTED;
            }
        }
        if (oldHistory != null) {
            int index = oldHistory.indexOf(newSigners.get(0));
            if (index >= 0 && index < oldHistory.size() - 1) {
                if (newHistory != null && !newHistory.equals(oldHistory.subList(0, index + 1)))
                    return Relation.CONFLICTING_LINEAGE_REPORTED;
                if (claimsReadableHistory(current) && newHistory == null)
                    return Relation.CONFLICTING_LINEAGE_REPORTED;
                return Relation.BACKWARD_ROTATION_REPORTED;
            }
        }
        return Relation.DIFFERENT_SIGNERS;
    }

    /** Sorted complete current signer set, or null for missing/malformed data. */
    public static List<String> currentSigners(JSONObject row) {
        if (row == null || !Boolean.TRUE.equals(row.opt("signingReadable"))) return null;
        List<String> values = digests(row.opt("signingSha256"));
        if (values == null) return null;
        Object mode = row.opt("signingMode");
        if (mode != null) {
            if (!(mode instanceof String)) return null;
            if ("SINGLE".equals(mode) && values.size() != 1
                    || "MULTIPLE".equals(mode) && values.size() < 2
                    || !"SINGLE".equals(mode) && !"MULTIPLE".equals(mode) && !"LEGACY".equals(mode))
                return null;
        }
        Collections.sort(values);
        return Collections.unmodifiableList(values);
    }

    /** Original-to-current order is significant. Never sort a signer lineage. */
    private static List<String> history(JSONObject row, String current) {
        if (row == null || !"SINGLE".equals(row.opt("signingMode"))
                || !claimsReadableHistory(row)) return null;
        List<String> values = digests(row.opt("signingHistorySha256"));
        if (values == null || !current.equals(values.get(values.size() - 1))) return null;
        return values;
    }

    private static boolean claimsReadableHistory(JSONObject row) {
        return row != null && Boolean.TRUE.equals(row.opt("signingHistoryReadable"));
    }

    private static List<String> digests(Object raw) {
        if (!(raw instanceof JSONArray)) return null;
        JSONArray array = (JSONArray) raw;
        if (array.length() == 0 || array.length() > MAX_SIGNERS) return null;
        List<String> values = new ArrayList<>(); Set<String> unique = new HashSet<>();
        for (int i = 0; i < array.length(); i++) {
            Object value = array.opt(i);
            if (!(value instanceof String) || !((String) value).matches("[0-9a-fA-F]{64}")) return null;
            String normalized = ((String) value).toLowerCase(Locale.ROOT);
            if (!unique.add(normalized)) return null;
            values.add(normalized);
        }
        return values;
    }
}

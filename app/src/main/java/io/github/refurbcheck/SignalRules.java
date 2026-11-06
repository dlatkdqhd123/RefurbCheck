package io.github.refurbcheck;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.Locale;

/** Small, Android-independent interpretation rules; absence is never a clean bill of health. */
public final class SignalRules {
    private SignalRules() { }

    public static String bootLevel(String state, String flashLocked, String vbmeta) {
        state=clean(state); flashLocked=clean(flashLocked); vbmeta=clean(vbmeta);
        if ("orange".equals(state) || "red".equals(state) || "0".equals(flashLocked)
                || "unlocked".equals(vbmeta)) return "ALERT";
        if ("yellow".equals(state)) return "WARN";
        if ("green".equals(state) && ("1".equals(flashLocked) || "locked".equals(vbmeta)))
            return "PASS";
        return "UNKNOWN";
    }

    public static long patchAgeDays(String patch, LocalDate today) {
        if (patch==null || !patch.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}"))
            throw new IllegalArgumentException("Invalid patch date");
        return ChronoUnit.DAYS.between(LocalDate.parse(patch), today);
    }

    public static String patchLevel(String patch, LocalDate today) {
        try {
            long age=patchAgeDays(patch,today);
            return age>180 || age < -31 ? "WARN" : "INFO";
        } catch (RuntimeException e) { return "UNKNOWN"; }
    }

    private static String clean(String value) {
        return value==null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}

package io.github.dlatkdqhd123.refurbcheck.prototype;

import java.time.LocalDate;

/** Dependency-free boundary tests; runnable with javac/java on the PC and in CI. */
public final class AuditRulesTest {
    private static int passed;
    private static void expect(boolean condition, String name) {
        if (!condition) throw new AssertionError(name);
        passed++;
    }
    public static void main(String[] args) {
        LocalDate now = LocalDate.of(2026, 11, 6);
        expect(AuditRules.patch(null, now).status == AuditRules.Status.UNKNOWN, "missing patch");
        expect(AuditRules.patch("", now).status == AuditRules.Status.UNKNOWN, "empty patch");
        expect(AuditRules.patch("2026-02-30", now).status == AuditRules.Status.UNKNOWN, "invalid date");
        expect(AuditRules.patch("2026-2-01", now).status == AuditRules.Status.UNKNOWN, "non-ISO date");
        expect(AuditRules.patch("2026-11-07", now).status == AuditRules.Status.UNKNOWN, "future date");
        expect(AuditRules.patch(now.toString(), now).status == AuditRules.Status.OBSERVED, "today observation");
        expect(AuditRules.patch(now.minusDays(180).toString(), now).status == AuditRules.Status.OBSERVED, "180-day boundary");
        expect(AuditRules.patch(now.minusDays(181).toString(), now).status == AuditRules.Status.REVIEW, "stale patch");
        expect(AuditRules.patch("2024-02-29", now).status == AuditRules.Status.REVIEW, "valid leap date");
        expect(!AuditRules.granted(0), "undeclared grant");
        expect(!AuditRules.granted(1), "requested is not granted");
        expect(AuditRules.granted(2) && AuditRules.granted(3), "granted flag");
        expect(!AuditRules.granted(4), "unrelated flag");
        System.out.println("PASS: " + passed + " conservative audit rule checks");
    }
}

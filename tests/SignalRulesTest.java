package io.github.refurbcheck;

import java.time.LocalDate;

/** Run with javac/java; no Android device or external test library required. */
public final class SignalRulesTest {
    private static int n;
    private static void same(Object expected,Object actual) {
        n++; if(!expected.equals(actual)) throw new AssertionError("Expected "+expected+", got "+actual);
    }
    public static void main(String[] args) {
        same("UNKNOWN",SignalRules.bootLevel(null,null,null));
        same("UNKNOWN",SignalRules.bootLevel("green","",""));
        same("UNKNOWN",SignalRules.bootLevel("garbage","1","locked"));
        same("PASS",SignalRules.bootLevel("green","1","locked"));
        same("PASS",SignalRules.bootLevel("green",null,"locked"));
        same("ALERT",SignalRules.bootLevel("green","0","locked"));
        same("ALERT",SignalRules.bootLevel("green","1","unlocked"));
        same("ALERT",SignalRules.bootLevel("orange","1","locked"));
        same("ALERT",SignalRules.bootLevel("red","1","locked"));
        same("WARN",SignalRules.bootLevel("yellow","1","locked"));
        same("ALERT",SignalRules.bootLevel("yellow","0","locked"));
        same("ALERT",SignalRules.bootLevel(" ORANGE ","1","locked"));
        LocalDate today=LocalDate.of(2026,11,6);
        same("UNKNOWN",SignalRules.patchLevel(null,today));
        same("UNKNOWN",SignalRules.patchLevel("",today));
        same("UNKNOWN",SignalRules.patchLevel("2026-02-30",today));
        same("UNKNOWN",SignalRules.patchLevel("2026-9-01",today));
        same("INFO",SignalRules.patchLevel("2026-11-01",today));
        same("WARN",SignalRules.patchLevel("2025-11-01",today));
        same("WARN",SignalRules.patchLevel("2027-11-01",today));
        same("INFO",SignalRules.patchLevel(today.minusDays(180).toString(),today));
        same("WARN",SignalRules.patchLevel(today.minusDays(181).toString(),today));
        same(5L,SignalRules.patchAgeDays("2026-11-01",today));
        System.out.println("SignalRules: "+n+" assertions passed");
    }
}

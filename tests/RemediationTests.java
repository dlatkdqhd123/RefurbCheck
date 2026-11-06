package io.github.refurbcheck;

import org.json.JSONArray;
import org.json.JSONObject;
import java.math.BigInteger;

/** Test-only metadata fixtures. They are never added to the shipping IOC database. */
public final class RemediationTests {
    private static final String OWN="io.github.refurbcheck",PKG="io.github.refurbcheck.fixture.removable";
    private static final String HASH=repeat('a'),OTHER=repeat('b');
    private static int scenarios,assertions,failures;
    private interface Checked {void run() throws Exception;}
    public static void main(String[] args) {
        scenario("stable exact-match user app is eligible for preflight, not silent deletion",()->yes(eligible(valid())));
        scenario("null row is ineligible",()->no(eligible(null)));
        scenario("system app is ineligible",()->no(eligible(valid().put("system",true))));
        scenario("self-removal is ineligible",()->no(eligible(valid().put("packageName",OWN).put("remediationPackageName",OWN))));
        scenario("missing system flag fails closed",()->{JSONObject row=valid();row.remove("system");no(eligible(row));});
        scenario("missing confirmed IOC flag fails closed",()->{JSONObject row=valid();row.remove("confirmedIoc");no(eligible(row));});
        scenario("false confirmed IOC flag fails closed",()->no(eligible(valid().put("confirmedIoc",false))));
        scenario("missing remediation eligibility fails closed",()->{JSONObject row=valid();row.remove("remediationEligible");no(eligible(row));});
        scenario("false remediation eligibility fails closed",()->no(eligible(valid().put("remediationEligible",false))));
        scenario("eligibility flags must be actual JSON booleans",()->{
            no(eligible(valid().put("system","false")));
            no(eligible(valid().put("confirmedIoc","true")));
            no(eligible(valid().put("remediationEligible","true")));
            no(eligible(valid().put("system",0)));
        });
        scenario("missing package binding fails closed",()->{JSONObject row=valid();row.remove("remediationPackageName");no(eligible(row));});
        scenario("different package binding fails closed",()->no(eligible(valid().put("remediationPackageName","com.example.different"))));
        scenario("malformed package name cannot become an uninstall URI",()->{
            for(String pkg:new String[]{"","single","com.example/other","package:com.example","com.example\nextra"})
                no(eligible(valid().put("packageName",pkg).put("remediationPackageName",pkg)));
        });
        scenario("missing version fails closed",()->{JSONObject row=valid();row.remove("versionCode");no(eligible(row));});
        scenario("negative version fails closed",()->no(eligible(valid().put("versionCode",-1))));
        scenario("missing update time fails closed",()->{JSONObject row=valid();row.remove("lastUpdateTime");no(eligible(row));});
        scenario("negative update time fails closed",()->no(eligible(valid().put("lastUpdateTime",-1))));
        scenario("version and update time must be actual integer metadata",()->{
            for(Object value:new Object[]{"1",1.5,1.0,true,JSONObject.NULL}) {
                no(eligible(valid().put("versionCode",value)));
                no(eligible(valid().put("lastUpdateTime",value)));
            }
        });
        scenario("Integer and Long version metadata are supported",()->{
            yes(eligible(valid().put("versionCode",1).put("lastUpdateTime",10L)));
            yes(eligible(valid().put("versionCode",1L).put("lastUpdateTime",10)));
        });
        scenario("package changed during scan fails closed",()->no(eligible(valid().put("apkChangedDuringScan",true))));
        scenario("missing match list fails closed",()->{JSONObject row=valid();row.remove("iocMatches");no(eligible(row));});
        scenario("empty match list fails closed",()->no(eligible(valid().put("iocMatches",new JSONArray()))));
        scenario("nonobject match row fails closed",()->no(eligible(valid().put("iocMatches",new JSONArray().put("bad")))));
        scenario("missing APK file list fails closed",()->{JSONObject row=valid();row.remove("apkFiles");no(eligible(row));});
        scenario("empty APK file list fails closed",()->no(eligible(valid().put("apkFiles",new JSONArray()))));
        scenario("missing file stability flag fails closed",()->{JSONObject row=valid();file(row).remove("fileStable");no(eligible(row));});
        scenario("unstable file fails closed",()->{JSONObject row=valid();file(row).put("fileStable",false);no(eligible(row));});
        scenario("missing file match confirmation fails closed",()->{JSONObject row=valid();file(row).remove("matchConfirmed");no(eligible(row));});
        scenario("unconfirmed file match fails closed",()->{JSONObject row=valid();file(row).put("matchConfirmed",false);no(eligible(row));});
        scenario("file evidence flags must be actual JSON booleans",()->{
            JSONObject row=valid();file(row).put("fileStable","true");no(eligible(row));
            row=valid();file(row).put("matchConfirmed","true");no(eligible(row));
        });
        scenario("partial or changed hash is not eligible",()->{
            for(String status:new String[]{"CHANGED","UNREADABLE","CANCELLED","TIME_LIMIT","HASHED_PENDING_STABILITY","NOT_SCANNED"}) {
                JSONObject row=valid();file(row).put("hashStatus",status);no(eligible(row));
            }
        });
        scenario("malformed hash strings fail closed",()->{
            for(String sha:new String[]{"",HASH.substring(1),repeat('g'),HASH+"0"," "+HASH}) {
                JSONObject row=valid();match(row).put("sha256",sha);file(row).put("sha256",sha);no(eligible(row));
            }
        });
        scenario("JSON-null hash fails closed",()->{JSONObject row=valid();match(row).put("sha256",JSONObject.NULL);no(eligible(row));});
        scenario("numeric hash is not a SHA256 string",()->{
            JSONObject row=valid();BigInteger number=new BigInteger(repeat('1'));match(row).put("sha256",number);file(row).put("sha256",number);no(eligible(row));
        });
        scenario("different IOC and file hash fails closed",()->{JSONObject row=valid();file(row).put("sha256",OTHER);no(eligible(row));});
        scenario("hash case differences are accepted",()->{JSONObject row=valid();match(row).put("sha256",HASH.toUpperCase(java.util.Locale.ROOT));yes(eligible(row));});
        scenario("malformed file id fails closed",()->{
            for(String id:new String[]{"","/data/app/base.apk","base:other","split:"}) {
                JSONObject row=valid();match(row).put("fileId",id);file(row).put("fileId",id);no(eligible(row));
            }
        });
        scenario("unmatched file id fails closed",()->{JSONObject row=valid();match(row).put("fileId","split:config.en");no(eligible(row));});
        scenario("duplicate matching file id fails closed",()->{
            JSONObject row=valid();row.getJSONArray("apkFiles").put(new JSONObject(file(row).toString()));no(eligible(row));
        });
        scenario("valid split match can pass eligibility",()->{
            JSONObject row=valid();match(row).put("fileId","split:config.en");file(row).put("fileId","split:config.en");yes(eligible(row));
        });
        scenario("one invalid match cannot hide behind another valid match",()->{
            JSONObject row=valid();row.getJSONArray("iocMatches").put(new JSONObject().put("fileId","split:missing").put("sha256",OTHER));no(eligible(row));
        });
        scenario("unreadable unrelated split does not negate stable exact-match evidence",()->{
            JSONObject row=valid().put("apkInspectionComplete",false);
            row.getJSONArray("apkFiles").put(new JSONObject().put("fileId","split:unreadable").put("hashStatus","UNREADABLE").put("fileStable",false));
            yes(eligible(row));
        });
        scenario("new-platform signature UNKNOWN does not erase exact file IOC evidence",()->{
            JSONObject row=valid();file(row).put("signatureStatus","UNKNOWN_PLATFORM");yes(eligible(row));
        });
        scenario("USB and wireless ADB zero never become resolved",()->{
            for(String id:new String[]{"settings.adb","settings.wireless_adb"})
                for(Finding.Status status:new Finding.Status[]{Finding.Status.INFO,Finding.Status.PASS,Finding.Status.UNKNOWN})
                    same("VERIFICATION_UNAVAILABLE",outcome(id,"WARN",status));
        });
        scenario("developer option zero never becomes resolved",()->{
            for(Finding.Status status:new Finding.Status[]{Finding.Status.INFO,Finding.Status.PASS,Finding.Status.UNKNOWN})
                same("VERIFICATION_UNAVAILABLE",outcome("settings.developer","WARN",status));
        });
        scenario("ADB or developer warning remains a warning",()->{
            for(String id:new String[]{"settings.adb","settings.wireless_adb","settings.developer"})
                same("STILL_REQUIRES_REVIEW",outcome(id,"WARN",Finding.Status.WARN));
        });
        scenario("observable setting WARN to INFO gives bounded signal-not-seen outcome",()->{
            for(String id:new String[]{"settings.accessibility","settings.admin","settings.notifications","network.vpn","network.proxy","network.user_ca"})
                same("SIGNAL_NOT_REOBSERVED",outcome(id,"WARN",Finding.Status.INFO));
        });
        scenario("observable setting ALERT to INFO is still only a bounded observation",()->same("SIGNAL_NOT_REOBSERVED",outcome("settings.accessibility","ALERT",Finding.Status.INFO)));
        scenario("remaining warning or alert never becomes resolved",()->{
            same("STILL_REQUIRES_REVIEW",outcome("settings.accessibility","WARN",Finding.Status.WARN));
            same("STILL_REQUIRES_REVIEW",outcome("settings.admin","WARN",Finding.Status.ALERT));
        });
        scenario("UNKNOWN result never becomes resolved",()->same("VERIFICATION_UNAVAILABLE",outcome("network.vpn","WARN",Finding.Status.UNKNOWN)));
        scenario("null finding is verification unavailable",()->same("VERIFICATION_UNAVAILABLE",RemediationRules.reobservedOutcome("settings.admin","WARN",null)));
        scenario("missing finding id is verification unavailable",()->{
            same("VERIFICATION_UNAVAILABLE",RemediationRules.reobservedOutcome("","WARN",finding("",Finding.Status.INFO)));
            same("VERIFICATION_UNAVAILABLE",RemediationRules.reobservedOutcome(null,"WARN",finding("settings.admin",Finding.Status.INFO)));
        });
        scenario("a different finding cannot prove a requested setting changed",()->same("VERIFICATION_UNAVAILABLE",
                RemediationRules.reobservedOutcome("settings.accessibility","WARN",finding("network.vpn",Finding.Status.INFO))));
        scenario("generic Galaxy action cannot claim the setting was fixed",()->{
            for(String id:new String[]{"galaxy.app_protection","galaxy.auto_blocker","coverage.hardware"})
                same("RECHECKED_NO_COMPLETION_CLAIM",outcome(id,"WARN",Finding.Status.INFO));
        });
        scenario("no previous alert means no remediation completion claim",()->same("RECHECKED_NO_COMPLETION_CLAIM",outcome("settings.accessibility","INFO",Finding.Status.INFO)));
        scenario("PASS is not substituted for a settings-specific observation",()->same("RECHECKED_NO_COMPLETION_CLAIM",outcome("settings.admin","WARN",Finding.Status.PASS)));
        scenario("package absence wording is scoped to the current profile",()->{
            String label=RemediationRules.outcomeLabel("PACKAGE_NOT_PRESENT");yes(label.contains("현재 프로필"));yes(label.contains("미발견"));no(label.contains("복구 완료"));
        });
        System.out.println("Remediation tests: "+scenarios+" scenarios, "+assertions+" assertions, "+failures+" failures");
        if(failures>0) throw new AssertionError("Remediation test failures");
    }
    private static JSONObject valid() {
        return new JSONObject().put("packageName",PKG).put("system",false).put("confirmedIoc",true)
                .put("remediationEligible",true).put("remediationPackageName",PKG).put("versionCode",1).put("lastUpdateTime",1_700_000_000_000L)
                .put("apkChangedDuringScan",false).put("apkInspectionComplete",true)
                .put("iocMatches",new JSONArray().put(new JSONObject().put("fileId","base").put("sha256",HASH)))
                .put("apkFiles",new JSONArray().put(new JSONObject().put("fileId","base").put("sha256",HASH)
                        .put("hashStatus","HASHED").put("fileStable",true).put("matchConfirmed",true)));
    }
    private static JSONObject match(JSONObject row) {return row.getJSONArray("iocMatches").getJSONObject(0);}
    private static JSONObject file(JSONObject row) {return row.getJSONArray("apkFiles").getJSONObject(0);}
    private static boolean eligible(JSONObject row) {return RemediationRules.eligible(row,OWN);}
    private static Finding finding(String id,Finding.Status status) {return new Finding(id,"test","test",status,"test","test");}
    private static String outcome(String id,String before,Finding.Status after) {return RemediationRules.reobservedOutcome(id,before,finding(id,after));}
    private static String repeat(char c) {char[] chars=new char[64];java.util.Arrays.fill(chars,c);return new String(chars);}
    private static void scenario(String name,Checked code) {
        scenarios++;try{code.run();System.out.println("PASS "+name);}catch(Throwable e){failures++;System.out.println("FAIL "+name+": "+e);}
    }
    private static void same(Object expected,Object actual) {assertions++;if(!java.util.Objects.equals(expected,actual))throw new AssertionError(expected+" != "+actual);}
    private static void yes(boolean value) {assertions++;if(!value)throw new AssertionError("expected true");}
    private static void no(boolean value) {yes(!value);}
}

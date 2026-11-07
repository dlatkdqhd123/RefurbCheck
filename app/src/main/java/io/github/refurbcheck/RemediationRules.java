package io.github.refurbcheck;

import org.json.JSONArray;
import org.json.JSONObject;

/** Pure fail-closed eligibility and outcome rules. Imported reports never enter the action flow. */
final class RemediationRules {
    private RemediationRules() { }
    static boolean eligible(JSONObject row,String ownPackage) {
        if(row==null) return false;
        String pkg=row.optString("packageName","");
        if(!pkg.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+")||pkg.equals(ownPackage)) return false;
        if(!Boolean.FALSE.equals(row.opt("system"))||!Boolean.TRUE.equals(row.opt("confirmedIoc"))||!Boolean.TRUE.equals(row.opt("remediationEligible"))
                ||row.optBoolean("apkChangedDuringScan")||!pkg.equals(row.optString("remediationPackageName"))) return false;
        if(!nonnegativeInteger(row.opt("versionCode"))||!nonnegativeInteger(row.opt("lastUpdateTime"))) return false;
        JSONArray matches=row.optJSONArray("iocMatches"),files=row.optJSONArray("apkFiles");
        if(matches==null||matches.length()==0||files==null||files.length()==0) return false;
        for(int i=0;i<matches.length();i++) {
            JSONObject match=matches.optJSONObject(i);if(match==null) return false;
            if(!(match.opt("sha256") instanceof String)||!(match.opt("fileId") instanceof String)) return false;
            String sha=match.optString("sha256",""),id=match.optString("fileId","");
            if(!sha.matches("(?i)[0-9a-f]{64}")||!(id.equals("base")||(id.startsWith("split:")&&id.length()>6))) return false;
            boolean found=false;
            for(int j=0;j<files.length();j++) {
                JSONObject file=files.optJSONObject(j);
                if(file!=null&&id.equals(file.optString("fileId"))) {
                    if(found||!"HASHED".equals(file.optString("hashStatus"))||!Boolean.TRUE.equals(file.opt("fileStable"))||!Boolean.TRUE.equals(file.opt("matchConfirmed"))
                            ||!(file.opt("sha256") instanceof String)
                            ||!sha.equalsIgnoreCase(file.optString("sha256"))) return false;
                    found=true;
                }
            }
            if(!found) return false;
        }
        return true;
    }
    private static boolean nonnegativeInteger(Object value) {
        return (value instanceof Integer||value instanceof Long)&&((Number)value).longValue()>=0;
    }
    static String reobservedOutcome(String findingId,String before,Finding after) {
        if(findingId==null||findingId.isEmpty()||after==null||!findingId.equals(after.id)||after.status==Finding.Status.UNKNOWN)
            return "VERIFICATION_UNAVAILABLE";
        if(findingId.equals("settings.adb")||findingId.equals("settings.wireless_adb")||findingId.equals("settings.developer"))
            return after.status==Finding.Status.WARN?"STILL_REQUIRES_REVIEW":"VERIFICATION_UNAVAILABLE";
        if(after.status==Finding.Status.ALERT||after.status==Finding.Status.WARN) return "STILL_REQUIRES_REVIEW";
        boolean observableSetting=findingId.equals("settings.accessibility")||findingId.equals("settings.admin")
                ||findingId.equals("settings.notifications")
                ||findingId.equals("network.vpn")||findingId.equals("network.proxy")||findingId.equals("network.user_ca");
        if(observableSetting&&("WARN".equals(before)||"ALERT".equals(before))&&after.status==Finding.Status.INFO)
            return "SIGNAL_NOT_REOBSERVED";
        return "RECHECKED_NO_COMPLETION_CLAIM";
    }
    static String outcomeLabel(String outcome) {
        switch(outcome) {
            case "SCREEN_OPENED":return "조치 화면 열림";
            case "SCREEN_RETURNED":return "조치 화면 복귀 · 결과 확인";
            case "OPEN_FAILED":return "화면 열기 실패";
            case "PREFLIGHT_BLOCKED":return "앱 변경·확인 제한으로 삭제 보류";
            case "PACKAGE_NOT_PRESENT":return "현재 프로필 앱 목록에서 미발견";
            case "PACKAGE_STILL_PRESENT":return "앱이 남아 있음 · 취소/차단/재설치 가능";
            case "SIGNAL_NOT_REOBSERVED":return "해당 범위에서 이전 신호 미재발견";
            case "STILL_REQUIRES_REVIEW":return "재검사 후에도 확인 필요";
            case "VERIFICATION_UNAVAILABLE":return "조치 결과를 자동 확인할 수 없음";
            case "RECHECKED_NO_COMPLETION_CLAIM":return "재검사 완료 · 전체 복구 판정 아님";
            default:return outcome;
        }
    }
}

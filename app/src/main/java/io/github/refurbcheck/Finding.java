package io.github.refurbcheck;

import org.json.JSONObject;

/** A bounded observation, never a certificate that a phone is clean. */
public final class Finding {
    public enum Status { PASS, INFO, WARN, ALERT, UNKNOWN }
    public final String id, category, title, detail, action;
    public final Status status;
    public final long observedAt=System.currentTimeMillis();
    public Finding(String id, String category, String title, Status status, String detail, String action) {
        this.id=id; this.category=category; this.title=title; this.status=status;
        this.detail=detail; this.action=action;
    }
    public JSONObject toJson() {
        JSONObject o=new JSONObject();
        try { o.put("id",id); o.put("category",category); o.put("title",title); o.put("status",status.name()); o.put("detail",detail); o.put("action",action);o.put("observedAt",observedAt);o.put("evidenceSource",evidenceSource()); } catch(Exception ignored) { }
        return o;
    }
    public String evidenceSource() {
        if(id.startsWith("coverage.")||id.equals("attestation_external")) return "NOT_VERIFIED";
        if(id.contains("revocation")||id.startsWith("ioc.")||id.equals("apk.ioc")||id.startsWith("malware.")) return "BUNDLED_REFERENCE_COMPARISON";
        if(id.startsWith("attestation")) return "LOCAL_CERTIFICATE_ANALYSIS";
        if(id.startsWith("apk.")||id.startsWith("root.paths")||id.startsWith("root.maps")) return "LOCAL_FILE_OBSERVATION";
        return "OS_REPORTED";
    }
    public String evidenceLabel() {
        switch(evidenceSource()) {
            case "NOT_VERIFIED":return "검증 미완료";
            case "BUNDLED_REFERENCE_COMPARISON":return "내장 기준자료 대조";
            case "LOCAL_CERTIFICATE_ANALYSIS":return "기기 내 인증서 분석";
            case "LOCAL_FILE_OBSERVATION":return "기기 내 파일 관측";
            default:return "OS 자기 보고";
        }
    }
}

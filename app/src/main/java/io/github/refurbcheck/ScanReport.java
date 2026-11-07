package io.github.refurbcheck;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public final class ScanReport {
    public final List<Finding> findings=new ArrayList<>();
    public final JSONObject evidence=new JSONObject();
    public JSONArray inventory=new JSONArray();
    public boolean inventoryComplete=false;
    public final long startedAt=System.currentTimeMillis();
    public final String reportId=UUID.randomUUID().toString();
    public long completedAt;
    public void add(Finding f) { findings.add(f); }
    public int count(Finding.Status status) { int n=0; for(Finding f:findings) if(f.status==status) n++; return n; }
    public String verdict() {
        if(count(Finding.Status.ALERT)>0) return "주의가 큰 징후 발견";
        if(count(Finding.Status.WARN)>0) return "확인이 필요한 항목 발견";
        boolean observed=false;
        for(Finding f:findings) if(!f.id.startsWith("coverage.")&&!f.id.equals("attestation_external")
                &&(f.status==Finding.Status.PASS||f.status==Finding.Status.INFO)) observed=true;
        if(!observed) return "검사 결과 확인 불가";
        if(count(Finding.Status.UNKNOWN)>0) return "미검증 항목이 남아 있습니다";
        return "관측 범위에서 뚜렷한 징후 없음";
    }
    public JSONObject toJson() {
        JSONObject o=new JSONObject(); JSONArray fs=new JSONArray();
        for(Finding f:findings) fs.put(f.toJson());
        try {
            o.put("schema", "refurbcheck-report-v2"); o.put("appVersion","1.4.0");
            o.put("reportId",reportId);o.put("rulesVersion","2026-11-one-run-4");o.put("clockSource","device clock; not independently authenticated");
            o.put("startedAt",startedAt); o.put("completedAt",completedAt); o.put("verdict",verdict());
            o.put("unverifiedFindingCount",count(Finding.Status.UNKNOWN));o.put("allRequiredDomainsVerified",false);
            o.put("factoryOriginalVerified",false); o.put("malwareAbsenceVerified",false);
            o.put("physicalHardwareVerified",false); o.put("findings",fs); o.put("evidence",evidence);
            o.put("inventoryComplete",inventoryComplete); o.put("inventory",inventory);
            o.put("limitations","이 기기의 운영체제 안에서 수행한 참고 점검입니다. 기기 자체가 침해되면 결과가 속을 수 있습니다. 공장 출고 상태, 악성코드 부재, 물리 하드웨어 무변조를 보증하지 않습니다. 앱 목록과 인증서는 개인정보를 포함할 수 있으므로 보고서를 공개하지 마세요.");
        } catch(Exception ignored) { }
        return o;
    }
}

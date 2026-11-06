package io.github.refurbcheck;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.os.Build;
import org.json.JSONObject;

/** Samsung-specific availability observations; never substitutes for Knox server attestation. */
final class GalaxyInspector {
    static final String DEVICE_CARE="com.samsung.android.lool";
    static final String MEMBERS="com.samsung.android.voc";
    static final String AUTO_BLOCKER="com.samsung.android.rampart";
    private GalaxyInspector() { }
    static void inspect(Context context,ScanReport report) throws Exception {
        boolean samsung="samsung".equalsIgnoreCase(Build.MANUFACTURER)||"samsung".equalsIgnoreCase(Build.BRAND);
        JSONObject galaxy=new JSONObject().put("identifiedByOs",samsung)
                .put("source","OS manufacturer/brand and current-profile package metadata; not manufacturer-authenticated")
                .put("deviceCare",availability(context,DEVICE_CARE))
                .put("members",availability(context,MEMBERS))
                .put("autoBlocker",availability(context,AUTO_BLOCKER))
                .put("autoBlockerEnabledVerified",false).put("samsungScanResultVerified",false)
                .put("knoxServerAttestationPerformed",false);
        report.evidence.put("galaxy",galaxy);
        if(!samsung) return;
        report.add(new Finding("galaxy.app_protection","갤럭시 보안","삼성 앱 보호 검사",Finding.Status.UNKNOWN,
                "디바이스 케어 패키지 조회: "+description(galaxy.getJSONObject("deviceCare"))+". 이 앱은 삼성의 검사 결과를 읽거나 대신 통과 처리하지 않습니다.",
                "조치 탭 → 삼성 앱 보호 열기. 설정 → 디바이스 케어 → 앱 보호 → 휴대전화 검사에서 직접 실행하고 결과를 확인하세요. 메뉴와 지원 여부는 모델·One UI·지역에 따라 다릅니다."));
        report.add(new Finding("galaxy.auto_blocker","갤럭시 보안","보안 위험 자동 차단",Finding.Status.UNKNOWN,
                "관련 패키지 조회: "+description(galaxy.getJSONObject("autoBlocker"))+". 패키지가 존재한다는 사실은 기능이 켜져 있다는 증거가 아닙니다.",
                "설정 → 보안 및 개인정보 보호 → 보안 위험 자동 차단을 확인하세요. GitHub APK 설치 후에는 브라우저/파일 앱의 외부 설치 허용을 해제하고 자동 차단을 다시 켜세요. 이 앱은 해당 설정을 자동으로 끄지 않습니다."));
        report.add(new Finding("coverage.knox_remote","갤럭시 보안","삼성 Knox 원격 증명",Finding.Status.UNKNOWN,
                "Samsung Enhanced Attestation의 서버 검증·nonce·삼성 서명된 기기 증명 서비스를 연결하지 않았습니다. Android 키 증명 또는 warranty 속성과 다른 검증입니다.",
                "OS 변조가 의심되면 판매자·삼성 서비스센터에 모델별 정품 펌웨어 및 Knox 상태 확인을 요청하세요. 실제 Warranty Bit가 변경된 경우 이 앱이나 공장 초기화로 되돌릴 수 없습니다."));
    }
    private static JSONObject availability(Context context,String name) throws Exception {
        JSONObject out=new JSONObject().put("packageName",name).put("present",false)
                .put("metadataOnly",true).put("publisherSignatureVerified",false);
        try {
            PackageInfo p=context.getPackageManager().getPackageInfo(name,0);
            out.put("present",true).put("enabled",p.applicationInfo!=null&&p.applicationInfo.enabled)
                    .put("versionName",p.versionName==null?"":p.versionName);
        } catch(android.content.pm.PackageManager.NameNotFoundException e) {
            out.put("result","not visible in current profile");
        } catch(RuntimeException e) { out.put("error",e.getClass().getSimpleName()); }
        return out;
    }
    private static String description(JSONObject value) {
        return value.optBoolean("present")?"현재 프로필에 표시됨 (활성화·발행자 진위 확인 아님)":"현재 프로필에서 확인하지 못함";
    }
}

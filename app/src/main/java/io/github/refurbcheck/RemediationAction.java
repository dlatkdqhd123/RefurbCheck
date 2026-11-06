package io.github.refurbcheck;

/** An explicit user action; none is a privileged/silent settings mutation. */
final class RemediationAction {
    enum Kind { ACCESSIBILITY, NOTIFICATIONS, DEVELOPER, SECURITY, KEYBOARDS, VPN, WIFI,
        APPS, UNKNOWN_SOURCES, DEVICE_CARE, MEMBERS, AUTO_BLOCKER, UPDATE, PLAY_PROTECT, SERVICE, UNINSTALL }
    final Kind kind;
    final String packageName,findingId,beforeStatus;
    RemediationAction(Kind kind) { this(kind,"","",""); }
    RemediationAction(Kind kind,String packageName,String findingId,String beforeStatus) {
        this.kind=kind;this.packageName=packageName;this.findingId=findingId;this.beforeStatus=beforeStatus;
    }
    String id() { return kind.name()+(packageName.isEmpty()?"":":"+packageName); }
    String label() {
        switch(kind) {
            case ACCESSIBILITY:return "접근성 설정 열기";
            case NOTIFICATIONS:return "알림 접근 설정 열기";
            case DEVELOPER:return "개발자 옵션 열기";
            case SECURITY:return "보안 설정 열기";
            case KEYBOARDS:return "키보드 설정 열기";
            case VPN:return "VPN 설정 열기";
            case WIFI:return "Wi-Fi 설정 열기";
            case APPS:return packageName.isEmpty()?"앱 권한·설정 열기":"검출 앱 설정·삭제 열기";
            case UNKNOWN_SOURCES:return "외부 앱 설치 허용 점검";
            case DEVICE_CARE:return "삼성 앱 보호 열기";
            case MEMBERS:return "Samsung Members 진단 열기";
            case AUTO_BLOCKER:return "자동 차단 설정 확인";
            case UPDATE:return "삼성 소프트웨어 업데이트 확인";
            case PLAY_PROTECT:return "Play Protect 검사로 이동";
            case SERVICE:return "삼성 공식 점검 안내";
            case UNINSTALL:return "일치 앱 삭제 확인창 열기";
            default:return "조치 화면 열기";
        }
    }
    String instruction() {
        switch(kind) {
            case ACCESSIBILITY:return "설치된 앱/서비스에서 본인이 허용하지 않은 접근성을 끄세요. 필요한 보조공학 앱은 유지하세요.";
            case NOTIFICATIONS:return "본인이 허용하지 않은 앱의 알림 접근을 해제하세요.";
            case DEVELOPER:return "사용하지 않는 USB·무선 디버깅을 끄고 기존 디버깅 허용 기기도 확인하세요. 이 앱은 일반 앱 조회값 0을 해제 완료로 판정하지 않습니다.";
            case SECURITY:return "보안 및 개인정보 보호 → 기타 보안 설정에서 기기 관리자 앱·사용자 인증서를 확인하세요. 회사 관리 항목은 관리자와 먼저 확인하세요.";
            case KEYBOARDS:return "일반 → 키보드 목록 및 기본에서 본인이 사용하는 입력기만 허용하세요.";
            case VPN:return "출처를 모르는 VPN 연결·프로필을 확인하고 해제하세요. 회사망과 보안 서비스에도 쓰이는 기능입니다.";
            case WIFI:return "현재 Wi-Fi → 네트워크 관리/고급 → 프록시를 확인하세요. 회사·학교에서 필요한 설정일 수 있습니다.";
            case APPS:return packageName.isEmpty()?"앱 정보 → 권한에서 불필요한 민감 권한을 해제하세요. 권한 보유만으로 악성 앱이라고 판단하지 않습니다.":
                    "검출 출처와 설치 목적을 확인하세요. 원치 않는 앱이면 이 앱 정보 화면에서 삭제하거나 권한을 해제하세요. 감시·관리 도구의 동의된 사용과 보안 시험 자료도 검출될 수 있습니다. 돌아오면 다시 검사합니다.";
            case UNKNOWN_SOURCES:return "보안 및 개인정보 보호 → 기타 보안 설정 → 출처를 알 수 없는 앱 설치에서 설치에 사용한 브라우저·파일 앱의 허용을 끄세요.";
            case DEVICE_CARE:return "디바이스 케어 → 앱 보호 → 휴대전화 검사를 실행하세요. 메뉴가 보이지 않으면 해당 모델의 지원 여부를 삼성 공식 안내에서 확인하세요. 이 앱은 삼성 검사 결과를 자동으로 읽지 못합니다.";
            case MEMBERS:return "Samsung Members → 도움받기/지원 → 휴대전화 진단을 실행하세요. 기능 정상 여부 검사로 내부 부품 무변조까지 증명되지는 않습니다.";
            case AUTO_BLOCKER:return "설정 → 보안 및 개인정보 보호 → 보안 위험 자동 차단을 확인하세요. APK 설치 때문에 일시 변경했다면 설치 후 다시 켜세요. 지원 모델·One UI에 따라 메뉴가 다릅니다.";
            case UPDATE:return "설정 → 소프트웨어 업데이트 → 다운로드 및 설치에서 공식 업데이트를 확인하세요. 다운로드·재부팅 여부는 삼성 화면에서 결정하세요.";
            case PLAY_PROTECT:return "Play 스토어 → 프로필 → Play Protect → 검사를 실행하세요. 이 앱에서 Play Protect 통과 여부를 확인하지는 못합니다.";
            case SERVICE:return "삼성 공식 안내에서 가까운 서비스센터와 점검 방법을 확인하세요. OS 변조·Knox 변경·부품 의심은 모델별 공식 펌웨어 및 실물 확인이 필요합니다. 임의로 부트로더를 잠그거나 초기화하지 마세요.";
            case UNINSTALL:return "삭제 직전에 앱 버전·업데이트 시각·현재 APK 해시를 다시 확인합니다. 그 후 Android 삭제 확인창에서 승인하면 앱과 해당 앱의 데이터가 제거됩니다. 삭제가 차단되면 기기 관리자 여부를 먼저 확인하세요.";
            default:return "변경 후 이 앱으로 돌아오면 다시 점검합니다.";
        }
    }
    static RemediationAction forFinding(Finding f) {
        Kind k=null;String id=f.id;
        if(id.equals("policy.factory_reset")) return new RemediationAction(Kind.APPS,"",id,f.status.name());
        if(id.equals("apps.capability_combinations")) return new RemediationAction(Kind.APPS,"",id,f.status.name());
        if(id.equals("policy.management_expected_absent")||id.equals("settings.management_roles"))
            return new RemediationAction(Kind.SECURITY,"",id,f.status.name());
        if(id.equals("policy.special_access")) return new RemediationAction(Kind.ACCESSIBILITY,"",id,f.status.name());
        if(id.startsWith("capabilities.app.")) return new RemediationAction(Kind.APPS,id.substring("capabilities.app.".length()),id,f.status.name());
        if(id.startsWith("malware.app.")) {
            String pkg=id.substring("malware.app.".length());
            if(pkg.length()<=255&&pkg.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"))
                return new RemediationAction(Kind.APPS,pkg,id,f.status.name());
            return null;
        }
        if(id.equals("settings.accessibility")) k=Kind.ACCESSIBILITY;
        else if(id.equals("settings.notifications")) k=Kind.NOTIFICATIONS;
        else if(id.equals("settings.admin")||id.equals("network.user_ca")) k=Kind.SECURITY;
        else if(id.equals("settings.keyboards")) k=Kind.KEYBOARDS;
        else if(id.equals("settings.developer")||id.equals("settings.adb")||id.equals("settings.wireless_adb")) k=Kind.DEVELOPER;
        else if(id.equals("network.vpn")) k=Kind.VPN;
        else if(id.equals("network.proxy")) k=Kind.WIFI;
        else if(id.equals("build.patch")) k=Kind.UPDATE;
        else if(id.equals("apps.sensitive")) k=Kind.APPS;
        else if(id.equals("apps.sources")) k=Kind.UNKNOWN_SOURCES;
        else if(id.equals("galaxy.auto_blocker")) k=Kind.AUTO_BLOCKER;
        else if(id.equals("coverage.hardware")) k=Kind.MEMBERS;
        else if(id.equals("coverage.malware")||id.equals("galaxy.app_protection")||id.equals("apk.ioc")
                ||id.equals("malware.reference_scan")||id.equals("malware.freshness")) k=Kind.DEVICE_CARE;
        else if(id.equals("coverage.play_integrity")) k=Kind.PLAY_PROTECT;
        else if(id.equals("coverage.factory")||id.equals("coverage.knox_remote")||id.startsWith("boot.")
                ||id.equals("build.warranty")||id.equals("build.type")||id.equals("system.selinux")
                ||id.startsWith("root.")||id.equals("attestation_boot")||id.equals("attestation_binding")
                ||id.equals("attestation_correlation")||id.equals("attestation_revocation_snapshot")) k=Kind.SERVICE;
        return k==null?null:new RemediationAction(k,"",id,f.status.name());
    }
}

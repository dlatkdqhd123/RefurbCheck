# RefurbCheck 1.1 검증 설계와 Galaxy 조치 근거

조사 기준일: 2026-11-06. 공식 제품 문서, 제조사 지원 문서, Android 공개 API 문서를 사용했다. 이 문서는 **참고한 절차와 설계 요구사항**을 기록한다. 실제 구현 범위와 실행 검증 결과는 소스 코드 및 해당 릴리스의 검증 문서를 함께 확인해야 한다. 사유 탐지 엔진을 복제하거나 유료 서비스를 구매·호출한 것은 아니다.

## 1. 무엇을 증명할 것인가

서로 다른 주장을 하나의 안전 점수로 합치지 않는다.

| 주장 | 필요한 근거 | 단독으로 충분하지 않은 근거 |
| --- | --- | --- |
| 관측한 설정이 정상이다 | 읽은 값, 관측 시각, 읽기 성공 여부 | 값이 없거나 접근이 거부된 상태 |
| APK 내용과 서명이 일치한다 | 실제 base/split 바이트의 서명 검증, 해시, 서명자 일관성 | PackageManager가 반환한 서명자 메타데이터 |
| 제조사가 인증한 부팅 상태다 | 신뢰한 루트·서명·fresh challenge·증명 필드·폐기 상태의 검증 | `getprop` 값, 로컬에서만 확인한 증명 |
| 알려진 위협 지표와 일치한다 | 지표 출처·버전·종류 및 일치한 원자료 | 권한 또는 패키지명 하나만 일치 |
| 기기의 모든 소프트웨어가 제조사 기준과 같다 | 해당 모델·지역·빌드에 대한 인증된 기준 자료와 충분한 측정 범위 | 출처가 확인되지 않은 참조 JSON과 일부 필드 일치 |
| 모든 하드웨어가 정품이며 악성 개조가 없다 | 제조사·수리 기관의 물리적 검사와 적절한 진위 검증 | 센서·버튼·카메라의 기능 검사 통과 |

서명 유효성, 앱의 무해성, 장치의 부팅 무결성은 다른 결론이다. 해시가 같은 보고서를 다시 받았다는 사실도 보고서 내용의 진실성을 보증하지 않는다. 조치 후 특정 신호가 사라졌다면 그 신호의 해소만 기록하며, 장치 전체를 안전하다고 인증하지 않는다.

## 2. 상용 제품에서 공개한 절차

| 공식 자료 | 공개된 절차·대상 | RefurbCheck에서 참고할 점 | 한계 |
| --- | --- | --- | --- |
| [Samsung Knox Enhanced Attestation v3][knox-attestation] | 짧은 유효기간 nonce, 장치 증명, Samsung 루트 기반 인증서·서명 확인, 서버 verdict | 로컬 관측과 독립 검증 구분, challenge 일치, 재전송 방지 | 지원 장치와 제조사 API/서버 구성이 필요하다. 일반 앱의 속성 읽기와 동등하지 않다. |
| [Zimperium resilience 기술 자료][zimperium-paper] | 루팅·SELinux·디버깅·재서명·런타임 변조 등 복수 신호 | 하나의 휴리스틱으로 전체 판정하지 않기, 자체 앱과 검사 대상의 무결성 구분 | 독점 엔진·성능을 공개한 명세가 아니다. 자료는 구형 MASVS/MSTG 번호를 사용한다. |
| [Microsoft의 Lookout 연동 문서][lookout] | 가능한 범위의 장치·앱·네트워크 원격측정 자료를 클라우드로 보내 위험 평가 | 장치·앱·네트워크 범주와 자료 수집 범위 구분 | 일반 APK가 상용 엔진·클라우드 지능·관리 권한을 그대로 제공할 수 있다는 뜻은 아니다. |
| [iVerify Android Intrusion Logging 연구][iverify-il] | 실제 Android 로그의 DNS·연결·프로세스·보안 이벤트를 시간순으로 교차 분석 | 수집 시각·최종 이벤트 시각·원자료 해시·공백을 함께 기록 | 2026-08-04 연구의 관측 결과다. 기능 활성화 이전 기록은 없고 사용자 조작 및 ADB/전문 도구가 필요한 수집 절차다. |
| [Phonecheck diagnostics][phonecheck] | 기능·배터리·외관·잠금 상태 등 정해진 검사 프로필과 개별 결과 | 모델별 적용 범위, 재검사, 항목별 결과 | 해당 페이지의 구체적 정품 부품 검증 설명은 iPhone/일부 Mac 대상이다. Android 전체 부품 진위로 확대하지 않는다. |
| [Blancco 결과 집계 KB][blancco-result] | 실행된 항목 성공 여부와 NOT PERFORMED 구분 | 검사 실행 범위와 결과를 별도로 기록 | 2020-03-13 KB에서 Not available은 전체 결과에 영향을 주지 않는다. PASS가 모든 항목 검사 완료를 의미하지 않는다. |
| [Cellebrite 수집 절차 설명][cellebrite] | 반복 가능한 획득, 해시 확인, 감사 기록 | 버전·시각·원자료·오류·보고서 해시 기록 | 해시는 획득물의 변경 확인 수단이며 원본 기기가 안전하다는 증명은 아니다. |

Blancco는 [최소/전체 검사 세트 구성][blancco-profile]과 [일부 항목의 사용자 상호작용][blancco-interaction]도 설명한다. 이 KB들은 각각 2019년·2017년 문서이므로 최신 제품의 모든 기능을 보장하는 사양으로 사용하지 않는다. Zimperium의 [Samsung Knox 연동][zimperium-knox]처럼 관측 권한이 제조사 기능에 의존하는 경우도 있다.

### 우선순위

1. 접근 가능한 base/split APK 전체 바이트 해시 및 내용 서명 검증. 파일 교체·읽기 오류·누락을 기록한다.
2. 자기보고, 로컬 암호 검증, 외부 검증, 인증된 제조사 기준의 증거 등급을 구분한다.
3. 정상/이상 외에 미지원·권한 부족·실행 오류·미실시를 분리하고 검사 범위를 표시한다.
4. 보고서에 앱·규칙 버전, 시각, 원자료 해시, 기준 자료 출처를 보존한다.
5. IOC의 출처·최신성·일치 종류를 표시하고 권한·설정만으로 악성 앱을 단정하지 않는다.
6. 제조사 검사 또는 외부 포렌식이 필요한 항목을 로컬 검사 성공으로 대체하지 않는다.

## 3. Galaxy에서 바로 이어서 할 수 있는 조치

일반 앱이 보안 설정을 몰래 변경하는 흐름을 만들지 않는다. 검사 결과에서 관련 시스템 화면이나 삼성 앱을 열고, 사용자가 대상과 영향을 확인한 뒤 조치하며, RefurbCheck로 돌아왔을 때 다시 관측하는 방식이다.

| 목적 | 공식 소비자 경로 | 앱에서 제공할 수 있는 연결 | 판정 한계 |
| --- | --- | --- | --- |
| 악성 앱 추가 검사 | 설정 → 디바이스 케어 → 앱 보호 → 휴대전화 검사 | 설치된 Device Care 열기, 없거나 실행 진입점이 없으면 설정과 경로 안내 | RefurbCheck가 삼성 검사 결과를 자동으로 읽거나 실행했다고 표시하지 않는다. |
| 기능·공식 소프트웨어 관련 자가 진단 | Samsung Members → 진단/도움받기 → 휴대전화 진단 | Samsung Members 열기 또는 삼성의 공식 스토어 페이지 | 검사 항목·탭 이름은 버전에 따라 다르며 여러 항목은 사용자 조작이 필요하다. |
| 추가 앱 설치·USB 공격 경로 제한 | 설정 → 보안 및 개인정보 보호 → 보안 위험 자동 차단 | 보안 설정 열기와 경로 안내 | One UI 6 이상. 기존 침해가 제거됐다는 인증이 아니다. |
| 더 강한 보호 정책 | 위 경로 → 최대 제한 | 기능 영향 설명 후 사용자가 선택 | One UI 6.1.1 이상. 업무 프로필·기기 관리자 등 사용에 영향을 줄 수 있다. |
| 문제 앱 제거 | 설정 → 애플리케이션 → 대상 앱 → 삭제 | 대상별 시스템 제거 확인 화면 | 사용자가 최종 확인한다. 시스템 앱/관리 정책 등에 따라 삭제 불가일 수 있다. |
| 보안 업데이트 확인 | 설정 → 소프트웨어 업데이트 → 다운로드 및 설치 | 시스템 설정과 공식 경로 안내 | 모델·통신사·지원 기간에 따라 제공 여부가 달라진다. 업데이트가 출고 이미지 전체 동일성을 인증하지 않는다. |
| 수리 의뢰 전 개인정보 보호 | 설정 → 디바이스 케어 → 수리 모드 | 공식 사용 안내 및 Device Care | 수리용 데이터 보호 기능이다. 악성코드 제거·부품 진위 검사가 아니다. |

공식 근거: [앱 보호와 안전 모드][samsung-malware], [Samsung Members/Device Care 진단][samsung-diagnostics], [자동 차단 한국어 안내][samsung-autoblocker], [소프트웨어 업데이트][samsung-update], [수리 모드][samsung-maintenance]. 메뉴와 지원 범위는 모델·지역·One UI 버전에 따라 달라질 수 있다.

### GitHub APK 설치와 자동 차단

보안 위험 자동 차단은 Play Store/Galaxy Store 외 출처의 APK 설치를 막을 수 있다. RefurbCheck의 GitHub APK 배포 흐름에서는 사용자가 선택한 릴리스와 서명/해시를 확인한 뒤 필요한 설치 승인을 거쳐야 한다. 설치 후 브라우저/파일 앱의 ‘출처를 알 수 없는 앱 설치’ 허용을 끄고 자동 차단을 다시 활성화하도록 안내한다. 앱이 보호 기능을 끄거나 켰다고 주장하지 않는다. 공식 근거: [삼성 자동 차단 안내][samsung-autoblocker].

### 실제 확인한 삼성 패키지

| 앱 | 확인한 패키지 | 1차 출처 | 연결 원칙 |
| --- | --- | --- | --- |
| Device Care | `com.samsung.android.lool` | [Samsung Electronics 공식 Play 등록][devicecare-play], [Samsung Developer 문서][samsung-app-management] | `getLaunchIntentForPackage` 결과가 있을 때만 실행한다. 없으면 시스템 설정으로 연결한다. |
| Samsung Members | `com.samsung.android.voc` | [Samsung Electronics 공식 Play 등록][members-play] | 설치된 앱의 실행 진입점 또는 공식 HTTPS 스토어 페이지를 사용한다. |
| Auto Blocker | `com.samsung.android.rampart` | [삼성 Galaxy Store 등록][autoblocker-store] | 패키지의 존재만으로 기능 켜짐을 판정하지 않는다. 공개된 안정적 설정 API가 확인되지 않아 보안 설정에서 사용자가 확인한다. |

패키지명만으로 설치된 앱이 정품임을 인증할 수는 없다. 삼성 앱 실행은 존재·실행 가능 여부를 검사하고, APK·서명 검증 결과와 충돌하면 안내를 표시해야 한다. 내부 Activity 이름을 추측하여 강제로 호출하는 방식은 사용하지 않는다. Samsung Developer가 공개한 Device Care 딥 링크는 배터리의 Sleeping/Deep sleeping/Never sleeping 목록용이며, 이를 악성코드 검사 실행 API로 해석하지 않는다.

## 4. Android 공개 API와 권한 경계

현재 프로젝트의 compileSdk/targetSdk 35에 맞는 공개 화면 연결을 우선한다. 모든 연결은 실제 처리 Activity가 있는지 확인하고 `ActivityNotFoundException`/`SecurityException`에 대해 설정 첫 화면과 수동 경로를 제공한다.

| 작업 | 공개 API | 입력·주의 |
| --- | --- | --- |
| 특정 앱 정보 | `Settings.ACTION_APPLICATION_DETAILS_SETTINGS` | `package:<정확한 패키지명>` URI |
| 접근성 권한 | `Settings.ACTION_ACCESSIBILITY_SETTINGS` | 사용자가 대상 서비스 해제 |
| 알림 접근 | `Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS` | 일반 목록; API 30 이상 상세 화면은 공개 component extra를 사용할 수 있음 |
| 입력기 | `Settings.ACTION_INPUT_METHOD_SETTINGS` | 사용자가 기본/활성 입력기 확인 |
| VPN | `Settings.ACTION_VPN_SETTINGS` | API 24 이상, 사용자가 해당 연결·프로필 확인 |
| 개발자/USB 디버깅 | `Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS` | 사용자가 USB/무선 디버깅 및 허용 컴퓨터 상태 확인 |
| 알 수 없는 앱 설치 | `Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES` | API 26 이상; 선택적으로 대상 패키지 URI |
| 다른 앱 위에 표시 | `Settings.ACTION_MANAGE_OVERLAY_PERMISSION` | 공개 관리 화면; 버전에 따라 대상 직접 진입이 달라질 수 있음 |
| 일반 권한·강제 종료·사용 중지 | 앱 정보 화면 | 실제 수행과 허용 여부는 시스템 UI/정책이 결정 |
| 기기 관리자·사용자 CA | `Settings.ACTION_SECURITY_SETTINGS` | 공개 보안 첫 화면과 모델별 경로 안내 |
| 전체 설정·업데이트 안내 | `Settings.ACTION_SETTINGS` | 소프트웨어 업데이트 경로 제공 |

출처: [Android Settings API][android-settings]. 공개 reference에서 `ACTION_DEVICE_ADMIN_SETTINGS`, `ACTION_TRUSTED_CREDENTIALS_*`를 공개 상수로 확인하지 못했으므로 이를 공개 API라고 문서화하지 않는다. 최신 reference의 `ACTION_SYSTEM_UPDATE_SETTINGS`는 version 36.1 추가이므로 compileSdk 35 코드에 직접 사용하지 않는다.

### 제거 요청

- `Intent.ACTION_UNINSTALL_PACKAGE`는 `package:` URI로 시스템 제거 UI를 연다. API 29부터 deprecated지만 공개 API로 남아 있으며, API 28 이상을 target하는 앱은 `REQUEST_DELETE_PACKAGES`가 필요하다.
- `REQUEST_DELETE_PACKAGES`는 제거 **요청** 권한이고, `DELETE_PACKAGES`와 같은 무인 삭제 권한이 아니다.
- 문서가 대안으로 안내하는 `PackageInstaller.uninstall`에도 호출자 조건과 결과 처리 의무가 있다. RefurbCheck를 device owner/installer인 것처럼 가정하지 않는다.
- 제거 화면을 열었거나 취소 화면에서 돌아왔다는 사실을 삭제 성공으로 처리하지 않는다. 해당 패키지/버전을 재조회하고 삭제됨·여전히 설치됨·접근 불가를 구분한다.
- 대상 앱의 이름·패키지·탐지 근거를 보여 주고 시스템 앱은 일괄 삭제 대상으로 삼지 않는다. 활성 기기 관리자가 삭제를 막으면 관련 설정과 삼성 안내로 연결한다.

출처: [Intent의 ACTION_UNINSTALL_PACKAGE][android-intent], [REQUEST_DELETE_PACKAGES/DELETE_PACKAGES][android-permissions], [PackageInstaller][android-packageinstaller], [삼성 앱 삭제 안내][samsung-delete].

### 일반 앱이 직접 변경할 수 없는 설정

[Settings.Secure 문서][android-secure]는 일반 앱이 secure 설정 데이터베이스를 직접 또는 `put` 메서드로 수정할 수 없으며 사용자가 시스템 UI에서 바꿔야 한다고 명시한다. [WRITE_SECURE_SETTINGS][android-permissions]는 일반 타사 앱용 권한이 아니다. ADB 관련 값은 [Settings.Global][android-global]에 속한다. 진단을 위해 루트·ADB 특권·접근성 자동 클릭을 요구하여 이 경계를 우회하지 않는다.

조사 당시 최신 `Settings.Global.ADB_ENABLED`와 `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED` 문서는 타사 앱에 항상 0을 반환한다고 설명한다. 해당 페이지가 이 제한의 도입 버전까지 명확히 구분하지 않으므로, 0을 관측했다는 사실만으로 USB 디버깅·개발자 옵션이 꺼졌거나 조치가 성공했다고 확정하지 않는다. 반환값의 신뢰 제한을 표시하고 개발자 옵션에서 사용자가 확인하도록 한다. 오래된 OS에서 실제 상태가 관측되는 경우도 전체 Galaxy 버전에 일반화하지 않는다.

[DevicePolicyManager][android-dpm]의 `removeActiveAdmin`은 자기 앱의 관리 component만 해제할 수 있다. `uninstallCaCert`는 device/profile owner 또는 위임받은 인증서 설치자가 사용하는 관리 API다. 일반 앱이 다른 앱의 관리자 권한·접근성 권한·사용자 CA를 조용히 제거할 수 있다고 표시하지 않는다. CA는 조직 Wi-Fi/VPN에서 정상적으로 사용될 수 있으므로 확인된 대상만 사용자가 검토한다. [Android 사용자 인증서 제거 안내][android-certificates]는 인증서 제거가 관련 연결에 영향을 줄 수 있음을 설명한다.

## 5. Knox Warranty Bit와 전문 점검의 경계

[삼성 Knox 공식 KB][knox-warranty]는 Warranty Bit를 한 번만 변경 가능한 e-fuse로 설명하고, 이미 tripped된 상태는 되돌릴 수 없으며 Knox 서비스 복구에는 PBA 하드웨어 교체가 필요하다고 명시한다. 앱 삭제·캐시 정리·공장 초기화·순정 펌웨어 재설치로 이 비트를 복구한다고 약속하지 않는다.

[Knox FAQ][knox-faq]에는 모델군별 다운로드 모드에서 Warranty Void를 확인하는 절차가 있다. 일반 앱이 읽은 `warranty_bit` 속성은 커널/OS 자기보고이며 해당 화면 또는 Knox 서버 증명과 같은 증거가 아니다. 모델이 확정되지 않은 상태에서 부팅 키 조합이나 플래시 도구를 자동 실행하지 않는다. 다운로드 모드 확인과 부트로더 잠금 해제/재잠금은 다른 작업이다.

Knox Bit가 정상이라는 사실만으로 모든 부품이 출고 당시 부품이거나 모든 악성코드가 없다고 결론 내리지 않는다. 제조사 증명에서도 검증 대상·시각·기기 바인딩·지원 조건을 기록한다. 하드웨어 개조, 시스템 영역 변조가 의심되거나 공식 업데이트/자가 진단이 실패하면 Samsung Members의 지원 또는 삼성 서비스센터 점검으로 이어간다.

## 6. 조치 결과 기록의 최소 기준

조치 이력에는 대상 패키지/항목, 제안 근거, 열었던 화면, 조치 요청 시각, 복귀 후 재검사 시각과 변화만 기록한다. 시스템 화면을 띄운 단계는 ‘조치 화면 열림’이며 ‘해결됨’이 아니다. 새 검사에서 관측할 수 없어진 항목을 성공으로 바꾸지 않는다. 사용자 취소와 시스템 정책 거부도 정상적인 결과 상태다.

공장 초기화, 부트로더 잠금 변경, 루팅, 펌웨어 플래시, 전체 인증서 삭제, 모든 접근성/업무 관리 기능 일괄 해제는 원클릭 조치에 포함하지 않는다. 현재 진단 자료를 보존하고 필요한 대상만 시스템 확인을 거쳐 조치하는 흐름이 이 프로젝트의 범위다.

## 출처

[knox-attestation]: https://docs.samsungknox.com/dev/knox-attestation/enhanced-attestation-v3/
[zimperium-paper]: https://zimperium.com/hubfs/MAPS/WP/GENERIC/How_Zimperium_Helps_You_Meet_OWASP_MASVS_Resilience_Requirements1.pdf?hsLang=en
[lookout]: https://learn.microsoft.com/en-us/intune/device-security/mobile-threat-defense/lookout
[iverify-il]: https://www.iverify.com/blog/android-intrusion-logging-forensics-analysis
[phonecheck]: https://www.phonecheck.com/diagnostics
[blancco-result]: https://blancco-support.atlassian.net/wiki/spaces/KB/pages/11633238/How+is+the+overall+result+of+diagnostics+determined
[blancco-profile]: https://blancco-support.atlassian.net/wiki/spaces/KB/pages/11633232/Can+I+select+which+diagnostics+tests+I+want+to+run
[blancco-interaction]: https://blancco-support.atlassian.net/wiki/spaces/KB/pages/11633217/Are+the+diagnostics+tests+automatic+or+does+the+user+have+to+do+something+with+the+device
[cellebrite]: https://cellebrite.com/en/blog/7-data-collection-mistakes-that-compromise-corporate-investigations-and-how-to-avoid-them/
[zimperium-knox]: https://www.samsungknox.com/en/partner-solutions/zimperium-zips-with-samsung-knox
[samsung-malware]: https://www.samsungsvc.co.kr/solution/618789
[samsung-diagnostics]: https://www.samsung.com/us/support/answer/ANS10003632/
[samsung-autoblocker]: https://www.samsungsvc.co.kr/solution/1711930
[samsung-update]: https://www.samsungsvc.co.kr/solution/2683703
[samsung-maintenance]: https://www.samsungsvc.co.kr/solution/1042940
[devicecare-play]: https://play.google.com/store/apps/details?id=com.samsung.android.lool
[members-play]: https://play.google.com/store/apps/details?id=com.samsung.android.voc
[autoblocker-store]: https://galaxystore.samsung.com/detail/com.samsung.android.rampart?cntyCd=KOR
[samsung-app-management]: https://developer.samsung.com/mobile/app-management.html
[android-settings]: https://developer.android.com/reference/android/provider/Settings
[android-intent]: https://developer.android.com/reference/android/content/Intent#ACTION_UNINSTALL_PACKAGE
[android-permissions]: https://developer.android.com/reference/android/Manifest.permission#REQUEST_DELETE_PACKAGES
[android-packageinstaller]: https://developer.android.com/reference/android/content/pm/PackageInstaller
[samsung-delete]: https://www.samsungsvc.co.kr/solution/39848
[android-secure]: https://developer.android.com/reference/android/provider/Settings.Secure
[android-global]: https://developer.android.com/reference/android/provider/Settings.Global
[android-dpm]: https://developer.android.com/reference/android/app/admin/DevicePolicyManager
[android-certificates]: https://support.google.com/pixelphone/answer/2844832
[knox-warranty]: https://docs.samsungknox.com/admin/knox-admin-portal/kbas/kba-360039680233/
[knox-faq]: https://docs.samsungknox.com/admin/knox-platform-for-enterprise/faq/

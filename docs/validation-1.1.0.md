# RefurbCheck 1.1.0 검증 기록

검증일: 2026-11-06. 개발 환경에서 수행한 검증이며 사용자의 실제 갤럭시 진단 결과가 아닙니다.

## 배포 APK

| 항목 | 값 |
|---|---|
| 패키지 | `io.github.refurbcheck` |
| 앱 이름 | 리퍼폰 점검 |
| 버전 | 1.1.0 / versionCode 2 |
| 최소 Android | 8.0 / API 26 |
| compile/target SDK | 35 |
| APK 크기 | 287,654 bytes |
| APK SHA-256 | `f3286044ca028e66eef0510074ecbfcbe87a6a63dc8c80010b6ac223e124a8e7` |
| 서명 인증서 SHA-256 | `31a3041c7933acb7cdafad342bb574f0726f6045ddf5ccf4d9fd3fc7f1f126ff` |

v1.0.0과 같은 개인 릴리스 키로 서명했습니다. APK v2/v3 서명 검증, 서명자 1명/RSA 3072, zipalign, package/version/minSdk/targetSdk/launcher 확인을 마쳤습니다. 공식 SDK의 Java 컴파일·D8 변환·aapt2 패키징이 성공했습니다. 정적 검증 출력은 `release/apk-build-verification.txt`, 입력 파일의 SHA-256은 `release/source-file-sha256.json`입니다. 이 해시 목록 자체가 외부 서명된 빌드 증명서는 아닙니다.

Manifest 권한은 `QUERY_ALL_PACKAGES`, `ACCESS_NETWORK_STATE`, `REQUEST_DELETE_PACKAGES`이며 INTERNET 권한은 없습니다. 포함 네이티브 라이브러리는 없고 공개 apksig Android 포트의 DEX 코드와 정적 기준자료를 포함합니다.

## 호스트 회귀 검사

| 영역 | 수행 결과 |
|---|---|
| 부팅·패치 판정 | 22 assertions, 실패 0 |
| DER·인증서·앱 바인딩·교차 비교·폐기 자료 | 323 assertions, 실패 0. DER 잘림 전 지점과 추가 malformed 입력 2,000개 포함 |
| 실제 APK 서명·해시·IOC·읽기 제한 | 30 시나리오, 51 assertions, 실패 0 |
| JSON 입력·보고서·기준 비교 | 91 시나리오, 478 assertions, 실패 0 |
| 삭제 자격·조치 후 판정 | 57 시나리오, 107 assertions, 실패 0 |
| 합계 | **981 assertions, 실패 0** |

정상적으로 서명된 실제 APK를 공개 apksig 포트로 검증하고, 같은 파일의 classes.dex 저장 데이터 1바이트를 변경한 경우 검증 실패를 확인했습니다. 이는 검증기 동작 시험이며 악성코드 탐지율 측정이 아닙니다. v1.1.0 배포 APK도 호스트 테스트 입력으로 사용했습니다.

조치 테스트는 시스템 앱·자기 앱·불안정 파일·누락/변형된 근거를 제거 대상으로 허용하지 않는지 확인합니다. 부분 검사라도 안정적인 정확 일치 근거는 보존하고, ADB·개발자 옵션의 제한된 0값을 해결 완료로 판정하지 않습니다. 보고서 가져오기는 비표준/잘린/깊게 중첩된/중복 키 JSON, malformed UTF-8, 숫자·Boolean 강제 변환과 모순된 APK 자료를 다룹니다.

## Android 실행 검증

API 26 x86 AOSP 가상기기에서 apksig 엔진 테스트를 실제 ART app_process로 실행했습니다. **30 시나리오·51 assertions, 실패 0**이며 위 호스트 테스트와 중복되는 검증을 별도 실행한 것입니다. 추가 고유 assertion 수로 합산하지 않았습니다. 기록: `docs/apksig-art-api26-v1.1.json` 및 `.txt`.

v1.1.0 서명 APK를 API26 가상기기에 설치하고 자동 검사를 실행해 실제 SAF로 JSON을 저장했습니다. 저장한 v2 보고서에서 다음을 확인했습니다.

- 보이는 설치 패키지 84개, 발견/해시 수집한 APK 84개.
- 서명 확인 84개, 실패 0, 서명 메타데이터 불일치 0, 확인 불가 0.
- 이 이미지에 설치된 대상은 base APK이며 실제 설치 split APK는 없었습니다. split 처리는 호스트 자료 비교/메타데이터 로직 테스트와 구분합니다.
- 앱 자신의 버전 1.1.0/code 2, 실제 APK SHA-256이 배포 파일과 일치.
- 앱 자신의 파일 안정성, v2/v3 서명, OS 서명자 메타데이터 일치가 보고서에 기록됨.
- apksig 경고 문자열도 보존됨. `V2_SIG_UNKNOWN_APK_SIG_SCHEME_ID` 같은 경고를 조용히 삭제하지 않음.
- 공장 원본·악성코드 부재·물리 하드웨어 검증 플래그는 모두 false.

API26의 실제 UI 검사 30개가 통과했습니다. 문서 선택기로 실제 저장한 JSON을 재가져와 비교 화면에 도달했고, AOSP의 manufacturer가 unknown이므로 기기 식별 정보 부족 안내로 비교를 중단한 것도 확인했습니다. 이를 실제 Galaxy의 전체 기준 비교 성공으로 확대하지 않습니다. 설정 복귀 후 새 reportId와 SCREEN_OPENED → SCREEN_RETURNED → VERIFICATION_UNAVAILABLE 기록을 확인했습니다. 검사 중단 시 CANCELLED 및 모든 APK 범위 complete=false가 남았고, 84개 중 54개 패키지의 미완료 범위가 보존됐습니다. 저장 화면 취소 후 기존 결과도 유지됐습니다. 보존한 로그에서 앱 FATAL EXCEPTION/ANR는 발견하지 못했습니다.

상세 결과: [API26 검증 설명](validation-api26-v1.1.md), [30개 UI 확인](ui-smoke-v1.1.json), [통합 관측값](emulator-api26-observations-v1.1.json). 테스트 중 발견한 자동화 큐의 중복 입력은 완료 ID/실행 claim 기록으로 수정하고 가져오기·설정 복귀·중단을 다시 확인했습니다. 앱 소스는 이 과정에서 변경하지 않았습니다. 초기 System UI ANR은 새 앱 설치 이전의 별도 가상환경 사건으로 기록했습니다.

## Android 15 / API35의 제한된 실행 확인

같은 SHA-256의 APK를 공식 AOSP Android 15/API35 x86_64 소프트웨어 에뮬레이터에 설치했습니다. 약 586초에 운영체제 부팅이 완료됐고 SDK 값 35를 확인했으며, 실제 앱에서 자동 점검 화면이 표시되는 것을 관측했습니다. 이 결과를 전체 호환성 통과로 확대하지 않습니다.

초기 am start 대기에는 시간 초과 표시가 있었지만 앱 화면은 나타났습니다. 후속 UI 검사 중 시스템 런처 Quickstep의 응답 없음 대화상자가 나타나 검사가 막혔습니다. /sdcard의 UI 덤프 읽기 권한 문제는 shell 소유 임시 경로에서 읽는 방법으로 구분했으며, 앱 권한이나 앱 소스를 바꾸지 않았습니다. VM 재시작이나 반복 복구로 검증 범위를 늘리지 않았습니다.

API35에서 실제 보고서의 자기 APK 해시·UNKNOWN_PLATFORM 값·조치 후 Settings 복귀는 확인하지 못했습니다. 해당 코드 정책은 호스트 회귀 검사와 구현 내용으로 확인한 범위이며 API35의 종단 실행 확인과 구분합니다. 물리 Galaxy/One UI 검증도 별개입니다. 상세한 관측·미검증 항목과 종료 기록은 [API35 실행 기록](api35-validation.md) 및 [구조화 결과](api35-validation.json)에 있습니다.

## 검증 범위와 한계

- 실제 Galaxy·One UI·Knox·TEE/StrongBox·부품·제조사 앱 결과는 검증하지 않았습니다. AOSP 에뮬레이터는 삼성 펌웨어를 대체하지 않습니다.
- 문서 선택기 중 앱 프로세스 종료 후 저장 복원, 실제 설치 split APK의 전체 통합 동작, IOC 탐지부터 앱 내부 삭제 요청까지의 종단 흐름은 이번 실행 검증에서 미실시입니다.
- 실제 악성코드 바이너리를 다운로드하거나 감염 기기를 실험하지 않았습니다. 공개 자료는 파일 해시뿐입니다. 오탐률·미탐률 수치를 산출하지 않았습니다.
- 빈 테스트 앱을 사용한 Android 제거 확인/취소 시험은 시스템 UI 시험이며, 실제 악성 IOC 일치부터 제거까지의 종단 시험과 다릅니다.
- 최신 플랫폼에서 apksig-android 4.4.0의 API33 모델 결과를 최신 플랫폼 검증으로 올리지 않습니다. API34 이상 최종 상태는 UNKNOWN_PLATFORM입니다.
- 내장 폐기 목록은 2026-11-06 수집한 1,771개 항목의 스냅샷입니다. source/cache lifetime/SHA-256을 보존했지만 실시간 미폐기를 보증하지 않습니다.
- 외부 증명 서버·Play Integrity·Samsung Enhanced Attestation 서비스·제조사 전체 파티션 대조·물리 부품 인증은 구현하지 않았습니다.
- Gradle assemble/lint와 GitHub Actions의 실행 완료는 이 환경에서 검증하지 않았습니다. Java의 Gradle 배포 다운로드 연결이 막혀 공식 SDK 직접 빌드 경로를 사용했습니다. CI 설정을 제공한 것과 CI 통과는 다릅니다.
- 과거 v1.0.0 기록은 `docs/validation-1.0.0.md`로 보존했습니다. 현재 버전의 범위/수치는 이 문서를 우선합니다.

개인 서명키와 암호는 배포 소스에 포함하지 않습니다. 가상기기 화면이나 테스트 수치는 사용자의 휴대전화 검사 결과가 아닙니다.

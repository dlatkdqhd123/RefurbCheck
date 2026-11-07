# 최신 정식 버전: RefurbCheck 1.4.0

갤럭시 리퍼폰을 초기화한 뒤 실행하면 자료 확인 → 검사 → 가능한 조치 승인 → 재확인 → 결과 요약을 한 흐름으로 진행합니다. Android 삭제 승인은 사용자가 직접 해야 합니다.

- **[설치 APK 다운로드](https://github.com/dlatkdqhd123/RefurbCheck/releases/download/v1.4.0/RefurbCheck-1.4.0.apk)**
- [공개 릴리스·체크섬·검증 자료](https://github.com/dlatkdqhd123/RefurbCheck/releases/tag/v1.4.0)
- [전체 소스 ZIP](https://github.com/dlatkdqhd123/RefurbCheck/releases/download/v1.4.0/RefurbCheck-1.4.0-source.zip)
- [사용 안내](https://github.com/dlatkdqhd123/RefurbCheck/blob/v1.4.0/README.md)
- [API26/36 실행·1.3→1.4 업데이트 검증](https://github.com/dlatkdqhd123/RefurbCheck/actions/runs/42341669753)

v1.3.0과 동일한 배포 서명으로 업데이트 설치할 수 있습니다. APK SHA-256: `56d9586b825520a9b1fe7d443d1398f4879a3e1eed6fa90b995293e9ad54ca59`.

실제 Galaxy/One UI 전체 시험과 악성코드 탐지율 측정은 수행하지 않았습니다. 순정 OS·모든 악성코드 부재·물리 하드웨어 무변조를 보증하지 않습니다. 정식 앱 소스는 `v1.4.0` 태그와 `release/1.4.0` 브랜치에 있으며, `main`의 이전 prototype 코드는 보존합니다.

---

## 이전 1.3.0 및 prototype 배포 기록

아래 내용은 당시 배포 기록으로 보존합니다. 현재 설치·다운로드는 위의 **1.4.0**을 사용하세요.

# RefurbCheck · 갤럭시 리퍼폰 점검

## 설치용 1.3.0 다운로드

**갤럭시에서 사용할 설치 파일은 [RefurbCheck-1.3.0.apk](https://github.com/dlatkdqhd123/RefurbCheck/releases/download/v1.3.0/RefurbCheck-1.3.0.apk)입니다.**

- [릴리스 설명 · 설치 파일 · 체크섬](https://github.com/dlatkdqhd123/RefurbCheck/releases/tag/v1.3.0)
- [전체 소스 ZIP](https://github.com/dlatkdqhd123/RefurbCheck/releases/download/v1.3.0/RefurbCheck-1.3.0-source.zip)
- [1.3.0 사용 안내](https://github.com/dlatkdqhd123/RefurbCheck/blob/v1.3.0/README.md)
- [구현한 개선 사항과 참고 자료](https://github.com/dlatkdqhd123/RefurbCheck/blob/v1.3.0/docs/research-improvements-1.3.0.md)
- [검증 범위와 한계](https://github.com/dlatkdqhd123/RefurbCheck/blob/v1.3.0/docs/validation-1.3.0.md)

**v1.2.0 사용자는 새로 설치해야 합니다.** 이전 개인 서명키를 복구하지 못해 v1.3.0에는 새 서명키를 사용했습니다. 필요한 JSON 보고서를 저장하고 사용자가 이전 앱을 삭제한 뒤 설치하세요. 공장 초기화 후 처음 설치하는 기기는 바로 설치할 수 있습니다. 앱 ID는 기존 정식 앱과 같은 `io.github.refurbcheck`입니다.

### 이번 개선

Wi-Fi에 연결하고 앱을 처음 실행하면 서명된 검사 자료를 확인한 뒤 검사합니다. 실행 중 재검사의 자동 자료 확인은 6시간 간격으로 제한하며, 결과 탭에서 수동 확인 또는 서명된 ZIP 가져오기도 가능합니다. 자료의 서명·해시·크기·순번·유효기간을 확인하고 적용하며, 앱 목록·APK·보고서를 서버에 전송하지 않습니다. 새 참조는 게시자가 검토·서명하여 배포해야 추가됩니다.

설치 요청 앱과 설치 기록 앱, 업데이트 소유 앱, 현재 서명과 서명 이력을 구분합니다. 초기화 후 예상하지 않은 앱·실제 활성 관리 권한·접근성과 민감 권한의 조합도 확인 대상으로 표시합니다. 이런 권한이나 출처만으로 악성으로 확정하거나 자동 삭제하지 않습니다.

알려진 악성·감시 참조와 정확히 일치한 일반 앱은 현재 유효 자료와 앱 파일·버전·관리자 상태를 삭제 직전에 재검증하고 Android 삭제 승인창으로 연결합니다. 사용자가 승인하면 제거 여부를 확인하며 다음 대상으로 진행하고 재검사합니다. 시스템 앱·조직 등록 강제 해제·펌웨어 자동 복구는 대상이 아닙니다.

APK 서명 검증기는 고정된 AOSP Android 16 QPR2 소스로 갱신했습니다. 기기 속성 키 증명과 제한적인 구형 공장 인증서 호환 검증도 추가했습니다. 확인하지 못한 항목은 확인 불가로 표시합니다.

첫 서명 자료는 기존 검토된 참조 **15,645개**를 새 형식으로 배포한 것으로, 새 악성코드 15,645개를 추가했다는 뜻이 아닙니다. 상용 백신 전체 엔진, 미지 악성코드 탐지 보장, 전체 펌웨어·물리 부품의 무변조 인증을 제공하지 않습니다.

### 버전과 검증

[배포 검증 성공 기록](https://github.com/dlatkdqhd123/RefurbCheck/actions/runs/42317274754): 호스트 3,243개 assertion, Android 8/API 26에서 73개, Android 16/API 36에서 69개가 통과했습니다. 원본 APK의 내부 파일 26개 검사와 실제 배포 APK 설치·시작도 확인했습니다.

Android 8.0/API 26 이상, 루트·PC·ADB·계정·API 키 없이 설치하여 사용합니다. 호스트 회귀 테스트 **3,243개 assertion**과 Android API 26/36 실행 검사가 통과한 뒤 게시하는 릴리스입니다. 실행 검사는 배포 코드·리소스·자산을 유지한 임시 서명 사본을 사용하고, 최종 배포 서명 APK의 설치·시작도 확인합니다. 실제 Galaxy/One UI 기기와 악성코드 탐지율·오탐률은 아직 검증하지 않았습니다.

정식 1.3.0 소스는 [release/1.3.0 브랜치](https://github.com/dlatkdqhd123/RefurbCheck/tree/release/1.3.0)와 [v1.3.0 태그](https://github.com/dlatkdqhd123/RefurbCheck/tree/v1.3.0)에 있습니다. 아래 `main`의 0.2 시험판 소스·CI는 별도 기록으로 보존합니다.

APK SHA-256:

```text
2d1b2c0d1222cf5089c0a30a10a81f884f8286f7b86cf214f82bb7f089f7efc8
```

---

## 이전 1.2.0 배포 기록

아래 1.2.0 링크와 설명은 이전 배포 기록으로 보존합니다. 현재 설치 파일은 위의 1.3.0을 사용하세요.

- [RefurbCheck-1.2.0.apk](https://github.com/dlatkdqhd123/RefurbCheck/releases/download/v1.2.0/RefurbCheck-1.2.0.apk)
- [전체 소스 ZIP](https://github.com/dlatkdqhd123/RefurbCheck/releases/download/v1.2.0/RefurbCheck-1.2.0-source.zip)
- [릴리스 설명 · 파일 목록 · 체크섬](https://github.com/dlatkdqhd123/RefurbCheck/releases/tag/v1.2.0)
- [1.2.0 전체 설명](https://github.com/dlatkdqhd123/RefurbCheck/blob/v1.2.0/README.md)
- [실제 검증 기록과 한계](https://github.com/dlatkdqhd123/RefurbCheck/blob/v1.2.0/docs/validation.md)

공장 초기화 후 앱·설정 백업을 복원하기 전에 설치하고 **리퍼폰 점검**을 실행하면 자동 검사합니다. 초기화 직후 모드가 기본으로 켜져 있습니다. 알려진 악성·감시 파일과 정확히 일치한 일반 앱은 삭제 직전 재검증 후 Android 삭제 확인창으로 이어지며, 사용자가 승인하면 제거 여부를 확인하고 다음 대상으로 진행한 뒤 전체 재검사합니다. Android의 최종 삭제 승인은 필요합니다.

1.2.0은 Android 8.0/API 26 이상을 대상으로 하며 APK 자체 검사는 오프라인입니다. 루트·PC·ADB·계정·API 키가 필요하지 않습니다. ClamAV·ESET·Échap·MVT의 공개 참조 해시 15,645개를 사용하며, 전체 백신 엔진·미지 악성코드 탐지·공장 원본이나 하드웨어 무변조 인증을 제공하지는 않습니다. 실제 Galaxy/One UI 검증과 실제 악성코드 탐지율 시험은 아직 수행하지 않았습니다. 읽지 못했거나 지원하지 않는 항목은 확인 불가로 남깁니다.

**버전 구분:** 아래에 보존한 `main`의 0.2 시험판은 `io.github.dlatkdqhd123.refurbcheck.prototype` 패키지의 별도 앱입니다. 설치용 1.2.0은 `io.github.refurbcheck`이며 소스는 [`release/1.2.0` 브랜치](https://github.com/dlatkdqhd123/RefurbCheck/tree/release/1.2.0)와 [`v1.2.0` 태그](https://github.com/dlatkdqhd123/RefurbCheck/tree/v1.2.0)에 있습니다. 0.2 시험판이 이미 설치돼 있다면 별도로 설치되므로 실행 화면의 1.2.0 표시를 확인하세요.

APK SHA-256:
```text
addf557694e94e499f4409b764ccc0780629f137e1e6494ce5eb357e6d51be8c
```

---

## 보존한 0.2 시험판 안내

다음 내용과 `main`의 소스/CI는 기존 0.2 시험판의 기록입니다.

# RefurbCheck 0.2.0

갤럭시 리퍼폰을 위한 무료·오프라인 보안 상태 점검 도구의 새 독립 구현입니다. 기존 다른 대화의 APK·소스는 사용하지 않았습니다. 기존 1.1.0과 패키지·서명·기능이 다르며 업데이트가 아닙니다. Android 8.0(API 26) 이상을 대상으로 합니다.

## 점검 범위

- 현재 사용자의 PIN·패턴·비밀번호 잠금 설정 여부
- OS가 보고한 보안 패치 날짜, 암호화 상태, 빌드 type/tags
- API가 반환하는 활성 접근성 서비스·기기 관리자 목록
- 현재 사용자에게 접근 가능한 앱의 설치 관리자, 디버그 빌드, 오래된 대상 SDK, 일부 허용된 민감 권한, 설치/오버레이 권한 선언
- 개발자·USB/무선 디버깅, 특별 접근 권한, VPN·사용자 인증서·Play 프로텍트의 수동 점검 안내

패치가 180일을 넘으면 업데이트 확인을 권합니다. 이는 이 앱의 참고 기준이며 제조사 지원 종료 판정이 아닙니다. 설정 화면을 열 수 있으며 기기에서 지원하지 않으면 직접 확인 안내를 표시합니다. 앱 삭제는 앱 정보에서 사용자가 직접 선택합니다. 자동 삭제·권한 취소·OS 설정 변경은 없습니다.

## 한계와 개인정보

**백신 엔진·악성코드 DB·실시간 보호가 없습니다.** 위험 신호는 악성코드 판정이 아닙니다. 신호가 없어도 감염 없음이나 기기 안전을 보증하지 않습니다. Verified Boot, 부트로더 잠금, Knox 보증 비트, 루팅·루트킷 부재, 펌웨어·부품 변조는 검증하지 못합니다. Play Integrity·하드웨어 키 증명은 구현하지 않았습니다. OS의 자기 보고값은 위조될 수 있습니다.

Android 패키지 가시성 제한을 준수합니다. 런처 인텐트 `<queries>`만 사용하며 `QUERY_ALL_PACKAGES`는 요청하지 않습니다. 다른 사용자·업무 프로필·모든 숨은 앱·앱 개인 데이터·메모리·펌웨어는 검사하지 않습니다. 허용된 민감 권한 목록도 전체 권한을 다루지 않습니다. 특별 권한 선언과 실제 허용 상태를 구분합니다.

요청 권한·INTERNET·추적 SDK·계정·루트·접근성 서비스·기기 관리자 권한을 사용하지 않습니다. 결과는 메모리에만 두며 자동 전송·파일 저장·백업하지 않습니다. 보고서 공유는 포함 데이터(기기/OS·앱/서비스 목록·권한·출처)를 안내하고 사용자가 동의한 후 Android 공유 선택기로 전달합니다. 외부 앱에 전달한 내용은 그 앱의 처리 대상입니다. 기기 시계가 잘못되면 패치 경과일도 부정확합니다.

## 로컬 빌드와 테스트

Android SDK 36, JDK 21, Gradle Wrapper 9.3.1, AGP 9.0.0을 사용합니다. Android Studio에서 이 폴더를 열고 SDK 위치를 설정하거나 로컬 `local.properties`에 `sdk.dir`을 설정하세요. 인증서 오류는 신뢰 체인·네트워크 구성을 확인해야 하며 TLS 검증을 끄면 안 됩니다.

```powershell
.\gradlew.bat assembleDebug lintDebug
New-Item -ItemType Directory -Force build/rule-tests
javac -encoding UTF-8 --release 17 -d build/rule-tests app/src/main/java/io/github/dlatkdqhd123/refurbcheck/prototype/AuditRules.java tests/AuditRulesTest.java
java -cp build/rule-tests io.github.dlatkdqhd123.refurbcheck.prototype.AuditRulesTest
```

APK 위치: `app/build/outputs/apk/debug/app-debug.apk`. 개발용 debug 서명이며 배포용 서명 릴리스가 아닙니다. 소스와 서명키는 별개입니다. 서명키·토큰·로컬 경로·빌드 산출물은 Git에서 제외합니다. 배포용 키는 생성하지 않았습니다.

## GitHub Actions

로컬 작성 → GitHub 소스 커밋/push → CI 빌드·lint·규칙 테스트 → debug APK artifact 순서입니다. CI가 미게시 PC 파일을 GitHub에 올리는 구조는 아닙니다. `main` push, PR, 수동 실행을 지원하고 `contents: read`만 요청합니다. 비밀값·자동 push·release 게시를 사용하지 않습니다. 공개 저장소의 Actions 결과는 공개될 수 있습니다. CI가 성공하기 전 APK 빌드 완료라고 간주하지 마세요.

## 검증 기록과 API 근거

현재 빌드·게시·인증 상태는 [WORK_LOG.md](WORK_LOG.md)에 기록합니다. 실제 갤럭시 기기에서 설정 화면, 앱 가시성, 접근 제한 시 동작을 검증해야 합니다.

- [패키지 가시성](https://developer.android.com/training/package-visibility)
- [일반 앱의 ADB/개발자 옵션 읽기 제한](https://developer.android.com/reference/android/provider/Settings.Global)
- [보안 잠금 조회](https://developer.android.com/reference/android/app/KeyguardManager)
- [암호화 상태와 관리자 API](https://developer.android.com/reference/android/app/admin/DevicePolicyManager)
- [설치 출처·권한 API](https://developer.android.com/reference/android/content/pm/PackageManager)

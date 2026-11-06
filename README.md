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

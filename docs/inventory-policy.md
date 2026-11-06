# 설치 출처·서명 이력·초기화 후 정책

이 기능은 현재 사용자/프로필에서 Android가 반환하는 정보를 정리한다. 독립적인 제조사 인증, 악성코드 판정, 다른 프로필의 전체 조사, 불법성 판정에 해당하지 않는다. 검사 결과나 가져온 보고서가 기기 밖의 신뢰 기준이 되는 것도 아니다.

## 설치 출처

`PackageProvenance`는 API 버전에 따라 다음 정보를 수집한다.

| 정보 | 최소 API | 해석 |
| --- | --- | --- |
| 설치 주체 기록 | 기존 API 또는 30 | installer of record; 이후 변경될 수 있다. |
| 설치/업데이트를 시작한 패키지 | 30 | 설치 주체 기록과 별개로 수집하며, 삭제된 설치 앱 등에서는 값이 없을 수 있다. |
| 시작 패키지의 서명 정보 | 30 | API가 제공하는 현재 서명과 교체 이력을 구분해서 기록한다. |
| 설치 경로 분류 | 33 | 스토어/로컬/다운로드 등 설치자가 기록한 분류이며 정품 인증이 아니다. |
| 업데이트 소유자 | 34 | 업데이트 소유권 적용 주체; null은 악성 또는 무관리의 증거가 아니다. |

각 필드는 `KNOWN`, `NOT_AVAILABLE`, `UNSUPPORTED_API`, `ERROR` 등 수집 상태와 값을 구분한다. 설치 출처 누락을 악성으로 처리하지 않는다. `com.android.vending` 등 패키지 이름만으로 승인 목록을 만들지 않는다. 일반 앱에서 제한되며 설치자가 입력하는 originating package는 요청하지 않는다.

## 서명 이력 비교

현재 서명 인증서 SHA-256 집합을 기존 `signingSha256` 필드로 보존한다. 단일 서명 앱은 `signingHistorySha256`에 과거부터 현재까지의 순서를 별도로 기록한다. 다중 서명 앱은 모든 현재 서명의 집합을 비교하며, 인증서 하나의 일치나 부분집합을 같은 앱 또는 정상 키 교체로 취급하지 않는다.

일반 보고서 비교는 다음을 구분한다.

- 현재 서명 집합이 같음.
- 새 보고서의 교체 이력에 이전 키가 포함되고 순서가 일관됨.
- 이전 보고서의 과거 키 방향으로 변경됨.
- 양쪽 교체 순서가 모순됨.
- 다른 서명이거나 충분한 이력을 수집하지 못함.

이력 연결도 **보고된 이력의 연결**이다. 가져온 JSON은 위조할 수 있다. 이 기능은 APK 서명 검증을 대체하거나 가져온 보고서를 신뢰 기준으로 승격하지 않는다. 이력·현재 서명 수·digest 형식이 잘못되거나 중복되면 정상 교체로 인정하지 않는다.

## 실제 관리 등록 구분

`ManagementInspection`은 현재 프로필의 활성 관리자마다 기기 소유자, 프로필 소유자, 일반 활성 관리자 역할을 조회한다. 지원하는 API에서는 조직 소유 업무 프로필 상태도 별도로 조회한다. 조회 실패나 일부 역할 미확인은 명시적으로 기록한다.

삼성 Knox 관련 패키지가 보이는 것과 관리 등록이 활성화된 것은 다르다. 패키지 이름만으로 회사 관리나 악성 앱으로 판정하지 않는다. 다른 프로필이나 서버에 남아 있는 Knox Mobile Enrollment 등록까지 완전히 조회한 결과도 아니다. 소유자 해제·삭제 제한 우회·관리자 권한 획득을 수행하지 않는다.

## 초기화 후 정책

사용자가 관리 앱과 개인 앱을 설치하지 않은 초기화 직후 검사라는 조건을 별도 정책으로 표현한다.

- 검사 앱 자체를 제외한 비시스템 앱은 확인 대상으로 표시한다. 초기 설정에서 정상 자동 설치·복원된 앱도 포함될 수 있다.
- 시스템으로 보고된 앱은 제조사 기준이 없으므로 순정 여부가 미검증이다. `FLAG_SYSTEM`은 승인 또는 안전 인증이 아니다.
- 활성 관리자, 조직 소유 관리 상태, 접근성·알림 접근은 기대 조건과의 차이로 표시한다.
- 첫 검사 결과나 가져온 일반 보고서를 자동으로 제조사 순정 기준으로 등록하지 않는다.

정책 결과에는 `automaticRemovalAuthorized=false`, `malwareClassification=false`가 기록된다. 기존 참조 해시 확인과 재검증을 거친 삭제 흐름의 적격성 필드를 추가하거나 변경하지 않는다.

## 해시와 독립적인 활성 권한 조합

`ManifestRiskInspection`은 `GET_PERMISSIONS | GET_SERVICES`로 읽은 OS의 매니페스트 메타데이터를 기록한다. 요청한 보안 관련 권한, OS가 부여했다고 보고하는 권한, 접근성·알림·VPN 서비스의 요구 바인딩 권한 및 exported/enabled 상태를 구분한다. `BIND_ACCESSIBILITY_SERVICE` 같은 서비스 보호 권한은 서비스에 접속하는 호출자에 대한 요구이며, 앱에 그 권한이 부여됐다는 의미로 처리하지 않는다.

`ManifestRiskRules`의 초기 규칙은 비시스템 앱에 대해 다음처럼 이미 활성화된 상태와 권한이 함께 있을 때만 검토를 요청한다.

| 규칙 | 함께 필요한 관측 |
| --- | --- |
| CAP-A11Y-INSTALL-01 | 활성 접근성 서비스 + 설치 요청 권한 선언 또는 실제 설치 권한 부여 |
| CAP-A11Y-MESSAGES-01 | 활성 접근성 서비스 + 문자/수신문자/통화기록 중 하나 이상 실제 권한 부여 |
| CAP-ADMIN-MESSAGES-01 | 활성 관리자 + 문자/수신문자/통화기록 중 하나 이상 실제 권한 부여 |

광범위한 앱 목록 접근, 부팅 수신, 인터넷 권한 또는 민감 권한의 **선언만으로** 악성이나 규칙 경고를 만들지 않는다. 정상 자동화·보조공학·관리 앱도 조합에 해당할 수 있다. 시스템 앱은 이 일반적인 조합 점수에서 제외했다고 명시하며, 해시·APK 서명 검사는 계속 적용된다.

이 규칙은 실제 악성 동작, DEX 코드, 암호화된 추가 payload, 다른 앱의 내부 데이터 또는 네트워크 통신을 분석하지 않는다. 일치 없음은 신규 악성코드 부재가 아니다. 규칙 결과는 자동 삭제나 관리 권한 우회에 사용하지 않는다.

## 검증

`bash tests/run_inventory_policy_tests.sh`는 정상·모순 서명 이력, 다중 서명 집합, 서명/패키지 메타데이터 오류, 정상 사전 설치 앱, 미지 설치 출처, 누락·잘못된 권한 증거, 활성 권한 조합과 삭제 권한 분리를 합성 자료로 검사한다. 이 테스트는 실제 갤럭시에서의 오탐률이나 악성코드 탐지율 측정이 아니다.

## 근거 자료

- Android [InstallSourceInfo](https://developer.android.com/reference/android/content/pm/InstallSourceInfo)
- Android [SigningInfo](https://developer.android.com/reference/android/content/pm/SigningInfo)
- Android [DevicePolicyManager](https://developer.android.com/reference/android/app/admin/DevicePolicyManager)
- Android [ApplicationInfo.FLAG_SYSTEM](https://developer.android.com/reference/android/content/pm/ApplicationInfo#FLAG_SYSTEM)
- Android [ServiceInfo.permission](https://developer.android.com/reference/android/content/pm/ServiceInfo#permission)
- Android [REQUEST_INSTALL_PACKAGES](https://developer.android.com/reference/android/Manifest.permission#REQUEST_INSTALL_PACKAGES)
- Samsung [Knox Mobile Enrollment FAQ](https://docs.samsungknox.com/admin/knox-mobile-enrollment/faq/)

API 동작과 신뢰 범위는 위 공식 문서를 기준으로 하며, 조합 규칙은 RefurbCheck의 설명 가능한 검토 정책이다. 이 규칙 자체를 논문이 검증한 탐지 모델로 표현하지 않는다.

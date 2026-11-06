# 하드웨어 키 증명 구현 범위 — 1.3.0

이 기능은 **오프라인 기기 내부 증거 수집·일관성 검사**다. `PASS`로 순정·안전을 선언하지 않는다. 침해된 OS는 앱의 관측과 검증 실행을 속일 수 있으므로, 서명된 자료가 맞더라도 다른 신뢰 기기에서의 검증과 최신 인증서 상태 조회가 남는다. 물리 부품 전체의 정품 여부나 악성코드 부재는 이 증명서의 보증 대상이 아니다.

## 실제 검사 순서

1. 검사 앱 자신의 패키지명, 설치 버전 코드, 현재 서명 인증서 SHA-256 집합, UID 공유 여부, 마지막 업데이트 시각을 읽는다.
2. AndroidKeyStore에서 매번 임의 별칭과 새로운 32바이트 challenge로 임시 EC P-256 키를 만든다. Android 12/API 31 이상에서는 브랜드·기기명·제품명·제조사·모델의 비고유 속성 증명도 요청한다. IMEI·기기 일련번호·고유 ID 증명은 요청하지 않는다. 속성을 포함한 생성이 `ProviderException`으로 실패하면 그 사실을 `UNKNOWN`으로 남기고, 부분 생성 키를 삭제한 뒤 새 challenge로 기본 증명을 한 번 시도한다. 기본 요청의 성공을 속성 증명 성공으로 표시하지 않는다.
3. 반환된 인증서 체인을 고정된 Google 공개 루트와 대조하고 PKIX 경로·서명을 확인한다. 선택한 고정 루트는 현재 유효해야 한다. 기기가 예전 루트 사본을 보내더라도 주체와 공개키가 현재 고정 루트와 같으면 현재 루트로 연결한다. 체인이 루트를 생략한 경우도 지원한다. 경로 유효기간은 기본적으로 기기 시각으로 확인하며, 아래에 명시한 좁은 구형 공장 CA 만료 예외만 적용한다.
4. 루트에 가장 가까운 첫 Android attestation 확장을 선택한다. RKP provisioning 확장이 있다면 바로 다음 인증서의 attestation 확장인지도 확인한다. 체인 뒤에 추가한 임의 확장은 선택하지 않는다.
5. challenge, 생성한 공개키, 개인키의 challenge 서명으로 확인한 키 소유 증거를 대조한다. 원래 인증서 체인, challenge, 서명 증거와 알고리즘도 보고서에 넣는다.
6. `[709] AttestationApplicationId`의 패키지명·64비트 버전 코드·서명 인증서 SHA-256 **전체 집합**을 1번 기대값과 정확히 비교한다. 키 생성 뒤 같은 메타데이터를 다시 읽어 검사 중 변경도 확인한다.
7. 증명 수준과 키 저장 수준이 TEE 또는 StrongBox인지, 문서에 정의된 attestation/Keymaster·KeyMint 버전 조합인지 확인한다. 기본 TEE 요청이며 StrongBox를 강제하지 않는다.
8. `hardwareEnforced`의 RootOfTrust에서 잠금, Verified Boot 상태, 부팅 키와 해시를 읽는다. 소프트웨어 영역의 RootOfTrust로 대체하지 않는다. 구형 버전 1·2는 3필드, 현대 버전은 부팅 해시를 포함한 4필드를 요구한다. Verified 증거에 사용할 해시는 32·48·64바이트로 제한하며 0으로만 채운 키·현대 부팅 해시는 사용하지 않는다.
9. 아래 표의 기존 일곱 항목과 비고유 기기 속성 다섯 항목, 총 12개를 기존 OS 관측값과 비교한다. 값이 없거나 의미가 맞지 않는 형식이면 `NOT_COMPARABLE`을 기록한다. 일치하는 한 항목으로 다른 불일치를 덮지 않는다.
10. 동봉한 공식 인증서 상태 목록 사본에서 제공된 모든 체인 인증서와, 생략되었다면 선택한 고정 루트까지 일련번호를 조회한다. 목록 파일의 SHA-256은 메타데이터의 값과 대조한다.
11. 임시 앱 전용 키를 `finally`에서 삭제한다. 전체 키 증명 요청은 15초 후 확인 불가를 반환하고, 늦게 돌아온 작업은 화면 결과를 바꾸지 않는다. 동시에 새 Keystore 요청을 중복 실행하지 않는다. OS 호출 자체가 영구 정지하면 앱은 해당 호출을 강제로 종료할 수 없다.

## 앱 신원 대조의 엄격한 조건

`AttestationApplicationId`는 Android 플랫폼이 제공하는 **softwareEnforced 신원 기록**이다. 하드웨어가 앱 APK를 직접 읽어 신원을 보증한다고 설명하지 않는다. 앱의 PackageManager 기대값도 같은 기기에서 읽은 값이다.

파서는 DER의 길이, 태그, 명시적 래퍼, 두 SET의 정렬, 중복 태그·패키지명·서명 다이제스트, SHA-256 32바이트 길이, UTF-8 이름, 비음수 버전, 1 KiB 크기 제한을 검사한다. 소프트웨어와 하드웨어 목록 양쪽의 중복 `[709]`는 해석 실패다. 하드웨어 영역에만 있는 `[709]`는 올바른 신원 증거로 대체하지 않는다.

현재 앱 한 개와 버전·현재 서명 집합이 모두 맞아야 연결 조건을 충족한다. 공유 UID로 패키지가 여러 개이거나, 추가 서명자가 있거나, 기대값을 읽지 못하면 `UNKNOWN`이다. 정당한 서명 키 회전에서 과거 인증서가 사용되는 경우도 현재 서명 기대값과 달라 `UNKNOWN`이 될 수 있다. 구형 증명서의 `[709]` 누락과 미지원 제조사 역시 변조 확정으로 처리하지 않는다.

## 교차 확인

| 항목 | 하드웨어 증명 | OS 관측 | 비교 단위 |
| --- | --- | --- | --- |
| Android 버전 | `[705] osVersion` | `Build.VERSION.RELEASE` | 숫자형 주·부·패치 버전 |
| OS 보안 패치 | `[706] osPatchLevel` | `Build.VERSION.SECURITY_PATCH` | 연월; 일자 일치를 주장하지 않음 |
| 벤더 패치 | `[718] vendorPatchLevel` | `ro.vendor.build.security_patch` | 유효한 달력 날짜 |
| 부팅 이미지 패치 | `[719] bootPatchLevel` | `ro.bootimage.build.version.security_patch` | 유효한 달력 날짜 |
| Verified Boot | RootOfTrust 상태 | `ro.boot.verifiedbootstate` | Verified/green, SelfSigned/yellow, Unverified/orange, Failed/red |
| Flash 잠금 | RootOfTrust `deviceLocked` | `ro.boot.flash.locked` | 잠김/해제 |
| VBMeta 잠금 | RootOfTrust `deviceLocked` | `ro.boot.vbmeta.device_state` | 잠김/해제 |
| 브랜드 | `[710] attestationIdBrand` | `Build.BRAND` | 대소문자 포함 정확한 문자열 |
| 기기명 | `[711] attestationIdDevice` | `Build.DEVICE` | 대소문자 포함 정확한 문자열 |
| 제품명 | `[712] attestationIdProduct` | `Build.PRODUCT` | 대소문자 포함 정확한 문자열 |
| 제조사 | `[716] attestationIdManufacturer` | `Build.MANUFACTURER` | 대소문자 포함 정확한 문자열 |
| 모델 | `[717] attestationIdModel` | `Build.MODEL` | 대소문자 포함 정확한 문자열 |

인증서 경로·새 요청·앱 신원·하드웨어 수준이 연결된 상태의 불일치는 `WARN`이다. 연결 조건이 부족하면 원래 비교값은 남기되 `UNKNOWN`이다. 업데이트 직후 상태, 제조사 구현 차이, 관측 오류도 가능하므로 불일치를 악성코드 확정으로 바꾸지 않는다. 일치 결과는 `INFO`이며 순정 펌웨어 해시 대조를 대신하지 않는다.

기기 속성은 `hardwareEnforced`의 값만 비교한다. `softwareEnforced` 값은 보고서에 별도로 남기고 하드웨어 신원 증거로 사용하지 않는다. 두 영역에 같은 속성이 중복되면 해석을 중단한다. 각 값은 UTF-8, 최대 512바이트, 제어문자 없음 조건을 요구하며, 빈 값·`unknown`·`null`은 일치로 계산하지 않는다. API 미지원·제조사 미지원·필드 누락은 모델 불일치나 순정 통과로 바꾸지 않는다. 속성 일치는 기판·교체 부품의 정품 판정이 아니다.

## 구형 공장 CA 만료 호환 정책

Google 공식 안내와 `android/keyattestation` v0.4는 공장에 주입된 증명 CA의 만료와 RKP 인증서의 만료를 다르게 다룬다. RefurbCheck는 일반 PKIX의 서명·CA·경로 제약을 유지하기 위해 공식 검증기보다 좁은 호환 범위를 구현했다.

- 선택한 고정 루트의 실제 공개키 SHA-256이 Google 기존 RSA 키 `feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae`와 같아야 한다. 루트 이름의 `SERIALNUMBER` 문자열만으로 예외를 허용하지 않는다.
- 루트를 제외한 경로가 정확히 3개 인증서이고, 루트 바로 아래의 서명 검증된 중간 CA에 `serialNumber` 이름 속성이 있어야 한다. CN·O를 포함한 RKP 형태나 애매한 형태는 예외 대상에서 제외한다.
- 어느 인증서에도 RKP provisioning 확장이 없어야 하고, 첫 attestation 확장이 leaf에 있어야 한다. 따라서 RKP 만료와 알 수 없는 체인 형식은 완화하지 않는다.
- leaf와 고정 루트는 현재 유효해야 한다. 공장 CA의 만료만 예외로 두며, 아직 시작되지 않은 인증서 기간은 예외로 두지 않는다.
- 모든 경로 인증서의 유효기간이 겹치는 과거 시점을 계산해 **같은 전체 경로**에 PKIX를 적용한다. 공통 시점이 없으면 `UNKNOWN`이다. 이 경로에서는 SHA-256 이상 RSA/ECDSA 서명과 RSA 2048비트 이상 또는 EC 256비트 이상 키도 별도로 요구한다. 서명, CA 제약 또는 경로 검증 실패를 만료 예외로 덮지 않는다.
- 사용한 날짜 정책, 만료 CA 개수, PKIX 검증 시각, 현재 루트로 연결했는지를 보고서에 기록한다. 모든 원래 인증서와 선택한 루트의 폐기 목록 대조, 새로운 challenge·키 소유·앱 연결 검사는 유지한다. 알려진 폐기·중지 키는 부팅 정상 근거로 사용하지 않는다.

이것은 공식 Kotlin 검증기를 그대로 탑재하거나 동등성을 보장한 구현이 아니다. 공식 검증기는 최종 leaf의 기기 지정 유효기간을 따로 취급하고 일부 비표준 레거시 경로도 수용하지만, RefurbCheck는 그 경우 `UNKNOWN`으로 남길 수 있다. 만료 예외를 적용한 `localChainValid`는 해당 정책으로 로컬 경로가 연결됐다는 뜻이며, 최신 미폐기·외부 검증·순정 펌웨어 보증이 아니다.

## 동봉 인증서 상태 목록

목록은 `assets/attestation_revocations.json`, 수집 메타데이터는 `assets/attestation_revocations_meta.json`이다. 메타데이터에는 공식 URL, 수집 epoch 밀리초, HTTP 캐시 기간, 본문 SHA-256이 들어 있다. 이 릴리스의 사본은 2026-11-06 수집, 1,771개 항목, SHA-256 `4110236d8d47b35e7a7f124d5325b4c997a07a4a3b5ecb134eb903b2240fd695`다.

- 유효한 고정 루트 체인에서 `REVOKED` 또는 `SUSPENDED` 일련번호가 발견되면 `ALERT`이며 해당 체인의 부팅 정보를 정상 근거로 사용하지 않는다.
- 체인이 검증되지 않았다면 일련번호 일치 자체도 출처를 신뢰할 수 없으므로 `UNKNOWN`으로 남긴다.
- 일치가 없으면 **그 사본에서의 부재**만 `INFO`로 기록한다. 최신 미폐기 판정은 하지 않는다.
- 기기 시각으로 캐시 기간이 지났거나 시각·메타데이터를 판단할 수 없으면 최신성 항목을 `UNKNOWN`으로 추가한다. 오래된 사본의 알려진 일치는 유지한다.
- 사본의 크기·구조·상태 값·일련번호 형식·본문 SHA가 틀리면 `UNKNOWN`이다. JSON 중첩은 파싱 전 제한한다. 앱은 이 목록을 온라인으로 갱신하지 않는다.

`revocationChecked`, `offDeviceVerified`, `fullAttestationTrusted`는 항상 `false`다. 별도 `revocationSnapshot.checked`는 동봉 사본 대조를 실행했다는 뜻이다. `CURRENT_BY_LOCAL_CLOCK`는 신뢰되지 않은 기기 시각을 기준으로 캐시 나이를 계산한 결과이며, 외부 검증이나 실시간 조회를 의미하지 않는다.

## 결과 등급과 다음 조치

잠김·Verified·형식이 맞는 해시와 모든 로컬 연결 조건을 확인해도 **INFO**까지만 표시한다. 사용자 지정 신뢰 키는 `WARN`, 로컬 연결 조건이 충족된 잠금 해제·Unverified·Failed 기록은 `ALERT`다. 알 수 없는 버전, 형식, 누락, 시간 초과, 지원되지 않는 인증서는 `UNKNOWN`이다.

Galaxy에서 이러한 부팅·증명 이상을 앱이 직접 복구할 수는 없다. 업데이트 후 재부팅해 재검사하고, 지속되면 Samsung 공식 서비스와 다른 신뢰 기기의 Android Key Attestation 검증기를 이용한다. 2026-11-07 확인한 Auditor의 검증 대상 목록에는 Galaxy가 없으므로 이 앱의 Galaxy 대체 검사로 안내하지 않는다. 다른 휴대폰을 검증하는 Auditor 역할과 해당 휴대폰 자신이 검증되는 Auditee 지원은 다르다. 이 검사 결과만으로 부트로더를 재잠그거나 비공식 펌웨어를 설치하는 절차를 자동 실행하지 않는다. Knox Warranty Bit의 OS 속성 값은 이 증명의 하드웨어 보증으로 승격하지 않는다.

구형 공장 발급 증명 키의 인증서 만료만으로 OS 변조를 확정하지 않는다. 위의 제한된 만료 호환 조건을 입증하지 못하면 `UNKNOWN`으로 처리한다. 호환 성공에도 최신 폐기 확인과 외부 검증은 남는다.

## 고정 공개 루트

| 루트 | 인증서 SHA-256 |
| --- | --- |
| Google 기존 RSA 루트 | `cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc` |
| 2026 회전 ECDSA 루트 | `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0` |

루트와 목록 사본은 앱 릴리스에서 갱신한다. 제조사 순정 펌웨어의 검증된 부팅 키·해시 데이터베이스 대조, 기판·모뎀·교체 부품·물리 임플란트 검사는 제공하지 않는다.

## 검증과 실제 기기 한계

프로젝트 루트에서 `bash tests/run_attestation_tests.sh`를 실행한다. JDK 17과 SHA-256으로 고정한 JSON-java 테스트 의존성을 사용한다. JSON-java는 호스트 테스트에만 쓰며 APK에는 추가하지 않는다. 앱은 Android 내장 `org.json`을 사용한다.

373개 assertion에는 기존 DER 잘림 전 지점 검사와 2,000개 임의 입력, 같은 subject의 가짜 루트·서명 오류·만료 체인·체인 확장 공격 외에 `[709]` 형식·중복·정렬·UTF-8 오류, 64비트 버전 보존, 추가 서명자, 공유 UID, nonce 재사용, 다른 공개키, 키 소유 실패, 필수 조건 하나씩 누락, 기존 7개 교차 비교의 누락·불일치·날짜 정규화, 전체 체인 폐기/중지 일치, 사본 만료·미래 시각·잘못된 JSON·실제 사본 SHA 검사가 들어 있다. v1.3의 50개 추가 assertion은 비고유 속성 5개와 누락·중복·잘못된 UTF-8·빈 모델·소프트웨어 대체 금지, 갱신된 Google 루트 연결, 공장 CA 만료 예외, RKP 만료 거부, 다른 키로 흉내 낸 루트 이름 거부 등을 검사한다.

공식 `android/keyattestation` v0.4가 쓰는 공개 factory/RKP 인증서 fixture를 가져와 같은 성공/실패 사례를 검증했고, 나머지는 테스트용 합성 공개 인증서다. 개인키는 포함하지 않는다. 공식 fixture의 출처·고정 commit·SHA-256·Apache 2.0 라이선스는 `tests/attestation-fixtures/README-v1.3.md`와 `GOOGLE_TESTDATA_LICENSE`에 기록했다. 공식 Kotlin 검증기 전체의 차등 실행이나 Galaxy 실기기 성공 검사는 아직 수행하지 않았다.

이 수치는 파서와 판정 규칙의 회귀 검사 수다. 실제 Galaxy의 하드웨어 키, Samsung 펌웨어별 호환성, 루팅 우회나 악성코드 탐지율을 실증한 수치가 아니다. 에뮬레이터는 실제 TEE/StrongBox 증명 성공을 재현하지 못한다. 해당 검증은 실제 지원 기기와 변조/정상 대조군으로 별도로 수행해야 한다.

## 공식 참고 자료

- [Android: Verify hardware-backed key pairs with key attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
- [AOSP: Key and ID attestation / ASN.1 schema](https://source.android.com/docs/security/features/keystore/attestation)
- [AOSP: ATTESTATION_APPLICATION_ID 태그, 1 KiB 제한 및 software-enforced 성격](https://android.googlesource.com/platform/hardware/interfaces/+/61eadb7ce45a3f0236dfe108dfab0a1ca3cc66b2/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl)
- [Google 공식 루트 인증서 JSON](https://android.googleapis.com/attestation/root)
- [Google 공식 인증서 상태 목록](https://android.googleapis.com/attestation/status)
- [공식 Android Key Attestation 검증기](https://github.com/android/keyattestation)
- [검토한 공식 검증기 v0.4의 기간 검사](https://github.com/android/keyattestation/blob/v0.4/src/main/kotlin/provider/KeyAttestationCertPathValidator.kt)
- [검토한 공식 검증기 v0.4의 발급 방식 구분](https://github.com/android/keyattestation/blob/v0.4/src/main/kotlin/provider/KeyAttestationCertPath.kt)
- [Android API: 비고유 기기 속성 증명](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setDevicePropertiesAttestationIncluded(boolean))
- [Auditor 검증 대상 기기 지원 목록](https://attestation.app/about)

보고서 파일을 다른 기기로 옮기는 것만으로 외부 증명이 완료되지는 않는다. 내보낸 서명은 앱이 만든 challenge의 키 소유 증거이며 보고서 전체를 인증하지 않는다. 더 강한 실시간 증명은 외부 검증자가 직접 낸 nonce, 검증자에 대한 신뢰, 신뢰할 수 있는 전송과 최신 상태 조회를 함께 갖춰야 한다.

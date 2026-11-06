# 연구·공개 자료를 반영한 v1.3.0 범위

검토 및 구현일: 2026-11-07 (KST). 사용 목적은 공장 초기화 후 Galaxy 리퍼폰의 설명되지 않은 소프트웨어·변조 징후를 확인하고 근거가 충분한 항목을 조치 화면으로 연결하는 것입니다. 커스텀 OS 또는 루팅의 법적 성격을 앱이 판단하지 않습니다.

## 실제 코드로 반영

| 자료에서 얻은 요구 | 구현 위치 | 검증/한계 |
|---|---|---|
| 최신성 저하와 원자료 업데이트 분리 | CatalogUpdateVerifier/Store/Manager, ScanSession | 서명·해시·순번·최대30일·엄격 ZIP/JSON·원자 저장·실패 보존·자동조치 최신성 게이트. 단일 키, 기기 시간에 의존하며 TUF 준수 아님 |
| 설치 요청자/설치 기록/업데이트 권한 구분 | PackageProvenance | API30/33/34 가드. 값 없음·오류·미지원 구분. 설치 출처만으로 정상 판정하지 않음 |
| 정상 서명 키 교체와 실제 서명 불일치 구분 | SignatureLineage, BaselineComparator, ApkEvidence | 단일 서명 이력과 복수 서명 전체 집합 구분. 외부 보고서의 진위는 인증하지 않음 |
| 현대 APK 서명 형식과 구조 | pinned AOSP Android16 QPR2 apksig | 변경 없는126개Java소스(클라우드 서명 provider 제외), 재현 빌드. API37+ 및 모호한 SDK 범위 UNKNOWN. 범위 오류를 변조로 확정하지 않음 |
| 관리 앱 미등록이라는 사용자 조건 | FactoryResetPolicy, ManagementInspection | 추가 비시스템 앱, 활성 관리자/DO/PO, 조직 관리 상태. Knox 설치 흔적만으로 등록 판단 안 함. 수동 승인 없이 관리 등록 해제 안 함 |
| 해시 미일치 앱의 설명 가능한 추가 확인 | ManifestRiskInspection/Rules | 활성 접근성·관리자와 설치 요청/실제 부여된 문자·통화기록 권한의3개 조합. 실행 행위·신규 악성코드 탐지율 주장 안 함 |
| 구형 factory 인증서 만료와 RKP 구분 | AttestationChain | 실제 고정 Google RSA 공개 키·제한된 체인 구조·서명·CA 제약·현재 leaf 유효성 확인. RKP 만료, 미래 날짜, 알 수 없는 구조에는 예외 없음 |
| 기기 표시 모델 값의 교차 확인 | AttestationProbe/Record/Checks | API31+ 비고유 brand/device/product/manufacturer/model 증명 요청. 미지원 fallback은 UNKNOWN, IMEI/일련번호 수집 안 함 |
| 이전 지표 철회와 자동 조치의 일관성 | RemediationController, MalwareRemovalVerifier | 통합 활성 자료만 조치에 사용. 구형MVT별도경로 비활성. 재검증 중 만료도 마지막 게이트에서 재확인 |

## 논문에서 얻은 검증 원칙

- **LAMDA, ICLR2026**는 시간에 따른 Android 악성코드 분포 변화의 평가가 중요함을 보여 주는 데이터셋입니다. 이 앱에 논문 모델/학습 데이터셋 전체를 넣거나 해당 연구의 탐지율을 가져오지 않았습니다.
  https://proceedings.iclr.cc/paper_files/paper/2026/hash/e25858a93f4efc2efb1391f4169c7c81-Abstract-Conference.html
- **TIF, TSE2026**의 시간 변화에 강한 검증 관점을 참고했습니다. APK 파일 지문, 권한 규칙과 기능 테스트만으로 미지 변종 성능을 주장하지 않습니다.
  https://arxiv.org/html/2502.05098v3
  https://github.com/ZhengXR930/TIF
- **FrameDroid, ToSEM2026 accepted manuscript**와 **ADD, TIFS2026**를 참고해 향후 ML 도입에는 시간 분할·미관측 악성군·정상 Galaxy앱·적대적 변경·전체 추출 비용 평가가 필요하다고 기록했습니다. 현재 앱에 ML 분류기를 구현하지 않았습니다.
  https://discovery.ucl.ac.uk/id/eprint/10224566/
  https://ieeexplore.ieee.org/abstract/document/11675890

## 공식 코드·API·커뮤니티에서 반영한 점

- Android InstallSourceInfo: https://developer.android.com/reference/android/content/pm/InstallSourceInfo
- Android SigningInfo: https://developer.android.com/reference/android/content/pm/SigningInfo
- Android 기기 속성 증명: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setDevicePropertiesAttestationIncluded(boolean)
- Android 키 증명 및 독립 검증 필요성: https://developer.android.com/privacy-and-security/security-key-attestation
- 공식 검증기v0.4: https://github.com/android/keyattestation/releases/tag/v0.4
- AOSP apksig 고정 코드: https://android.googlesource.com/platform/tools/apksig/+/ba8f1f1c74b62b8742c9946b09d4a9c6ac7446ae/
- TUF 위협 모형: https://theupdateframework.io/docs/security/
- Knox 초기화 후 재등록: https://docs.samsungknox.com/admin/knox-mobile-enrollment/faq/
- SO의 API30 이전 getInstallSourceInfo 호출 오류: https://stackoverflow.com/questions/76741135/java-lang-nosuchmethoderror-no-virtual-method-getinstallsourceinfo — 기존가드를 유지하고 새API도분리했습니다.
- OWASP MASWE#188: https://github.com/OWASP/maswe/issues/188 — 인증서 구조·버전 차이는 fixtures/UNKNOWN 처리로 다룹니다.
- MVT#869: https://github.com/mvt-project/mvt/issues/869 — 삼성 복제 앱/다른사용자 결과 혼합의 교훈으로 현재프로필 한계를 유지합니다. 해당 문제가 본앱에도 있었다고 주장하지 않습니다.
- Auditor: https://attestation.app/about — 현재지원auditee목록에 없는Galaxy를 Auditor지원기기로 추천하지 않도록 안내를수정했습니다.

## 이번 버전에 넣지 않은 항목

YARA-X/DEX·native 정적 패턴 엔진, ML 분류기, 로컬 VPN 격리, 원격 독립 증명 서버, 모델별 OEM 승인 profile, Samsung Knox Enhanced Attestation 계약 연동, Google Product Application Transparency 포함 증명, MVT intrusion log 수집은 구현하지 않았습니다. 외부 엔진 코드를 단순 복사해 신규 악성코드 탐지를 보장할 수 없고, 각 기능의 Android 런타임/라이선스/오탐/권한/서버 요구 조건을 추가 검증해야 합니다.

Google APK 투명성은 일부 공식 Google 배포 바이트 확인에 유용하지만 Galaxy 전체 펌웨어의 순정 인증이나 악성코드 부재를 증명하지 않습니다.
https://developers.google.com/android/binary_transparency/google_apk/overview

자체 참조 비교는 제조사 인증 baseline이 아닙니다. 최초 검사 결과를 자동으로 순정으로 등록하지 않았습니다. 기기 전체가 침해되면 목록·파일읽기·앱실행·기기 시각이 속을 수 있으며, 소프트웨어 검사만으로 실제 하드웨어 변조를 배제할 수 없습니다.

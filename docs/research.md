# 무료 도구 조사와 구현 근거

확인일: 2026-11-06. 공개 개발사·프로젝트·Android 공식 자료를 기준으로 정리했습니다. 아래 앱들의 존재는 모든 기기의 출고 상태를 완전히 판별할 수 있다는 뜻이 아닙니다.

| 도구 | 무료 제공 범위 | 적용 판단 |
|---|---|---|
| RootBeer | 루팅 흔적 확인 라이브러리와 예제 앱. Apache-2.0 | 파일·패키지·개발 빌드 탐지 접근을 참고. 공식 README도 100% 탐지 불가능 명시. BusyBox만으로 루팅 판정하지 않음 |
| Key Attestation | 하드웨어 키 증명 생성·검증·내보내기. Apache-2.0 | 공개 Google 루트·요청 연결·부팅 상태 해석과 로컬 검증의 한계를 참고 |
| Auditor | 하드웨어 증명을 통한 기기·OS 무결성 확인. MIT | 외부 기기/서버, 페어링, 지원 모델의 중요성 참고. 앱 하나의 자기 검사로 같은 보증을 제공한다고 주장하지 않음 |
| App Manager | 앱·권한·서명·라이브러리 분석. GPLv3+ | 패키지와 민감 권한 목록 표시를 참고. 추적기·권한은 악성 판정과 다름 |
| Hypatia | 공개 DB를 이용한 알려진 악성파일 해시 검사. AGPL-3.0 계열 | 공식 GitHub가 2024-12-23 보관 처리되어 최신 백신 엔진으로 내장하지 않음 |
| Google Play Protect | Play 및 외부 설치 앱의 잠재적 유해 동작 검사 | 별도 검사 안내. 이 앱에 결과를 자동 수집하는 공용 API가 있다고 가정하지 않음 |
| Samsung Members | Galaxy 기능·소프트웨어 진단 | 제조사별 추가 점검 참고. 기능이 작동한다는 사실은 물리 부품 무변조 인증과 다름 |

## 1차 출처

1. RootBeer README, 범위 및 탐지 한계: https://github.com/scottyab/rootbeer
2. Key Attestation README, 네트워크 권한 없음·다른 기기 검증 권고: https://github.com/vvb2060/KeyAttestation
3. Auditor 설계와 두 번째 기기/서버 검증: https://attestation.app/about
4. App Manager: https://github.com/MuntashirAkon/AppManager
5. App Manager 매뉴얼: https://muntashir.dev/AppManager/en/
6. Hypatia 보관 상태: https://github.com/Divested-Mobile/Hypatia
7. Hypatia DB 업데이트 종료 관련 CalyxOS 공식 이슈: https://gitlab.com/CalyxOS/calyxos/-/issues/2890
8. Play Protect 기능과 사용자 검사: https://support.google.com/googleplay/answer/2812853
9. Samsung 공식 진단 안내: https://www.samsung.com/us/support/answer/ANS10003632/
10. Android Key Attestation 검증·루트·폐기목록: https://developer.android.com/privacy-and-security/security-key-attestation
11. 공식 Android Key Attestation verifier: https://github.com/android/keyattestation
12. AOSP ASN.1 키 증명 정의: https://source.android.com/docs/security/features/keystore/attestation
13. Verified Boot 색 상태: https://source.android.com/docs/security/features/verifiedboot/boot-flow
14. Android 앱 샌드박스: https://source.android.com/docs/security/app-sandbox
15. Android 앱 가시성 및 보안 앱 사례: https://developer.android.com/training/package-visibility/declaring
16. 공장 초기화의 데이터 제거 범위: https://support.google.com/android/answer/6088915
17. Play Integrity 구성: https://developer.android.com/google/play/integrity/overview
18. 공개 IOC와 clean 판정의 한계: https://docs.mvt.re/en/latest/introduction/
19. AGP 8.9와 Gradle/JDK/SDK 호환: https://developer.android.com/build/releases/agp-8-9-0-release-notes

## 설계 결정

네트워크 API 키와 유료 서버 없이 APK를 설치해 동작하게 하기 위해 로컬 선별 검사로 만들었습니다. v1.1.0은 공개 파일 IOC 156개와 공식 증명 키 폐기 목록의 내장 스냅샷을 추가했지만, 실시간 DB/폐기 상태 확인과 외부 검증 서버는 제공하지 않습니다. 자료의 출처·수집 시각·미검증 범위를 화면과 보고서에 명시합니다.

공장 초기화 기록이나 `green` 문자열만으로 ‘공장 출고와 동일’이라고 결론 내리지 않습니다. 사후 확인에는 모델별 공식 펌웨어·부팅 키 기준, 독립 검증 기기, 제조사 서비스 점검 등이 필요합니다.

## 1.1.0 추가 근거와 구현

| 자료 | 반영 | 그대로 제공하지 않는 부분 |
|---|---|---|
| AOSP apksig / apksig-android 4.4.0 | 실제 APK 다이제스트와 서명을 검증하는 공개 Android 포트 번들. 원본 AAR/JAR 해시·태그 commit 보존 | 최신 AOSP 검증기와 동일하다고 주장하지 않음. API34 이후 최종 플랫폼 판정은 UNKNOWN |
| MVT indicators MIT 저장소 | BTMOB 131 + EagleMsgSpy 25 파일 SHA-256의 정확 일치. 고정 commit·데이터해시·라이선스 포함 | 포괄적 악성코드 엔진, 동적행위, 변종, 앱 데이터 검사 |
| Android Key Attestation schema/verifier | [709] 앱 패키지·버전·서명, challenge·키 소유, 7개 OS/부팅 교차 비교, 폐기 목록 스냅샷 | 검사 대상 폰 안에서 외부 서버와 같은 신뢰 보증 |
| GrapheneOS Auditor 정책 | 제조사 부팅 키·정책·외부 기기 신뢰가 별도로 필요함을 설계에 반영 | Pixel 모델의 부팅 키를 갤럭시 순정 기준으로 사용하지 않음 |
| Android Settings.Global 최신 reference | 개발자 옵션·USB 디버깅의 0값을 안전/해결 완료로 해석하지 않음 | 타사 앱에 제한된 설정 상태를 정확히 읽었다고 주장하지 않음 |

추가 1차 출처:

- https://android.googlesource.com/platform/tools/apksig/
- https://github.com/MuntashirAkon/apksig-android
- https://github.com/MuntashirAkon/apksig-android/tree/4.4.0
- https://github.com/MuntashirAkon/AppManager/blob/master/versions.gradle
- https://github.com/mvt-project/mvt-indicators/tree/b22ddf05e1a31e7732b8895676987c5c3482ef65
- https://github.com/mvt-project/mvt-indicators/blob/b22ddf05e1a31e7732b8895676987c5c3482ef65/2026-05-26_btmob/sha256.txt
- https://github.com/mvt-project/mvt-indicators/blob/b22ddf05e1a31e7732b8895676987c5c3482ef65/2024-12-25_eaglemsgspy/sha256.txt
- https://grapheneos.org/articles/attestation-compatibility-guide
- https://developer.android.com/reference/android/provider/Settings.Global

삼성 Knox·Phonecheck·Blancco·iVerify·Zimperium/Lookout 등의 공개 상용 절차는 [별도 조사 문서](commercial-methodology-v1.1.md)에 출처·적용 범위를 정리했습니다. 비공개 코드나 상용 탐지 엔진을 사용하지 않았습니다.

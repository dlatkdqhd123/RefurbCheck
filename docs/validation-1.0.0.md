# RefurbCheck 1.0.0 검증 기록

검증일: 2026-11-06. 아래 결과는 개발 환경에서 수행한 검증이며, 사용자의 실제 휴대전화 판정이 아닙니다.

## 배포물

- 패키지: `io.github.refurbcheck`
- 앱 이름: `리퍼폰 점검`
- 버전: `1.0.0` / versionCode `1`
- 최소 Android: 8.0 / API 26
- compile/target SDK: 35
- 배포 APK 크기: 57,900 bytes
- APK SHA-256: `6291f729593532408b5a79fbb58be1afe6426d6b02e3c591093f17c089ef8b45`
- 서명 인증서 SHA-256: `31a3041c7933acb7cdafad342bb574f0726f6045ddf5ccf4d9fd3fc7f1f126ff`

## 수행 완료

| 검증 | 결과 |
|---|---|
| Google 공식 Android SDK platform 35 / Build Tools 35.0.0 다운로드 | 공식 메타데이터 파일 크기 및 SHA-1 일치 확인 |
| Java 컴파일 및 D8 변환 | 성공. 앱에 외부 런타임 라이브러리 없음 |
| aapt2 manifest·리소스 패키징 | 성공. package/minSdk/targetSdk/version/launcher 확인 |
| zipalign | 통과 |
| apksigner 검증 | APK Signature Scheme v2/v3 검증 통과, 서명자 1명, RSA 3072 |
| 권한 검사 | QUERY_ALL_PACKAGES, ACCESS_NETWORK_STATE만 선언. INTERNET 없음 |
| 부팅·패치 판정 테스트 | 22 assertions 통과 |
| DER·증명 체인 테스트 | 214 assertions 통과. 잘린 데이터 전 지점 검사와 2,000 malformed DER 입력 포함 |
| 보고서·참고 비교 테스트 | 39개 시나리오, 100 assertions 통과 |
| 전체 핵심 로직 검증 | 총 336 assertions 통과 |
| Android 8.0 AOSP x86 가상기기 설치 | 최종 서명 APK 설치 성공 |
| Android 가상기기 시작·자동 검사 | MainActivity 시작 및 29항목 결과 표시 확인 |
| Android 가상기기 핵심 UI 9개 확인 | 자동 검사, 설치 앱 탭, 안내 탭, 확인 불가 필터/스크롤, 재검사 후 가로 회전, 세로 복귀 후 검사 완료, JSON 저장 화면 열기, 취소 복귀, Fatal exception·ANR 미발견 |

핵심 테스트는 미지원·누락값이 정상으로 바뀌지 않는지, 가짜 루트·잘못된 서명·만료 체인이 신뢰되지 않는지, 설명 문구만 있을 때 ‘징후 없음’으로 표시하지 않는지, 참고 파일의 잘못된 서명을 일치로 처리하지 않는지 확인합니다.

가상기기는 개발용 OS와 소프트웨어 키 저장소 등을 사용하므로 그 경고·미지원 결과를 실제 휴대전화의 위험도와 비교할 수 없습니다. 실물 TEE/StrongBox 증명 성공률, 제조사별 API 차이 및 탐지 정확도는 이 테스트로 입증되지 않습니다.

## 미실시·제한

- 실제 삼성·구글·샤오미 등 물리 기기 실행과 실제 제조사 하드웨어 증명은 미검증입니다.
- 런타임 검증은 Android 8.0/API 26에 한정합니다. Android 15/API 35 런타임과 JSON 파일의 실제 쓰기 완료는 검증하지 않았습니다. JSON은 저장 화면 열기와 취소 복귀까지만 확인했습니다.
- 실제 악성코드 샘플·감염 기기 실험, 탐지율/오탐률 측정은 하지 않았습니다. 앱에는 백신 엔진이 없습니다.
- 최신 증명 키 폐기목록 조회, 외부 검증 서비스, Play Integrity, 공식 펌웨어 전체 비교, 물리 부품 검증은 구현하지 않았습니다.
- GitHub Actions 및 Gradle의 assemble/lint 작업은 이 환경에서 실행 완료되지 않았습니다. Gradle wrapper 배포 ZIP 다운로드에서 Java 네트워크 연결이 막혔고, Gradle 컴파일·lint는 시작되지 않았습니다. 실제 배포 APK는 공식 SDK 도구를 직접 사용하는 `tools/build_apk.py`로 컴파일·서명·검증했습니다.
- 인증서 루트·패키지 탐지 목록은 업데이트가 필요할 수 있습니다. 오래된 목록으로 새로운 위협까지 확인했다고 해석하면 안 됩니다.

상세 정적 패키지 검증 출력은 `release/apk-build-verification.txt`에 있습니다. 테스트 스크립트와 가상 테스트 인증서도 소스에 포함했습니다. 개인 서명키와 암호는 배포 소스에 포함하지 않았습니다.

가상기기 실행 확인 기록: `docs/ui-smoke-results.json`. 화면 예시: `docs/images/emulator-overview.png`. 예시의 숫자는 테스트용 에뮬레이터의 결과이며 사용자의 휴대전화 결과가 아닙니다.

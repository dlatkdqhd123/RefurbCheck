# RefurbCheck 1.3.0 검증 기록

검증일2026-11-07 KST. 아래 호스트 테스트는 실제 최종 배포 APK를 입력으로 실행했습니다.

- APK SHA-256: `2d1b2c0d1222cf5089c0a30a10a81f884f8286f7b86cf214f82bb7f089f7efc8`
- APK 크기890,794bytes, package `io.github.refurbcheck`, version1.3.0/code4, minAPI26/target35
- 새 signer SHA-256: `d02b8c5cbcde0ad3fbd3eb9e4c66e28094a27cf4f7a8472d309f84d825184ceb`
- SDK35.0.0 apksigner: v2/v3 유효, RSA3072단일서명. 정상 APK서명은 앱 안전성·삼성 공식 인증을 의미하지 않습니다.
- 실제 입력64파일을 `release/source-file-sha256-1.3.0.json`에 기록했습니다.

## 호스트 회귀 테스트

| 영역 | assertion |
|---|---:|
| 키 증명·DER·공장CA/RKP·속성 |373|
| 보고서·엄격JSON·참고비교 |478|
| APK파일·서명·변경 |51|
| 기존조치/설정결과 규칙 호환 |107|
| 멀티해시·ZIP·압축/범위·변조 |1,331|
| 현재자료 기반 삭제전 증거 |326|
| 설치·서명이력·초기화후정책 |133|
| 활성권한조합 |229|
| AOSP APK서명 API별회전/변조 |53|
| 서명된자료 갱신·저장·롤백 |102|
| 시스템표시규칙 |22|
| **합계** |**3,205**|

모두 통과했습니다. 전체 로그는 `docs/validation-1.3.0-host.txt`입니다. 이 수치는 검출 악성코드 수나 정확도·오탐률이 아닙니다. DER2,000개입력·ZIP1,000개변형을 다루는 기존 검증도 유지했으며 이를 별도 악성코드 표본 수로 계산하지 않습니다. 구형MVT조치 규칙은 호환 테스트만 남고 실제v1.3조치 경로에서는 호출하지 않습니다.

AOSP Android16 QPR2의126개원본Java파일로 새apksig JAR을 재빌드하여 바이트 단위 동일 SHA-256을 확인했습니다. 원본코드commit은2025-07-16이며 다운로드일이2026-11-07이라고 코드 작성일을 바꾸지 않았습니다.

## Android 실행 검증과 게시 조건

공개된 v1.3.0릴리스는 `.github/workflows/release.yml`의API26/API36두실행작업이 모두 성공한 경우에만 게시됩니다. 실제 완료 여부·실행로그는 해당릴리스커밋의GitHub Actions run을 확인하세요. 이문서작성시점의로컬검증과 이후GitHub실행결과를 혼동하지 않습니다.

`tests/android-v13/run_ci.sh`는 배포APK의사본을 임시CI키로재서명한후 별도testOnly instrumentationAPK와실행합니다. DEX·AndroidManifest·리소스·자산및비서명ZIP항목이정식APK와바이트단위동일한지확인합니다. 달라지는것은 APK서명정보이며 배포개인키는CI에전달하지않습니다. 테스트후임시앱들을제거하고 정확한배포서명APK도설치·시작합니다.

실행시험은실제Android API의설치정보분기,관리상태,자기APK해시/서명,서명자료가져오기/변조거부/기존자료보존,Android암호공급자의ECDSA/v3.1,공식factory/RKP인증서,키증명의UNKNOWN처리를확인합니다. 최종JSON·통과수·API·정확한테스트대상해시·Instrumentation종료코드를모두검사합니다. `am instrument`셸종료코드만으로성공이라고하지않습니다.

## 아직 확인하지 않은 것

실제Galaxy/OneUI별동작과성능,물리부품·전체펌웨어무변조,제조사별순정기준,실제악성코드탐지율/오탐률,0-day/새악성군,독립원격키증명은검증하지않았습니다. 무해한fixture의정확일치·구조실패테스트를실제악성코드정확도로표시하지않습니다. 새v1.3Android시험은제거확인UI의실제삭제를실행하지않습니다. v1.2에서기존흐름을검사한기록은별도버전기록으로남깁니다.

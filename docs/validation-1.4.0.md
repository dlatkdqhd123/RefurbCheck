# RefurbCheck 1.4.0 최종 검증 — 2026-11-07

- 검증 커밋: `aadeab8659163180545fbe69d2ba79c151dec273` (`release/1.4.0`)
- [성공한 CI 실행](https://github.com/dlatkdqhd123/RefurbCheck/actions/runs/42341669753)
- [검토용 릴리스 초안](https://github.com/dlatkdqhd123/RefurbCheck/releases/tag/untagged-921b6039cead9884c3af) — 저장소 계정으로 확인 가능. 공개 승인 전에는 일반 다운로드 링크가 동작하지 않는다.

## 결과

| 검증 | 결과 |
|---|---|
| 검토된 APK·앱/build 입력 | 65개 입력 지문 및 APK 지문 일치 |
| 전체 호스트 회귀 검사 | 키 증명, 보고서, APK, 조치, 악성 파일 근거, 자료 갱신, 정책, 실행 상태 검사 모두 통과 |
| 실행 상태 회귀 검사 | 22개 시나리오, 250개 assertion, 실패 0 |
| Android API26 실행 | 134개 runtime assertion 통과, 110027ms |
| Android API36 실행 | 130개 runtime assertion 통과, 118217ms |
| 실행·중지·회전·task 복귀 | 두 API에서 실제 Activity 동작 확인, 새 launcher의 resumed 상태 확인 |
| 자동 전체 점검 | 두 API에서 `COMPLETE`, 최초 scanCount=1, 불필요한 재검사·허위 삭제 결과 없음 |
| 원본 APK 1.3→1.4 업데이트 | 두 API에서 삭제 없이 `adb install -r` 성공, versionCode 4→5, 최초 설치 시각 유지 |
| 원본 배포 앱 화면 | 두 API에서 실제 1.4.0 실행과 한 번에 점검 단계 UI·스크린샷 확인 |
| 서명 | 1.3/1.4 동일 배포 인증서, v2/v3 APK 서명 검증 통과 |

APK SHA-256: `56d9586b825520a9b1fe7d443d1398f4879a3e1eed6fa90b995293e9ad54ca59`

APK 크기: 903082바이트.

배포 인증서 SHA-256: `d02b8c5cbcde0ad3fbd3eb9e4c66e28094a27cf4f7a8472d309f84d825184ceb`.

검증용 임시 서명 앱은 배포 APK의 DEX·manifest·리소스·자산을 그대로 유지한다. 원본 배포 APK의 직접 파일 검사와 배포 서명 그대로의 설치·업데이트·시작은 별도로 확인했다. 배포 APK·서명키를 바꾸지 않았으며 개인키를 CI에 넣거나 공개하지 않았다.

## 근거 파일과 제한

CI의 `RefurbCheck-1.4-host-validation`, `RefurbCheck-1.4-android-26-validation`, `RefurbCheck-1.4-android-36-validation` artifact에 로그, `summary.json`, `upgrade-summary.json`, 원본 배포 앱 화면 XML/PNG가 있다. 결과 파일은 보관 기간 30일이다.

이번 이어하기에서는 로컬 에뮬레이터를 시작하지 않았고, Actions도 수정 뒤 한 번만 실행했다. 호스트 job 30초, API26 job 3분56초, API36 job 4분10초, 초안 준비 10초로 끝났다. 불필요한 재빌드를 피하기 위해 이 문서만의 커밋은 CI를 생략한다. 태그·배포 소스 ZIP은 위 검증 커밋을 유지한다.

실제 Galaxy/One UI 시험, 모든 기기·프로필·악성코드 탐지율 측정, 실제 삭제 실행은 이번 runtime 검증 결과가 아니다. 악성 앱 삭제 결과·보류 조건은 상태/정책 회귀 검사로 검증했으며 Android 사용자 삭제 승인은 여전히 필요하다. 순정 OS·악성코드 부재·물리 부품 무변조를 보증하지 않는다.

## 공개 상태

1.4.0 APK·소스 ZIP·지문·서명 자료는 **초안**에 준비했다. 결과 검토 후 사용자가 공개를 승인해야 정식 릴리스를 공개한다. 현재 공개 최신 릴리스는 1.3.0이다. 기존 태그나 자산은 덮어쓰지 않는다.

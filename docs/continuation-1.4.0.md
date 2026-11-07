# 1.4.0 배포 검증 이어하기 — 2026-11-07

## 기준과 실패 원인

- 공개 버전은 1.3.0이다. `main`은 prototype이며 작업 기준이 아니다.
- 한 번에 점검 개선은 `release/1.4.0`의 `a065eba59ea8bfbe5ee957db114d45be5f001df7`에 이미 구현되어 있다. 새로 만들거나 기존 APK를 재서명하지 않았다.
- 기존 CI `42322065979`의 호스트·입력 지문 검증은 통과했지만, Android API26/36 모두 `V14Instrumentation.oneRunLifecycle`의 두 번째 회전 준비에서 null Activity의 `getResources()`를 호출해 실패했다.
- 새 launcher intent는 `onNewIntent`에서 runId를 바꾸지만 그 시점이 `onResume` 완료와 같지는 않다. 앱의 작업 상태 변화만 기다리던 테스트가 일시적으로 paused 상태인 Activity를 읽었다. 이것만으로 앱 전체가 정상이라고 판단하지 않는다.

## 수정

- 테스트의 resumed Activity 관찰과 조건 검사를 Android main thread에 모았다. 새 runId와 resumed/non-destroyed Activity를 함께 기다린 뒤 UI를 읽는다.
- 회전과 task 복귀에서도 같은 main-thread 관찰을 사용한다. 제한 시간 내 복귀하지 않으면 테스트는 계속 실패한다. 임의 sleep이나 무조건 재시도, 검증 생략을 추가하지 않았다.
- 최종 결과 검사기는 `freshLauncherResumedBeforeUiAccess` 근거를 추가로 요구한다.
- 앱 실행 코드, APK, versionCode, 참조 자료, APK 서명 인증서는 변경하지 않았다.
- CI는 성공 시 릴리스 초안까지만 생성한다. 사용자 결과 검토와 승인 없이 초안을 공개하지 않는다.

## 로컬 검증

- APK와 앱/build 입력 65개 지문 검증 통과. Windows 체크아웃 줄바꿈을 원래 Git 커밋 바이트로 복원해 검사했다. 앱 소스의 내용 변경은 없다.
- `OneRunStateTests`: 22개 시나리오, 250개 assertion, 실패 0.
- 로컬 Android 에뮬레이터를 시작하지 않았다. 필요한 컴파일과 작은 상태 회귀 검사만 실행해 PC 자원을 절약했다.
- Android API26/36 실행, 원본 APK의 1.3→1.4 업데이트 설치, 동일 서명 검증은 수정 커밋의 CI에서 확인해야 한다.

앱의 공장 순정·악성코드 부재·물리 하드웨어 무변조 인증 한계는 그대로 유지한다. Android 삭제 승인은 생략하지 않으며, 이름·설치 출처·권한 조합만으로 자동 삭제하지 않는다.

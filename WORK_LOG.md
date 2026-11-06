# 작업 기록

## 2026-11-06

- 기존 다른 대화의 APK·소스 접근 제한을 유지하고 독립 프로젝트를 생성했다. 기존 1.1.0과 다른 applicationId이며 업데이트·동일 기능을 보장하지 않는다.
- 로컬 골격과 Gradle Wrapper, 최소 권한의 CI를 커밋했다: `dfedcad488666cdecb997d0ec8c8ddb8921e7ad6`.
- 사용자가 CLI 브라우저 인증 및 PC 저장을 승인했다. 공식 `gh auth login --hostname github.com --git-protocol https --web` 흐름을 시작했고 사용자 승인을 기다리는 중이다. 토큰·일회용 인증 코드는 이 기록에 저장하지 않는다.
- 화면 잠금, OS 보안 패치 날짜, 암호화 상태, 빌드 신호, 접근성·관리자 목록 및 접근 가능한 앱의 권한·설치 출처·디버그 설정을 구현했다.
- ADB·개발자 옵션은 일반 앱에 제한된 값을 반환할 수 있어 자동 안전 판정을 하지 않는다. 부트/Knox/하드웨어 무결성, 악성코드 부재도 확정하지 않는다.
- 설정 열기, 앱 정보·삭제 방법 안내, 명시적 동의 후 보고서 공유를 구현했다. 자동 삭제·권한 해제·설정 변경·네트워크 전송은 구현하지 않았다.
- 표준 Wrapper 다운로드는 Java TLS 인증 경로 검증 실패로 중단됐다. 검증 해제·임의 인증서 추가는 하지 않았다. 기존 Windows 신뢰 저장소를 사용하는 프로세스 한정 시도도 저장소 접근 오류로 실패했다. OS 전역 설정은 바꾸지 않았다.
- 최초 소스 컴파일에서 공개 SDK에 없는 업데이트 설정 상수 참조를 발견하여 일반 설정 화면으로 수정했다. 설치된 SDK/Gradle 캐시로 빌드 검증을 진행 중이다.

- 전체 Java 소스의 Android 36 SDK 대상 `javac --release 17` 컴파일이 성공했다. 공개 API에 맞게 업데이트 연결을 일반 설정 화면으로 수정했다.
- 날짜 형식·잘못된 날짜·미래 패치·180/181일 경계·윤년·권한 요청과 허용 비트 구분 테스트 13개가 통과했다.
- 오프라인 Gradle 구성 단계는 Kotlin/ASM 등 캐시 의존성 부족으로 실패했다. APK 조립·lint·실기기/에뮬레이터 실행 검증은 미완료다.
- 소스에 토큰·서명키·일회용 인증 코드가 없는지 패턴 검사했고 발견되지 않았다. 전수 악성코드 검사가 아닌 앱 신호 점검이라는 한계를 UI와 README에 명시했다.
- GitHub CLI 브라우저 승인은 여전히 대기 중이다. GitHub push·CI 실행·APK 게시가 성공했다고 기록하지 않는다.

- PC 사용자 환경에서 `gh auth status`로 `dlatkdqhd123` 계정의 활성 로그인과 키링 저장을 확인했다. 채팅·프로젝트에 토큰을 저장하지 않았다. 이전 제한 실행 환경의 로그인 대기 프로세스와 구분한다.
- GitHub API로 `dlatkdqhd123/RefurbCheck`가 공개(`isPrivate: false`)이며 기본 브랜치가 없는 빈 저장소임을 확인했다. 인증된 `git ls-remote`도 기존 refs 없이 성공했다.
- PC 사용자와 작업 폴더의 소유자가 달라 Git 소유자 검사가 발생했다. 전역 예외 대신 이 작업의 Git 명령에 정확한 저장소 경로만 `safe.directory`로 지정한다.

- 소스를 공개 저장소 `https://github.com/dlatkdqhd123/RefurbCheck`의 `main`에 push했다. 원격 기본 브랜치 `main`과 공개 상태를 재확인했다.
- 게시 커밋 `1c94a2f0c4fbd67ff07a03a5891acc207c6d3781`의 CI 실행이 시작됐다: `https://github.com/dlatkdqhd123/RefurbCheck/actions/runs/42195100462`. 결과 확인 중이다.

- CI `42195100462`가 성공했다. APK 조립(`assembleDebug`), `lintDebug`, 규칙 테스트 13개 및 artifact 업로드가 모두 통과했다. 빌드 job 소요 시간은 52초다. 로컬 TLS 오류를 우회하지 않고 GitHub 호스팅 runner에서 빌드했다.
- 새 CI artifact `RefurbCheck-prototype-debug`(ID `13491033022`, 보관 7일)를 `build/ci-apk/app-debug.apk`로 다운로드했다. 이 파일은 Git 추적에서 제외된다. 기존 차단 파일이 아닌 이번 새 구현의 산출물이다.
- APK 크기: 861518바이트. SHA-256: `2cd5babdd36e988be09131614cf1128559d0be6f4f1bf34ad7a23e4b0f825459`.
- 공식 SDK `apksigner verify --verbose --print-certs`로 유효한 v2 APK 서명을 확인했다. 인증서는 Android Debug이며 배포용 릴리스 서명이 아니다. CI debug 키는 저장소에 게시하지 않는다. 호스팅 runner마다 debug 키가 달라질 수 있어 이후 APK의 업데이트 설치가 보장되지 않는다.
- 공식 SDK `aapt2 dump permissions`에서 package `io.github.dlatkdqhd123.refurbcheck.prototype` 및 요청 권한이 없음을 확인했다.
- PC 사용자 환경의 ADB는 `emulator-5580 unauthorized`를 보고했다. 인증을 우회하거나 에뮬레이터에 APK를 설치하지 않았다. UI/실기기 동작 검증은 남아 있다. 정상 기기·감염 없음·하드웨어 무결성을 보증하지 않는다.
- GitHub Actions는 `upload-artifact@v4`의 Node 20 런타임 폐기와 호스팅 Ubuntu 버전 전환에 대한 안내를 출력했으나, 해당 작업은 성공했다.

완료: 공개 소스 게시, CI 빌드·lint·규칙 테스트, debug APK 다운로드·서명/권한 확인.
남은 검증: 사용자 승인된 에뮬레이터/실제 갤럭시에서 UI·제조사 설정 연결·패키지 가시성 동작 확인. 배포용 서명 및 백신/무결성 증명은 제공 범위에 포함되지 않는다.


## 1.2.0 공개 배포 — 2026-11-06

별도 검증된 1.2.0 전체 소스와 서명 APK를 `release/1.2.0` 브랜치 및 `v1.2.0` 태그로 게시했습니다. 이 커밋은 `main`의 0.2 시험판 코드·빌드 구성을 보존하고 다운로드 안내만 추가합니다.

- 릴리스: https://github.com/dlatkdqhd123/RefurbCheck/releases/tag/v1.2.0
- 설치 패키지: `io.github.refurbcheck`, versionName `1.2.0`, versionCode `3`
- APK SHA-256: `addf557694e94e499f4409b764ccc0780629f137e1e6494ce5eb357e6d51be8c`
- 서명 인증서 SHA-256: `31a3041c7933acb7cdafad342bb574f0726f6045ddf5ccf4d9fd3fc7f1f126ff`
- 배포 workflow가 고정 APK·서명·51개 입력 파일 지문을 검사한 뒤 현재 커밋의 소스 ZIP을 함께 게시합니다. 개인 서명키·암호는 게시하지 않았습니다.
- 검증 범위와 미검증 항목은 1.2.0의 `docs/validation.md`에 있으며, 실제 Galaxy/One UI 또는 실제 악성코드 탐지율 시험을 수행했다는 뜻은 아닙니다.

게시 검증: https://github.com/dlatkdqhd123/RefurbCheck/actions/runs/42215327279 — success. 태그는 `a50f52d7f53fa31d50dcf843f4dadf29348d70a7`을 가리키며, 공개 Release의 APK digest가 위 SHA-256과 일치합니다. 공개 소스 ZIP SHA-256은 `e366435776f1e09464dee142a31f6ae681cfd5328c3f61f710a0367bd89e26df`입니다. 소스 ZIP에는 배포 문서와 workflow 변경이 포함되며, APK와 검토된 51개 입력 파일은 변경하지 않았습니다.

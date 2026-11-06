# v1.2 검증 전용 fixture와 UI 시험 재현 소스

이 폴더는 **실제 배포 앱과 분리된 무해한 시험 앱을 만드는 소스**입니다. 실제 악성 샘플, APK, 키 저장소, 암호 파일, 대용량 로그는 포함하지 않습니다. 실행한 결과와 한계는 `docs/test-only-remediation-v1.2.md` 및 JSON에 기록합니다.

## 시험 목적

권한·실행 코드가 없는 fixture 2개를 만듭니다. 하나는 signed APK 전체 SHA-256, 다른 하나는 설명용 평문 ZIP 항목의 SHA-256으로 검출합니다. `fixture.synthetic` 출처는 별도 테스트 카탈로그에만 들어가며, 배포 앱 데이터에 추가하면 안 됩니다.

복제한 테스트 앱의 applicationId는 `io.github.refurbcheck.validation`, Activity 클래스는 원래 `io.github.refurbcheck.MainActivity`입니다. `testOnly=true`, `debuggable=true`를 적용하고 원래 Java 동작 코드는 생성 `MalwareCatalog.java` 외에 수정하지 않습니다. 실제 preflight·시스템 승인·취소·재개·순차 제거·최종 재검사 코드를 실행하기 위한 구성입니다.

## 준비와 파일 배치

시험에는 JDK 17, Python 3, 공식 Android SDK의 platform 35·build-tools 35.0.0·platform-tools·emulator와 API 26 x86 시스템 이미지가 필요합니다. 사용 중인 개인 휴대폰 대신 폐기 가능한 에뮬레이터를 사용하세요. 에뮬레이터는 앱 목록을 기본 84개로 준비했던 본 세션과 다를 수 있으므로 숫자 자체를 통과 조건으로 삼지 않습니다.

아래처럼 **프로젝트 밖의 별도 작업 폴더**로 복사하여 실행합니다. 설명에서 `/work`는 사용자가 선택한 작업 디렉터리입니다.

| 경로 | 내용 |
|---|---|
| `/work/refurbcheck` | 이 버전의 전체 소스 프로젝트 |
| `/work/android-toolchain/sdk` | 공식 SDK와 API 26 x86 이미지 |
| `/work/android-toolchain/v1.2-fixtures` | 이 폴더의 최상위 Python/Java 소스를 복사할 위치 |
| `/work/android-toolchain/emulator_smoke_driver.py` | `support/`의 동일 이름 파일 |
| `/work/android-toolchain/send_smoke_command.py` | `support/`의 동일 이름 파일 |
| `/work/android-toolchain/avd` | `RefurbCheck_Smoke` AVD 설정 위치 |

지원 driver는 `RefurbCheck_Smoke`라는 AVD를 `emulator-5580`으로 실행하고, 동일 디렉터리의 `smoke-queue`/`smoke-results`로 명령을 한 번씩 처리합니다. AVD와 SDK 위치는 driver 상단에 명시되어 있으므로 공식 SDK의 AVD 도구로 해당 위치에 먼저 준비합니다. driver에 포함된 추가 `emulator-host-libs` 검색 경로는 이 세션의 Linux 실행 환경 보조 설정이며 다른 호스트에서는 일반 SDK 시스템 의존성 설치로 충족할 수 있습니다.

공유 에뮬레이터를 여러 실행자가 동시에 조작하지 않습니다. 실제 시험에서는 부모 실행자와 순서 인계 후 단독으로 UI를 사용했습니다.

## 생성과 실행

아래 명령은 `/work/android-toolchain/v1.2-fixtures`를 작업 디렉터리로 실행합니다.

```bash
python3 create_fixtures.py
python3 build_validation_clone.py --freeze-confirmed
```

`--freeze-confirmed`는 운영 소스를 변경 중인 다른 실행자가 없을 때만 사용합니다. 복제 전후 소스 지문이 달라지면 빌더가 중지합니다. 별도 서명 키와 암호 파일은 프로젝트 밖의 `private-test-signing/`에 생성됩니다. 공개 재현 소스는 새 난수 암호를 만들며, 본 세션의 실제 암호를 포함하지 않습니다.

서명 키를 매번 새로 만들므로 **재현 APK의 해시는 본 세션 기록과 달라집니다.** 생성기가 실제 생성한 APK·내부 파일 해시를 계산하고 테스트 카탈로그 및 상수를 다시 고정합니다. 이것은 동일 기능 시나리오의 재현이며 개인 서명 키를 포함하는 바이트 단위 복제 배포가 아닙니다. `source-manifest.json`에는 본 세션 원본 소스와 공개 재현 소스의 SHA-256 및 암호 생성 방식의 작은 차이를 기록합니다.

다른 터미널에서 driver를 유지합니다.

```bash
python3 /work/android-toolchain/emulator_smoke_driver.py \
  --no-install --duration 7200 \
  --artifacts /work/android-toolchain/smoke-artifacts-v1.2
```

에뮬레이터 부팅과 `Ready for queued commands`를 확인한 뒤, **단독 UI 사용이 가능한 상태에서만** 각 단계를 차례로 실행합니다.

```bash
python3 run_validation.py first --exclusive-ui-granted
python3 run_validation.py cancel --exclusive-ui-granted
python3 run_validation.py resume --exclusive-ui-granted
```

첫 단계는 앱 실행 후 최초 시스템 승인창에서 멈춥니다. 두 번째는 실제 취소와 재검사·보고서 회수 후 멈춥니다. 세 번째는 `fixture.whole`과 `fixture.entry`에 해당하는 두 무해한 앱의 Android 승인창만 확인하고, 순차 제거 뒤 마지막 재검사까지 관찰합니다. 알려지지 않은 대상의 제거를 허용하는 일반 자동 클릭 스크립트가 아닙니다.

이 시나리오에서 fixture 제거는 원래 앱의 요청에 따라 표시된 Android 승인창의 `OK`를 눌러 수행합니다. `adb uninstall`로 이 기능 검증을 대체하지 않습니다. 모든 보고서·UI XML·화면·명령 이력은 프로젝트 밖 `evidence/`에 저장됩니다. 시험 끝에는 검증용 앱을 정리하고 에뮬레이터 사용을 종료하거나 다음 검증자에게 인계합니다.

## 검사 한계와 읽기 재시도

소프트웨어 에뮬레이터에서는 UIAutomator 호출도 CPU를 사용합니다. 진행 중인 검사 화면은 20초 간격으로 확인합니다. 3분의 앱 검사 예산에 도달하면 나머지는 `TIME_LIMIT`/확인 불가로 기록해야 하며, 전체 안전 또는 전체 완료로 바꾸면 안 됩니다. 시험 대상 각각이 complete한 정확 일치 근거를 제공했는지와 전체 환경의 coverage 완료 여부는 별도로 확인합니다.

UIAutomator는 Activity 전환 도중 exit 0과 null-root 진단을 함께 돌려줄 수 있습니다. 하네스는 UI **읽기만** 제한적으로 재시도합니다. 버튼 조작이나 제거 동작을 무조건 재실행하지 않습니다. 실제 기기·관리자 차단·업무 프로필·다른 Android 버전·악성 표본 재현율은 이 단일 시나리오가 검증하지 않습니다.

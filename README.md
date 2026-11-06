# RefurbCheck — independent prototype

새로 생성한 Android 프로젝트의 빌드 가능한 시작점입니다. 이전 버전의 APK·소스는 사용하지 않았으며 기존 1.1.0과 기능 동등성 또는 업데이트 호환성을 보장하지 않습니다. 별도 applicationId를 사용합니다.

**검사 기능은 아직 없습니다.** 기기 상태 판정, 악성코드 탐지·치료, 백신 기능을 제공하지 않습니다. 기존 기능 요구사항이 확인되지 않아 임의로 구현하지 않았습니다.

## Local build

Android SDK 36과 Java 21이 필요합니다. Android Studio에서 이 폴더를 열고 SDK 위치를 설정하거나 로컬 `local.properties`에 `sdk.dir`을 설정합니다. `local.properties`는 게시하지 않습니다.

```powershell
.\gradlew.bat assembleDebug lintDebug
```

APK: `app/build/outputs/apk/debug/app-debug.apk`. 개발용 debug APK이며 배포용 서명 릴리스가 아닙니다. 별도 서명키는 생성하거나 저장소에 넣지 않습니다.

## CI

순서: 로컬 프로젝트 생성 → GitHub에 소스 커밋·push → GitHub Actions 빌드·lint → Actions artifact에서 debug APK 다운로드. CI가 PC의 미게시 파일을 GitHub로 전송하는 구조가 아닙니다.

워크플로는 `main` push, PR, 수동 실행에서 동작합니다. 코드 읽기 권한만 요청하며, release 게시·자동 push·비밀키를 사용하지 않습니다. 공개 저장소의 빌드 결과도 공개될 수 있습니다.

## Security and privacy

현재 앱에는 요청 권한, 네트워크 통신, 분석 SDK, 계정 접근, 파일 스캔이 없습니다. launcher Activity만 외부 실행 가능하게 선언되어 있습니다. 키·토큰·사용자 자료·로컬 SDK 경로·빌드 산출물은 커밋에서 제외합니다. 검사나 백신 기능 추가 시 권한·데이터 처리와 기능 한계를 다시 검토해야 합니다.

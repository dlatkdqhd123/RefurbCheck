# RefurbCheck용 ClamAV Android 해시 자료

이 폴더는 **공식 ClamAV 서명 자료 중 Android 플랫폼 파일 해시 일부**와 변환 기록이다. ClamAV 전체 엔진, 전체 규칙, 실시간 보호, 동적 분석, 치료 엔진을 포함하지 않는다. 실제 악성코드 실행 파일은 수집하거나 포함하지 않았다.

## 수록 내용

- `clamav-android.tsv`: Android용 MD5/SHA256 및 **정확한 파일 크기**를 유지한 13,764개 규칙.
- `clamav-allow.tsv`: 공식 `.fp`/`.sfp`의 996개 파일 허용 규칙. **ClamAV 자료에서 나온 탐지에만 적용**한다. 다른 조사기관의 탐지를 자동으로 무효화하는 범용 안전 목록이 아니다.
- `raw/`: 선택한 원문 `.hdb`/`.hsb` 행, 전체 `.fp`/`.sfp`/`.ign`/`.ign2`, 서명된 CVD 내부 파일 정보 및 라이선스 사본.
- `provenance.json`: 원본 CVD SHA256·버전·작성 시각, 선택 규칙, 제외 수, 원문·결과 파일 SHA256.
- `excluded-records.json`: 광고 프로그램·도구·패킹 분류 308개, 폐기 규칙 1개, 동일 해시/크기의 별칭 4개를 제외한 기록.
- `*.sigtool.txt`, `verification-tool-provenance.json`: 공식 ClamAV 도구가 원본 CVD를 검증한 기록과 도구 출처.
- `normalize_clamav_android.py`: 원본 검증·추출 및 동봉 원문에서 TSV를 재생성하는 변환 스크립트.

## 원본과 검증

기준일은 2026-11-06이다. `main.cvd`는 버전 63, 2025-12-16 23:18 UTC 작성본이며 `daily.cvd`는 버전 28175, 2026-11-06 06:24 UTC 작성본이다. 선택된 Android 해시 규칙은 모두 `main`에서 왔다. `daily`는 최신 폐기·허용 목록을 반영하는 데 사용했다. 이 자료의 모든 Android 규칙이 2026년에 새로 추가된 것이라는 뜻은 아니다.

공식 CVDUpdate 1.2.0 설치와 정상 실행을 시도했으나 환경의 DNS TXT 요청이 차단되어 종료됐다. DNS나 네트워크 정책을 변경하지 않았다. 공개 재배포 미러 <https://mirror.sg.gs/clamav/>에서 원본 CVD를 받고, **공식 `clamav/clamav` 이미지에서 가져온 ClamAV sigtool 1.5.4**로 두 파일의 `Verification OK`를 확인했다. OCI manifest·config·다운로드한 도구 레이어의 SHA256도 검증했다. 공식 이미지의 프로그램을 Android 앱에 포함한 것은 아니다.

검증에 사용된 CVD 서명은 ClamAV의 기존 RSA/MD5 내부 서명이다. 별도의 최신 `.sign` 파일을 검증했다고 주장하지 않는다. 변환기는 외부 CVD 헤더의 버전·시각·발행자 등이 서명된 내부 `.info`와 일치하는지도 확인하고, 검사에 사용하는 원본 멤버들의 SHA256과 크기도 비교한다.

## 선택과 판정 범위

`.hdb`/`.hsb`의 이름이 `Andr.` 또는 `Android.`로 시작하는 행만 대상으로 삼았다. `Win.Trojan.Android`처럼 Windows 플랫폼 이름에 Android라는 단어만 들어간 행은 포함하지 않는다. Malware, Trojan, Dropper, Spyware, Ransomware, Downloader, Keylogger, Virus 분류만 선택했다. PUA 형식인 `.hdu`/`.hsu` 및 Adware, Tool, Packed 분류는 포함하지 않는다.

서명의 파일 크기를 없애거나 `0`을 임의로 와일드카드로 취급하지 않는다. 이 자료의 13,764개 규칙은 모두 정확한 크기를 갖는다. 동일 해시/크기의 여러 별칭은 첫 이름 하나만 남기고 원문과 제외 기록을 보존했다. 현재 자료에서 같은 알고리즘의 허용 해시와 충돌하는 선택 규칙은 없었다. 실행 중 다른 알고리즘의 파일 허용 규칙이 일치할 수 있으므로 전체 허용 목록도 제공한다.

해시 비교 대상은 **실제 읽은 파일 바이트**다. APK 전체와 그 안의 ZIP 구성 파일을 각각 읽어 비교할 수 있지만, ClamAV의 텍스트 정규화, HTML 전처리, 난독화 해제, 실행·행위 분석, PE 섹션 검사 또는 다른 엔진 기능을 재현하지 않는다. APK 한 글자라도 바뀌면 전체 파일 해시가 달라진다. 내부의 동일한 악성 구성 파일이 그대로 남는 경우에는 구성 파일 해시 비교가 도움이 될 수 있지만 변종 탐지를 보장하지 않는다.

MD5 규칙은 알려진 파일 식별용이며 무결성 인증·공급자 인증·악성코드 부재 증명용이 아니다. 사용자에게는 서명 목록 일치 근거와 한계를 표시해야 한다. 서명에 일치하지 않았다는 사실은 안전 판정이 아니다.

## 재생성

동봉 원문의 SHA256를 확인한 뒤 같은 TSV를 다시 만들려면:

```bash
python3 normalize_clamav_android.py --out . --rebuild
```

새 CVD로 갱신하려면 공식 FreshClam 또는 CVDUpdate 등 지원되는 경로로 원본을 확보하고, 설치된 공식 sigtool을 지정한다. 전체 갱신 결과는 검토하고 앱 배포 때 해당 결과의 SHA256를 고정해야 한다.

```bash
python3 normalize_clamav_android.py \
  --cvd-dir /path/to/verified-databases \
  --out /path/to/new-subset \
  --sigtool-command-json '["sigtool"]'
```

클라이언트에는 출처가 검증되지 않은 임의 DB나 새 규칙을 자동 신뢰하는 기능을 추가하지 않는다. 자료의 갱신 실패·오래됨·일부 검사 중단은 사용자에게 명확히 표시해야 한다.

## 라이선스

ClamAV의 서명 자료는 **GPL-2.0-only**로 취급하고, CVD에 들어 있는 GPL 버전 2 원문을 `COPYING-ClamAV.txt`에 그대로 보존했다. 원문에 없는 ‘or later’ 허용을 추가하지 않았다. 배포 시 이 데이터의 라이선스·출처·선택 원문·변환 스크립트를 함께 제공한다. 원래 작성한 변환 스크립트는 MIT이며, ClamAV 프로그램 소스 코드를 Android 앱에 복사한 것은 아니다. 앱의 다른 구성 요소 라이선스와 이 데이터의 라이선스는 각각 표시한다.

## 공식 자료

- [ClamAV 해시 서명 형식](https://docs.clamav.net/manual/Signatures/HashSignatures.html)
- [파일 허용 및 서명 제외 목록](https://docs.clamav.net/manual/Signatures/AllowLists.html)
- [ClamAV 개발·CVD 문서](https://docs.clamav.net/manual/Development/libclamav.html)
- [공식 Docker 이미지 설치 문서](https://docs.clamav.net/manual/Installing/Docker.html)
- [FreshClam 다운로드 관련 안내](https://docs.clamav.net/faq/faq-freshclam)
- [Fedora의 공식 clamav-data 패키지 라이선스 표기](https://packages.fedoraproject.org/pkgs/clamav/clamav-data/index.html)

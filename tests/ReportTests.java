package io.github.refurbcheck;

import org.json.JSONArray;
import org.json.JSONObject;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Host-only tests. JSON-java is test infrastructure; it is not packaged in the Android app. */
public final class ReportTests {
    private static int scenarios, failures, assertions;
    private static final String A=digest('a'), B=digest('b');

    public static void main(String[] args) {
        scenario("identical reports remain a limited comparison",()->{
            JSONObject ref=report(pkg("com.example.alpha",1,A));
            String before=ref.toString(),result=BaselineComparator.compare(ref,copy(ref));
            contains(result,"기기 정보 차이 0건"); contains(result,"앱 추가 0개 · 누락 0개");
            contains(result,"버전/서명 차이 0건 · 서명 확인 불가 0개");
            contains(result,"공장 출고 상태는 인증하지 않습니다"); contains(result,"차이가 없더라도 APK 내용");
            same(before,ref.toString());
        });
        scenario("changed signer is reported",()->{
            String result=compare(pkg("com.example.alpha",1,A),pkg("com.example.alpha",1,B));
            contains(result,"서명 차이: com.example.alpha"); contains(result,"버전/서명 차이 1건");
            absent(result,"버전 차이:"); contains(result,"정상 서명 교체 여부도 확인");
        });
        scenario("changed version is reported",()->{
            String result=compare(pkg("com.example.alpha",1,A),pkg("com.example.alpha",2,A));
            contains(result,"버전 차이: com.example.alpha  v1 → v2"); contains(result,"버전/서명 차이 1건");
            absent(result,"서명 차이:");
        });
        scenario("version and signer changes are two observations",()->{
            String result=compare(pkg("com.example.alpha",1,A),pkg("com.example.alpha",2,B));
            contains(result,"버전/서명 차이 2건"); contains(result,"서명 차이:"); contains(result,"버전 차이:");
        });
        scenario("added and missing packages are distinguished",()->{
            JSONObject ref=report(pkg("com.example.alpha",1,A),pkg("com.example.removed",1,B));
            JSONObject now=report(pkg("com.example.alpha",1,A),pkg("com.example.added",1,B));
            String result=BaselineComparator.compare(ref,now);
            contains(result,"앱 추가 1개 · 누락 1개"); contains(result,"추가: com.example.added");
            contains(result,"목록에서 누락: com.example.removed");
        });
        scenario("multisigner order does not create a difference",()->{
            String result=compare(pkg("com.example.alpha",1,A,B),pkg("com.example.alpha",1,B,A));
            contains(result,"버전/서명 차이 0건 · 서명 확인 불가 0개"); absent(result,"서명 차이:");
        });
        scenario("hexadecimal letter case does not create a difference",()->{
            String result=compare(pkg("com.example.alpha",1,A.toUpperCase(java.util.Locale.ROOT)),pkg("com.example.alpha",1,A));
            contains(result,"버전/서명 차이 0건 · 서명 확인 불가 0개");
        });
        scenario("malformed reference signer stays unknown",()->unknownSigner(pkg("com.example.alpha",1,"not-a-digest"),false));
        scenario("malformed current signer stays unknown",()->unknownSigner(pkg("com.example.alpha",1,"not-a-digest"),true));
        scenario("empty signer array stays unknown",()->unknownSigner(pkg("com.example.alpha",1),false));
        scenario("empty signer string stays unknown",()->unknownSigner(pkg("com.example.alpha",1,""),false));
        scenario("short signer digest stays unknown",()->unknownSigner(pkg("com.example.alpha",1,A.substring(1)),false));
        scenario("nonhex signer digest stays unknown",()->unknownSigner(pkg("com.example.alpha",1,digest('g')),false));
        scenario("missing signer field stays unknown",()->{
            JSONObject p=pkg("com.example.alpha",1,A); p.remove("signingSha256"); unknownSigner(p,false);
        });
        scenario("null signer element stays unknown",()->{
            JSONObject p=pkg("com.example.alpha",1,A); p.put("signingSha256",new JSONArray().put(JSONObject.NULL)); unknownSigner(p,false);
        });
        scenario("numeric signer element is malformed, not a SHA256 string",()->{
            JSONObject p=pkg("com.example.alpha",1,A);
            p.put("signingSha256",new JSONArray().put(new BigInteger(digest('1')))); unknownSigner(p,false);
        });
        scenario("explicitly unreadable signing metadata stays unknown",()->{
            JSONObject p=pkg("com.example.alpha",1,A); p.put("signingReadable",false); unknownSigner(p,false);
        });
        scenario("incomplete reference inventory receives a caution",()->{
            JSONObject ref=report(pkg("com.example.alpha",1,A)); ref.put("inventoryComplete",false);
            contains(BaselineComparator.compare(ref,report(pkg("com.example.alpha",1,A))),"앱 목록 수집이 불완전합니다");
        });
        scenario("incomplete current inventory receives a caution",()->{
            JSONObject now=report(pkg("com.example.alpha",1,A)); now.put("inventoryComplete",false);
            contains(BaselineComparator.compare(report(pkg("com.example.alpha",1,A)),now),"수집된 목록 안에서만 비교합니다");
        });
        scenario("different model stops package comparison",()->{
            JSONObject now=report(pkg("com.example.alpha",1,B)); device(now).put("model","Different Model");
            String result=BaselineComparator.compare(report(pkg("com.example.alpha",1,A)),now);
            contains(result,"서로 다른 모델/제품"); contains(result,"비교를 중단했습니다"); absent(result,"버전/서명 차이");
        });
        scenario("missing model stops comparison",()->{
            JSONObject ref=report(); device(ref).remove("model"); missingModel(ref);
        });
        scenario("unknown model stops comparison",()->{
            JSONObject ref=report(); device(ref).put("model"," UnKnOwN "); missingModel(ref);
        });
        scenario("JSON null model stops comparison",()->{
            JSONObject ref=report(); device(ref).put("model",JSONObject.NULL); missingModel(ref);
        });
        scenario("literal null model stops comparison",()->{
            JSONObject ref=report(); device(ref).put("model","null"); missingModel(ref);
        });
        scenario("blank current model stops comparison",()->{
            JSONObject now=report(); device(now).put("model","   ");
            contains(BaselineComparator.compare(report(),now),"기기 식별 정보가 부족하여 비교를 중단했습니다");
        });
        scenario("invalid report schema is rejected",()->{
            JSONObject ref=report(); ref.put("schema","some-other-report");
            rejects(()->BaselineComparator.compare(ref,report())); rejects(()->BaselineComparator.compare(new JSONObject(),report()));
        });
        scenario("duplicate reference package names are rejected",()->{
            JSONObject ref=report(pkg("com.example.alpha",1,A),pkg("com.example.alpha",1,B));
            rejects(()->BaselineComparator.compare(ref,report()));
        });
        scenario("duplicate current package names are rejected",()->{
            JSONObject now=report(pkg("com.example.alpha",1,A),pkg("com.example.alpha",1,B));
            rejects(()->BaselineComparator.compare(report(),now));
        });
        scenario("nonobject package rows are rejected",()->{
            JSONObject ref=report(); ref.put("inventory",new JSONArray().put("not-a-package"));
            rejects(()->BaselineComparator.compare(ref,report()));
        });
        scenario("application itself is excluded from reference changes",()->{
            String result=BaselineComparator.compare(report(pkg("io.github.refurbcheck",1,A)),report(pkg("io.github.refurbcheck",2,B)));
            contains(result,"앱 추가 0개 · 누락 0개 · 버전/서명 차이 0건");
        });
        scenario("build metadata differences are visible",()->{
            JSONObject now=report(); device(now).put("securityPatch","2026-12-01");
            String result=BaselineComparator.compare(report(),now);
            contains(result,"securityPatch:"); contains(result,"기기 정보 차이 1건");
        });
        scenario("empty reports never receive a clean observation verdict",()->same("검사 결과 확인 불가",new ScanReport().verdict()));
        scenario("unknown checks plus coverage text remain unknown",()->{
            ScanReport r=new ScanReport(); finding(r,"boot.verified",Finding.Status.UNKNOWN);
            finding(r,"coverage.self_report",Finding.Status.INFO); finding(r,"coverage.hardware",Finding.Status.UNKNOWN);
            same("검사 결과 확인 불가",r.verdict());
        });
        scenario("external-attestation explanatory text is not an observation",()->{
            ScanReport r=new ScanReport(); finding(r,"attestation_external",Finding.Status.INFO);
            same("검사 결과 확인 불가",r.verdict());
        });
        scenario("a substantive INFO is a bounded observation",()->{
            ScanReport r=new ScanReport(); finding(r,"apps.inventory",Finding.Status.INFO);
            finding(r,"coverage.hardware",Finding.Status.UNKNOWN);
            same("미검증 항목이 남아 있습니다",r.verdict());
        });
        scenario("a PASS remains bounded by unknown scope",()->{
            ScanReport r=new ScanReport(); finding(r,"boot.verified",Finding.Status.PASS);
            finding(r,"coverage.malware",Finding.Status.UNKNOWN);
            same("미검증 항목이 남아 있습니다",r.verdict()); flagsNeverPromise(r);
        });
        scenario("WARN takes precedence over observed and unknown",()->{
            ScanReport r=new ScanReport(); finding(r,"system.selinux",Finding.Status.PASS);
            finding(r,"coverage.malware",Finding.Status.UNKNOWN); finding(r,"root.packages",Finding.Status.WARN);
            same("확인이 필요한 항목 발견",r.verdict()); flagsNeverPromise(r);
        });
        scenario("ALERT takes precedence over WARN",()->{
            ScanReport r=new ScanReport(); finding(r,"root.packages",Finding.Status.WARN);
            finding(r,"root.paths",Finding.Status.ALERT); finding(r,"boot.verified",Finding.Status.PASS);
            same("주의가 큰 징후 발견",r.verdict()); flagsNeverPromise(r);
        });
        scenario("report serialization preserves counts and explicit limits",()->{
            ScanReport r=new ScanReport(); finding(r,"one",Finding.Status.INFO); finding(r,"two",Finding.Status.INFO);
            finding(r,"three",Finding.Status.UNKNOWN); r.completedAt=r.startedAt+100;
            same(2,r.count(Finding.Status.INFO)); same(1,r.count(Finding.Status.UNKNOWN)); same(0,r.count(Finding.Status.ALERT));
            JSONObject json=r.toJson(); same("refurbcheck-report-v2",json.getString("schema"));
            same("1.3.0",json.getString("appVersion")); same(1,json.getInt("unverifiedFindingCount"));
            check(!json.getBoolean("allRequiredDomainsVerified"),"Must not claim complete domain verification");
            same(3,json.getJSONArray("findings").length()); same(r.verdict(),json.getString("verdict"));
            check(json.getLong("completedAt")>=json.getLong("startedAt"),"Completion precedes start");
            flagsNeverPromise(r);
        });
        testFileComparisons(); testJsonInputs();
        System.out.println("ReportTests: "+(scenarios-failures)+"/"+scenarios+" scenarios passed; "+assertions+" assertions checked");
        if(failures>0) throw new AssertionError(failures+" scenario(s) failed");
    }

    private static void testFileComparisons() {
        scenario("v1 and v2 metadata comparisons remain compatible",()->{
            JSONObject old=report(pkg("com.example.alpha",1,A));
            JSONObject now=reportV2(apkPkg("com.example.alpha",2,B));
            String result=BaselineComparator.compare(old,now);
            contains(result,"버전 차이: com.example.alpha"); contains(result,"v1 형식이 포함되어 APK 파일 내용은 비교하지 않습니다");
            contains(result,"APK 내용 확인 불가: com.example.alpha"); contains(result,"내용 차이 0개 앱");
        });
        scenario("v1 cannot supply file evidence by inserting v2 fields",()->{
            JSONObject old=report(apkPkg("com.example.alpha",1,A));
            JSONObject now=reportV2(apkPkg("com.example.alpha",1,B));
            contains(BaselineComparator.compare(old,now),"내용 차이 0개 앱");
        });
        scenario("identical complete v2 hashes are a read-only bounded comparison",()->{
            JSONObject ref=reportV2(apkPkg("com.example.alpha",1,A,file("split:config.en",B)));
            JSONObject now=copy(ref); String before=ref.toString(),after=now.toString();
            String result=BaselineComparator.compare(ref,now);
            contains(result,"보고된 해시 동일 1개 앱 · 내용 차이 0개 앱 · 구성 차이 0개 앱 · 확인 불가 0개 앱");
            contains(result,"읽기 전용"); contains(result,"가져온 보고서로 앱 삭제나 설정 변경을 실행하지 않습니다");
            contains(result,"제조사 순정 기준으로 인증하지 않습니다"); same(before,ref.toString()); same(after,now.toString());
        });
        scenario("base APK bytes can differ while package signer and version stay the same",()->{
            String result=compareV2(apkPkg("com.example.alpha",1,A),apkPkg("com.example.alpha",1,B));
            contains(result,"버전/서명 차이 0건"); contains(result,"동일 버전·펌웨어 지문의 APK 내용 차이: com.example.alpha");
            contains(result,"원인 미확인 내용 차이 1개 앱"); contains(result,"base: "+A+" → "+B);
        });
        scenario("changed split content is compared independently of base",()->{
            String result=compareV2(apkPkg("com.example.alpha",1,A,file("split:config.en",A)),
                    apkPkg("com.example.alpha",1,A,file("split:config.en",B)));
            contains(result,"내용 차이 1개 앱"); contains(result,"split:config.en: "+A+" → "+B);
            absent(result,"  base:");
        });
        scenario("file array order never becomes a content change",()->{
            JSONObject old=apkPkg("com.example.alpha",1,A,file("split:config.en",B),file("split:feature",A));
            JSONObject now=copy(old); JSONArray files=now.getJSONArray("apkFiles");
            now.put("apkFiles",new JSONArray().put(files.get(2)).put(files.get(0)).put(files.get(1)));
            contains(compareV2(old,now),"보고된 해시 동일 1개 앱 · 내용 차이 0개 앱");
        });
        scenario("file hash letter case is normalized",()->{
            contains(compareV2(apkPkg("com.example.alpha",1,A.toUpperCase(java.util.Locale.ROOT)),apkPkg("com.example.alpha",1,A)),"보고된 해시 동일 1개 앱");
        });
        scenario("normal version update does not become unexplained content change",()->{
            String result=compareV2(apkPkg("com.example.alpha",1,A),apkPkg("com.example.alpha",2,B));
            contains(result,"APK 내용 차이 — 비교 조건 다름/미확인"); contains(result,"정상 업데이트·배포 경로·기기 구성 변화");
            contains(result,"원인 미확인 내용 차이 0개 앱"); absent(result,"동일 버전·펌웨어 지문의 APK 내용 차이:");
        });
        scenario("changed firmware fingerprint prevents unexplained content classification",()->{
            JSONObject old=reportV2(apkPkg("com.example.alpha",1,A)),now=reportV2(apkPkg("com.example.alpha",1,B));
            device(now).put("fingerprint","Example/device_a/new-build:user/release-keys");
            String result=BaselineComparator.compare(old,now);
            contains(result,"내용 차이 1개 앱"); contains(result,"원인 미확인 내용 차이 0개 앱");
        });
        scenario("missing fingerprints on both sides cannot count as equality",()->{
            JSONObject old=reportV2(apkPkg("com.example.alpha",1,A)),now=reportV2(apkPkg("com.example.alpha",1,B));
            device(old).remove("fingerprint"); device(now).remove("fingerprint");
            String result=BaselineComparator.compare(old,now);
            contains(result,"fingerprint: 자료 부족"); contains(result,"원인 미확인 내용 차이 0개 앱");
        });
        scenario("unknown fingerprint strings cannot establish context",()->{
            JSONObject old=reportV2(apkPkg("com.example.alpha",1,A)),now=reportV2(apkPkg("com.example.alpha",1,B));
            device(old).put("fingerprint","unknown"); device(now).put("fingerprint","unknown");
            contains(BaselineComparator.compare(old,now),"원인 미확인 내용 차이 0개 앱");
        });
        scenario("missing versions on both sides cannot establish same-version context",()->{
            JSONObject old=apkPkg("com.example.alpha",1,A),now=apkPkg("com.example.alpha",1,B);
            old.remove("versionCode"); now.remove("versionCode");
            String result=compareV2(old,now); contains(result,"버전 확인 불가 1개"); contains(result,"원인 미확인 내용 차이 0개 앱");
        });
        scenario("string and fractional version codes are not accepted by coercion",()->{
            for(Object malformed:new Object[]{"1",1.0,-1L,new BigInteger("9223372036854775808")}) {
                JSONObject old=apkPkg("com.example.alpha",1,A),now=apkPkg("com.example.alpha",1,B);
                old.put("versionCode",malformed); now.put("versionCode",malformed);
                String result=compareV2(old,now); contains(result,"버전 확인 불가 1개"); contains(result,"원인 미확인 내용 차이 0개 앱");
            }
        });
        scenario("64-bit version code does not truncate",()->{
            String result=compareV2(apkPkg("com.example.alpha",0x100000001L,A),apkPkg("com.example.alpha",1,B));
            contains(result,"버전 차이:"); contains(result,"원인 미확인 내용 차이 0개 앱");
        });
        scenario("different split distribution receives configuration caution",()->{
            String result=compareV2(apkPkg("com.example.alpha",1,A,file("split:config.en",A)),
                    apkPkg("com.example.alpha",1,A,file("split:config.ko",A)));
            contains(result,"APK 구성 차이: com.example.alpha"); contains(result,"언어·기기 구성·배포 split 변화");
            contains(result,"보고된 해시 동일 0개 앱 · 내용 차이 0개 앱 · 구성 차이 1개 앱");
            contains(result,"원인 미확인 내용 차이 0개 앱");
        });
        scenario("common base content difference remains visible when split distribution changes",()->{
            String result=compareV2(apkPkg("com.example.alpha",1,A,file("split:config.en",A)),
                    apkPkg("com.example.alpha",1,B,file("split:config.ko",A)));
            contains(result,"내용 차이 1개 앱 · 구성 차이 1개 앱"); contains(result,"base: "+A+" → "+B);
            contains(result,"원인 미확인 내용 차이 0개 앱");
        });
        scenario("partial package scan cannot compare an apparently present base digest",()->{
            JSONObject bad=apkPkg("com.example.alpha",1,B); bad.put("apkInspectionComplete",false); unknownApk(bad);
        });
        scenario("missing or string completion flags cannot count as complete",()->{
            JSONObject bad=apkPkg("com.example.alpha",1,B); bad.remove("apkInspectionComplete"); unknownApk(bad);
            bad.put("apkInspectionComplete","true"); unknownApk(bad);
        });
        scenario("changed package invalidates otherwise complete hash records",()->{
            JSONObject bad=apkPkg("com.example.alpha",1,B); bad.put("apkChangedDuringScan",true); unknownApk(bad);
        });
        scenario("package collection error conflicts with completed evidence",()->{
            JSONObject bad=apkPkg("com.example.alpha",1,B); bad.put("apkInspectionError","PACKAGE_RECHECK_FAILED"); unknownApk(bad);
        });
        scenario("unreadable pending truncated and cancelled hashes stay unknown",()->{
            for(String status:new String[]{"UNREADABLE","HASHED_PENDING_STABILITY","UNKNOWN_STABILITY","CHANGED","CANCELLED","TIME_LIMIT","TOTAL_BYTE_LIMIT"}) {
                JSONObject bad=apkPkg("com.example.alpha",1,B); firstFile(bad).put("hashStatus",status); unknownApk(bad);
            }
        });
        scenario("observed partial digest is never promoted to final SHA256",()->{
            JSONObject bad=apkPkg("com.example.alpha",1,B); firstFile(bad).remove("sha256"); firstFile(bad).put("observedSha256",B); unknownApk(bad);
        });
        scenario("file stability requires a real true boolean",()->{
            for(Object stable:new Object[]{false,"true",JSONObject.NULL}) {
                JSONObject bad=apkPkg("com.example.alpha",1,B); firstFile(bad).put("fileStable",stable); unknownApk(bad);
            }
        });
        scenario("malformed file digests never establish byte differences",()->{
            for(Object hash:new Object[]{"",B.substring(1),digest('g'),new BigInteger(digest('1')),JSONObject.NULL}) {
                JSONObject bad=apkPkg("com.example.alpha",1,B); firstFile(bad).put("sha256",hash); unknownApk(bad);
            }
        });
        scenario("missing or noninteger file size is incomplete evidence",()->{
            for(Object size:new Object[]{-1,"1000",1000.0,JSONObject.NULL}) {
                JSONObject bad=apkPkg("com.example.alpha",1,B); firstFile(bad).put("size",size); unknownApk(bad);
            }
        });
        scenario("same hash with contradictory size is unknown",()->{
            JSONObject bad=apkPkg("com.example.alpha",1,A); firstFile(bad).put("size",1001); unknownApk(bad);
        });
        scenario("duplicate base and split identities cannot be compared",()->{
            JSONObject bad=apkPkg("com.example.alpha",1,B); bad.getJSONArray("apkFiles").put(file("base",B)); unknownApk(bad);
            bad=apkPkg("com.example.alpha",1,B,file("split:config.en",A),file("split:config.en",B)); unknownApk(bad);
        });
        scenario("malformed file identity and mismatched split name stay unknown",()->{
            JSONObject bad=apkPkg("com.example.alpha",1,B); firstFile(bad).put("fileId","other"); unknownApk(bad);
            bad=apkPkg("com.example.alpha",1,B,file("split:config.en",B)); bad.getJSONArray("apkFiles").getJSONObject(1).put("splitName","config.ko"); unknownApk(bad);
            bad=apkPkg("com.example.alpha",1,B); firstFile(bad).put("kind","unknown"); unknownApk(bad);
        });
        scenario("missing base file cannot appear as a complete split-only package",()->{
            JSONObject bad=apkPkg("com.example.alpha",1,B); bad.put("apkFiles",new JSONArray().put(file("split:config.en",B))); unknownApk(bad);
        });
        scenario("missing empty nonarray and malformed file rows stay unknown",()->{
            JSONObject bad=apkPkg("com.example.alpha",1,B); bad.remove("apkFiles"); unknownApk(bad);
            bad.put("apkFiles",new JSONArray()); unknownApk(bad);
            bad.put("apkFiles",new JSONObject()); unknownApk(bad);
            bad.put("apkFiles",new JSONArray().put("base")); unknownApk(bad);
        });
        scenario("complete common packages remain bounded when enumeration is incomplete",()->{
            JSONObject old=reportV2(apkPkg("com.example.alpha",1,A)),now=reportV2(apkPkg("com.example.alpha",1,B));
            now.put("inventoryComplete",false); String result=BaselineComparator.compare(old,now);
            contains(result,"수집된 목록 안에서만 비교합니다"); contains(result,"원인 미확인 내용 차이 1개 앱");
        });
        scenario("self APK is excluded from content comparison too",()->{
            String result=compareV2(apkPkg("io.github.refurbcheck",1,A),apkPkg("io.github.refurbcheck",2,B));
            contains(result,"내용 차이 0개 앱"); contains(result,"확인 불가 0개 앱"); absent(result,"동일 버전·펌웨어 지문의 APK 내용 차이:");
        });
        scenario("missing inventory is rejected rather than treated as empty",()->{
            JSONObject bad=report(); bad.remove("inventory"); rejects(()->BaselineComparator.compare(bad,report()));
            rejects(()->BaselineComparator.compare(report(),bad));
        });
        scenario("wrong inventory type is rejected",()->{
            JSONObject bad=report(); bad.put("inventory",new JSONObject()); rejects(()->BaselineComparator.compare(bad,report()));
        });
        scenario("current schema and null reports are validated",()->{
            JSONObject bad=report(); bad.put("schema","unsupported"); rejects(()->BaselineComparator.compare(report(),bad));
            rejects(()->BaselineComparator.compare(null,report())); rejects(()->BaselineComparator.compare(report(),null));
        });
        scenario("duplicate signers are not accepted as a readable signer set",()->{
            unknownSigner(pkg("com.example.alpha",1,A,A),false);
        });
        scenario("numeric device identity is not accepted by coercion",()->{
            JSONObject old=report(),now=report(); device(old).put("model",123); device(now).put("model",123);
            contains(BaselineComparator.compare(old,now),"기기 식별 정보가 부족하여 비교를 중단했습니다");
        });
    }

    private static void testJsonInputs() {
        scenario("strict parser accepts an actual v2 report with Unicode strings",()->{
            JSONObject value=reportV2(apkPkg("com.example.alpha",1,A));
            value.put("notes","한글, \"인용\", 역슬래시 \\, 괄호 [{]}와 이모지 😀\n새 줄");
            JSONObject parsed=parse(value.toString()); same(value.toString(),parsed.toString());
            same("refurbcheck-report-v2",parsed.getString("schema"));
        });
        scenario("strict parser accepts standard numeric and boolean JSON",()->{
            JSONObject parsed=parse("{\"numbers\":[0,-0,12,-12,0.25,1e2,-1E-3],\"yes\":true,\"no\":false,\"nothing\":null}");
            same(7,parsed.getJSONArray("numbers").length()); check(parsed.getBoolean("yes"),"true lost");
            check(!parsed.getBoolean("no"),"false lost"); check(parsed.isNull("nothing"),"null lost");
        });
        scenario("valid whitespace around a report is accepted",()->same(0,parse(" \r\n\t{} \r\n\t").length()));
        scenario("deep brackets inside strings do not count as structural depth",()->{
            String value=repeat("[{",300)+"\\\""+repeat("}]",300);
            JSONObject parsed=parse(new JSONObject().put("text",value).toString()); same(value,parsed.getString("text"));
        });
        scenario("depth boundary is bounded before org.json parsing",()->{
            String atLimit="{\"v\":"+repeat("[",ReportJson.MAX_DEPTH-1)+"0"+repeat("]",ReportJson.MAX_DEPTH-1)+"}";
            check(parse(atLimit).has("v"),"depth boundary rejected");
            rejectsJson(utf8("{\"v\":"+repeat("[",ReportJson.MAX_DEPTH)+"0"+repeat("]",ReportJson.MAX_DEPTH)+"}"));
            rejectsJson(utf8("{\"v\":"+repeat("[",10000)+"0"+repeat("]",10000)+"}"));
        });
        scenario("every truncation of a representative JSON object is rejected",()->{
            byte[] data=utf8("{\"schema\":\"refurbcheck-report-v2\",\"label\":\"한글\",\"inventory\":[{\"packageName\":\"a.b\",\"x\":[1,true,null]}]}");
            for(int cut=0;cut<data.length;cut++) rejectsJson(Arrays.copyOf(data,cut));
        });
        scenario("empty null and oversized imports are rejected",()->{
            rejectsJson(null); rejectsJson(new byte[0]); rejectsJson(new byte[ReportJson.MAX_BYTES+1]);
        });
        scenario("malformed UTF8 is rejected rather than replaced",()->{
            for(byte[] bad:new byte[][]{{(byte)0xc3,0x28},{(byte)0xc0,(byte)0xaf},{(byte)0xed,(byte)0xa0,(byte)0x80},
                    {(byte)0xf4,(byte)0x90,(byte)0x80,(byte)0x80},{(byte)0x80}}) {
                byte[] prefix=utf8("{\"v\":\""),suffix=utf8("\"}"); byte[] data=new byte[prefix.length+bad.length+suffix.length];
                System.arraycopy(prefix,0,data,0,prefix.length); System.arraycopy(bad,0,data,prefix.length,bad.length);
                System.arraycopy(suffix,0,data,prefix.length+bad.length,suffix.length); rejectsJson(data);
            }
        });
        scenario("trailing objects scalars garbage and NUL are rejected",()->{
            for(String bad:new String[]{"{}{}","{} true","{}garbage","{}\u0000","{} // comment"}) rejectsJson(utf8(bad));
        });
        scenario("top-level arrays and scalar values are not reports",()->{
            for(String bad:new String[]{"[]","null","true","1","\"text\""}) rejectsJson(utf8(bad));
        });
        scenario("duplicate object names including escaped equivalents are rejected",()->{
            rejectsJson(utf8("{\"schema\":\"v1\",\"schema\":\"v2\"}"));
            rejectsJson(utf8("{\"a\":1,\"\\u0061\":2}"));
            rejectsJson(utf8("{\"outer\":{\"x\":1,\"x\":2}}"));
            same(2,parse("{\"a\":{\"x\":1},\"b\":{\"x\":2}}").length());
        });
        scenario("lenient org.json extensions are rejected consistently",()->{
            for(String bad:new String[]{"{'x':1}","{x:1}","{\"x\"=1}","{\"x\":1;\"y\":2}","{\"x\":1,}",
                    "{\"x\":[1,]}","{\"x\":[1,,2]}","{\"x\":/*comment*/1}","{\"x\":NaN}","{\"x\":Infinity}",
                    "{\"x\":+1}","{\"x\":01}","{\"x\":1.}","{\"x\":.1}","{\"x\":1e}","{\"x\":-}","{\"x\":TRUE}"})
                rejectsJson(utf8(bad));
        });
        scenario("malformed escapes raw controls and Unicode surrogates are rejected",()->{
            for(String bad:new String[]{"{\"x\":\"\\q\"}","{\"x\":\"\\u12xz\"}","{\"x\":\"\\uD800\"}",
                    "{\"x\":\"\\uDC00\"}","{\"x\":\"\\uD800A\"}","{\"x\":\"raw\nline\"}"}) rejectsJson(utf8(bad));
            same("😀",parse("{\"x\":\"\\uD83D\\uDE00\"}").getString("x"));
        });
        scenario("structural mismatches are rejected before recursive parsing",()->{
            for(String bad:new String[]{"{]","{\"a\":[}","{\"a\":1}}","{\"a\":1 \"b\":2}"}) rejectsJson(utf8(bad));
        });
        scenario("large single numbers and excessive value counts are bounded",()->{
            rejectsJson(utf8("{\"n\":"+repeat("1",129)+"}"));
            rejectsJson(utf8("{\"items\":["+repeat("0,",200000)+"0]}"));
        });
    }

    private static JSONObject reportV2(JSONObject... packages) { return report(packages).put("schema","refurbcheck-report-v2"); }
    private static JSONObject apkPkg(String name,long version,String baseHash,JSONObject... splits) {
        JSONArray files=new JSONArray().put(file("base",baseHash)); for(JSONObject split:splits) files.put(split);
        return pkg(name,version,A).put("apkInspectionComplete",true).put("apkChangedDuringScan",false).put("apkFiles",files);
    }
    private static JSONObject file(String id,String hash) {
        boolean base="base".equals(id);
        return new JSONObject().put("fileId",id).put("kind",base?"base":"split").put("splitName",base?"":id.substring(6))
                .put("hashStatus","HASHED").put("fileStable",true).put("sha256",hash).put("size",1000);
    }
    private static JSONObject firstFile(JSONObject pkg) { return pkg.getJSONArray("apkFiles").getJSONObject(0); }
    private static String compareV2(JSONObject old,JSONObject now) { return BaselineComparator.compare(reportV2(old),reportV2(now)); }
    private static void unknownApk(JSONObject bad) {
        String result=compareV2(apkPkg("com.example.alpha",1,A),bad);
        contains(result,"APK 내용 확인 불가: com.example.alpha"); contains(result,"내용 차이 0개 앱");
        contains(result,"확인 불가 1개 앱"); contains(result,"원인 미확인 내용 차이 0개 앱");
    }
    private static byte[] utf8(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static JSONObject parse(String text) {
        try { return ReportJson.parse(utf8(text)); } catch(IOException exception) { throw new AssertionError("Valid JSON rejected: "+exception.getMessage(),exception); }
    }
    private static void rejectsJson(byte[] data) {
        assertions++;
        try { ReportJson.parse(data); } catch(IOException expected) { return; }
        throw new AssertionError("Malformed or oversized JSON was accepted");
    }
    private static String repeat(String text,int count) { StringBuilder out=new StringBuilder(text.length()*count); for(int i=0;i<count;i++) out.append(text); return out.toString(); }

    private static JSONObject report(JSONObject... packages) {
        JSONObject d=new JSONObject().put("manufacturer","Example").put("brand","Example").put("model","Model A")
                .put("device","device_a").put("product","product_a").put("fingerprint","Example/device_a/build:user/release-keys")
                .put("securityPatch","2026-11-01").put("androidRelease","16").put("apiLevel",36)
                .put("buildType","user").put("buildTags","release-keys");
        JSONArray apps=new JSONArray(); for(JSONObject p:packages) apps.put(p);
        return new JSONObject().put("schema","refurbcheck-report-v1").put("evidence",new JSONObject().put("device",d))
                .put("inventory",apps).put("inventoryComplete",true);
    }
    private static JSONObject pkg(String name,long version,String... signers) {
        return new JSONObject().put("packageName",name).put("label",name).put("system",false)
                .put("versionCode",version).put("versionName","v"+version).put("signingReadable",true)
                .put("signingSha256",new JSONArray(Arrays.asList(signers)));
    }
    private static JSONObject device(JSONObject report) { return report.getJSONObject("evidence").getJSONObject("device"); }
    private static JSONObject copy(JSONObject object) { return new JSONObject(object.toString()); }
    private static String compare(JSONObject before,JSONObject after) { return BaselineComparator.compare(report(before),report(after)); }
    private static String digest(char c) { char[] result=new char[64]; Arrays.fill(result,c); return new String(result); }
    private static void unknownSigner(JSONObject bad,boolean current) {
        JSONObject good=pkg("com.example.alpha",1,A); String result=current?compare(good,bad):compare(bad,good);
        contains(result,"서명 확인 불가 1개"); contains(result,"서명 확인 불가: com.example.alpha"); absent(result,"서명 차이:");
    }
    private static void missingModel(JSONObject reference) {
        String result=BaselineComparator.compare(reference,report());
        contains(result,"기기 식별 정보가 부족하여 비교를 중단했습니다"); absent(result,"버전/서명 차이");
    }
    private static void finding(ScanReport report,String id,Finding.Status status) {
        report.add(new Finding(id,"test","test",status,"observed","inspect"));
    }
    private static void flagsNeverPromise(ScanReport report) {
        JSONObject json=report.toJson();
        check(!json.getBoolean("factoryOriginalVerified"),"Must not promise factory-original state");
        check(!json.getBoolean("malwareAbsenceVerified"),"Must not promise absence of malware");
        check(!json.getBoolean("physicalHardwareVerified"),"Must not promise physical integrity");
    }
    private static void scenario(String name,Runnable test) {
        scenarios++;
        try { test.run(); System.out.println("PASS "+name); }
        catch(AssertionError|RuntimeException e) { failures++; System.err.println("FAIL "+name+": "+e.getMessage()); }
    }
    private static void check(boolean condition,String message) { assertions++; if(!condition) throw new AssertionError(message); }
    private static void same(Object expected,Object actual) { check(expected.equals(actual),"Expected "+expected+", got "+actual); }
    private static void contains(String text,String expected) { check(text.contains(expected),"Missing: "+expected+"\nResult: "+text); }
    private static void absent(String text,String unexpected) { check(!text.contains(unexpected),"Unexpected: "+unexpected+"\nResult: "+text); }
    private static void rejects(Runnable action) {
        assertions++;
        try { action.run(); } catch(IllegalArgumentException expected) { return; }
        throw new AssertionError("Expected IllegalArgumentException");
    }
}

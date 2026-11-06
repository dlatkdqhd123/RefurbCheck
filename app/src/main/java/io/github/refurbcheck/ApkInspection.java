package io.github.refurbcheck;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import com.android.apksig.ApkVerifier;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/** Reads only base/split paths returned by PackageManager for the current profile. */
public final class ApkInspection {
    private static final String CATEGORY="앱 파일 무결성";
    private static final int MAX_FILES_PER_PACKAGE=2048;
    private ApkInspection() { }

    public static void inspect(Context context,ScanReport report,ScanEngine.Progress progress,
            AtomicBoolean cancelled) throws Exception {
        final long startElapsed=SystemClock.elapsedRealtime(), startWall=System.currentTimeMillis();
        final ApkEvidence.Budget budget=new ApkEvidence.Budget(cancelled);
        final PackageManager pm=context.getPackageManager();
        final MalwareInspection malware=new MalwareInspection(context,budget,report);
        // v1.3 uses a single authenticated active catalog for all sources,
        // including MVT. A retired IOC must not survive in a legacy side list.
        ApkEvidence.IocIndex database=null;
        report.evidence.put("iocDatabase",new JSONObject().put("loaded",false)
                .put("state","SUPERSEDED_BY_ACTIVE_MALWARE_CATALOG")
                .put("scope","MVT references are included in malwareDatabase; legacy bundled side list is not executed."));
        String stopped=""; int metadataFailures=0;
        List<Integer> order=new ArrayList<>();
        for(int i=0;i<report.inventory.length();i++) order.add(i);
        // Known malicious user apps should not be left behind a large system APK when the budget expires.
        Collections.sort(order,(left,right)-> {
            JSONObject a=report.inventory.optJSONObject(left),b=report.inventory.optJSONObject(right);
            boolean aSystem=a==null||a.optBoolean("system",true),bSystem=b==null||b.optBoolean("system",true);
            int type=Boolean.compare(aSystem,bSystem);
            return type!=0?type:(a==null?"":a.optString("packageName")).compareTo(b==null?"":b.optString("packageName"));
        });
        for(int i=0;i<order.size();i++) {
            JSONObject row=report.inventory.optJSONObject(order.get(i));
            if(row==null) { metadataFailures++; continue; }
            row.put("apkFiles",new JSONArray()).put("apkInspectionComplete",false)
                    .put("confirmedIoc",false).put("iocMatches",new JSONArray())
                    .put("remediationEligible",false).put("remediationPackageName","")
                    .put("malwareInspectionComplete",false).put("malwareReferenceMatchCount",0)
                    .put("malwareReferenceMatches",new JSONArray()).put("apkChangedDuringScan",false)
                    .put("apkFileSetComplete",false);
            String pkg=row.optString("packageName","");
            if(pkg.isEmpty()) { row.put("apkInspectionError","MISSING_PACKAGE_NAME"); metadataFailures++; continue; }
            try { budget.check(); }
            catch(ApkEvidence.LimitException e) { stopped=e.reason; row.put("apkInspectionError",e.reason); metadataFailures++; continue; }
            if(!stopped.isEmpty()) { row.put("apkInspectionError",stopped); metadataFailures++; continue; }
            update(progress,"APK·악성 파일 검사 "+(i+1)+" / "+report.inventory.length()+" · "+pkg);
            Snapshot before;
            try { before=snapshot(pm,pkg); }
            catch(Exception e) { row.put("apkInspectionError",error(e)); metadataFailures++; continue; }
            row.put("versionKnown",before.version>=0);
            JSONArray files=row.getJSONArray("apkFiles");
            List<Target> targets;
            try { targets=targets(before.info); }
            catch(Exception e) { row.put("apkInspectionError",error(e)); metadataFailures++; continue; }
            row.put("apkFileSetComplete",true);
            List<String> expectedSigners=strings(row.optJSONArray("signingSha256"));
            if(!row.optBoolean("signingReadable",false)) expectedSigners=Collections.emptyList();
            for(Target target:targets) {
                JSONObject file=new JSONObject().put("fileId",target.id).put("kind",target.base?"base":"split")
                        .put("splitName",target.splitName).put("fileName",new File(target.path).getName())
                        .put("sourcePath",target.path)
                        .put("source","PackageManager.getApplicationInfo")
                        .put("hashStatus","NOT_SCANNED").put("signatureStatus","NOT_SCANNED")
                        .put("size",-1).put("signerSha256",new JSONArray()).put("matchedIoc",new JSONArray())
                        .put("matchConfirmed",false).put("fileStable",false).put("errors",new JSONArray());
                files.put(file);
                if(!stopped.isEmpty()) {
                    file.put("hashStatus",stopped).put("signatureStatus","UNKNOWN_LIMIT");
                    continue;
                }
                try {
                    budget.check();
                    inspectFile(target,file,budget,expectedSigners,database,malware);
                    JSONArray errors=file.getJSONArray("errors");
                    for(int e=0;e<errors.length();e++) {
                        String reason=errors.optString(e);
                        if("TIME_LIMIT".equals(reason)||"CANCELLED".equals(reason)||"TOTAL_BYTE_LIMIT".equals(reason)) stopped=reason;
                    }
                } catch(ApkEvidence.LimitException e) {
                    stopped=e.reason; file.put("hashStatus",e.reason).put("signatureStatus","UNKNOWN_LIMIT");
                    file.getJSONArray("errors").put(e.reason);
                } catch(OutOfMemoryError e) {
                    stopped="MEMORY_LIMIT"; file.put("signatureStatus","UNKNOWN_RESOURCE");
                    file.getJSONArray("errors").put("MEMORY_LIMIT");
                } catch(Exception e) {
                    if("NOT_SCANNED".equals(file.optString("hashStatus"))) file.put("hashStatus","UNREADABLE");
                    if(!file.optBoolean("fileStable",false)) {
                        if("HASHED_PENDING_STABILITY".equals(file.optString("hashStatus"))) file.put("hashStatus","UNKNOWN_STABILITY");
                        file.put("signatureStatus","UNKNOWN_READ");
                    }
                    file.getJSONArray("errors").put(error(e));
                }
                if(!file.optBoolean("fileStable",false)) MalwareInspection.invalidate(file);
            }
            boolean changed=before.version!=row.optLong("versionCode",-1L)
                    ||before.updated!=row.optLong("lastUpdateTime",-1L);
            try { changed|=!before.same(snapshot(pm,pkg)); }
            catch(Exception e) { changed=true; row.put("apkInspectionError","PACKAGE_RECHECK_FAILED: "+error(e)); }
            if(changed) {
                row.put("apkChangedDuringScan",true).put("apkInspectionError","PACKAGE_CHANGED_DURING_SCAN");
                for(int j=0;j<files.length();j++) invalidate(files.getJSONObject(j));
                report.inventoryComplete=false;
            }
            boolean allHashed=files.length()>0;
            JSONArray packageMatches=new JSONArray();
            for(int j=0;j<files.length();j++) {
                JSONObject file=files.getJSONObject(j);
                allHashed&="HASHED".equals(file.optString("hashStatus"));
                if(file.optBoolean("matchConfirmed",false)) {
                    JSONArray matches=file.getJSONArray("matchedIoc");
                    for(int k=0;k<matches.length();k++) packageMatches.put(matches.getJSONObject(k));
                }
            }
            boolean confirmed=packageMatches.length()>0&&!changed;
            row.put("apkInspectionComplete",allHashed&&!changed).put("confirmedIoc",confirmed)
                    .put("iocMatches",packageMatches).put("remediationEligible",confirmed&&!row.optBoolean("system",true)
                            &&!pkg.equals(context.getPackageName()))
                    .put("remediationPackageName",confirmed?pkg:"");
            MalwareInspection.summarizePackage(report,row);
            if(confirmed) report.add(new Finding("ioc."+pkg,CATEGORY,"공개 악성 파일 해시와 정확히 일치: "+row.optString("label",pkg),Finding.Status.ALERT,
                    pkg+"의 설치 APK "+packageMatches.length()+"건에서 공개 IOC의 SHA-256과 정확히 일치했습니다. 보고서의 파일·캠페인·출처를 확인하세요.",
                    row.optBoolean("system",true)?"시스템 앱은 이 앱에서 삭제할 수 없습니다. 사용을 중단하고 제조사 서비스센터에 공식 펌웨어 점검을 요청하세요.":
                            "앱 사용을 중단하고 기기의 삭제 화면에서 제거 여부를 확인하세요. 접근성·기기 관리자 권한 때문에 삭제가 차단되면 설정에서 해제한 뒤 다시 시도하세요. 삭제만으로 기기 전체의 복구를 보증하지 않습니다."));
        }
        finish(report,budget,database,metadataFailures,stopped,startWall,SystemClock.elapsedRealtime()-startElapsed);
        malware.finish(report,report.evidence.getJSONObject("apkCoverage").optString("stopReason"),SystemClock.elapsedRealtime()-startElapsed);
    }

    private static void inspectFile(Target target,JSONObject out,ApkEvidence.Budget budget,
            List<String> expectedSigners,ApkEvidence.IocIndex database,MalwareInspection malware) throws Exception {
        File path=new File(target.path);
        ApkEvidence.Stamp before=pathStamp(path);
        out.put("size",before.size).put("modifiedAtMillis",before.mtime)
                .put("identityChecked",before.identityAvailable);
        if(before.size>ApkEvidence.MAX_FILE_BYTES) {
            out.put("hashStatus","FILE_BYTE_LIMIT").put("signatureStatus","UNKNOWN_LIMIT"); return;
        }
        try(final RandomAccessFile input=new RandomAccessFile(path,"r")) {
            ApkEvidence.Stamp opened=fdStamp(input.getFD());
            if(!sameIdentity(before,opened)) { invalidate(out); out.getJSONArray("errors").put("OPENED_FILE_IDENTITY_CHANGED"); return; }
            String hash=null;MalwareEvidence.Hashes hashes=null;
            try {
                hashes=MalwareEvidence.hash(new InputStream() {
                    @Override public int read() throws IOException { return input.read(); }
                    @Override public int read(byte[] b,int off,int len) throws IOException { return input.read(b,off,len); }
                },before.size,budget);
                hash=hashes.sha256;
                out.put("observedSha256",hash).put("hashStatus","HASHED_PENDING_STABILITY");
            } catch(ApkEvidence.LimitException e) {
                out.put("hashStatus",e.reason).put("signatureStatus","UNKNOWN_LIMIT"); out.getJSONArray("errors").put(e.reason);
            } catch(IOException e) {
                out.put("hashStatus","UNREADABLE").put("signatureStatus","UNKNOWN_READ"); out.getJSONArray("errors").put(error(e));
            }
            if(hash!=null) verifySignature(input,out,budget,expectedSigners);
            if(hash!=null) {
                try {
                    out.put("malware",malware.scan(input,hashes,budget));
                    String stop=out.getJSONObject("malware").optString("stopReason");
                    if("TIME_LIMIT".equals(stop)||"CANCELLED".equals(stop)||"TOTAL_BYTE_LIMIT".equals(stop))
                        out.getJSONArray("errors").put(stop);
                } catch(Exception ex) {
                    out.put("malware",new JSONObject().put("state","SCAN_ERROR").put("complete",false)
                            .put("wholeFileCompared",false).put("archiveComplete",false).put("error",error(ex)));
                    if(ex instanceof ApkEvidence.LimitException) out.getJSONArray("errors").put(((ApkEvidence.LimitException)ex).reason);
                }
            }
            ApkEvidence.Stamp after=pathStamp(path),closed=fdStamp(input.getFD());
            if(!before.same(after)||!opened.same(closed)||!sameIdentity(after,closed)) {
                invalidate(out); out.getJSONArray("errors").put("FILE_CHANGED_DURING_SCAN"); return;
            }
            out.put("fileStable",true);
            if(hash!=null) {
                out.remove("observedSha256"); out.put("sha256",hash).put("hashStatus","HASHED");
            }
            MalwareInspection.stabilize(out);
            if(hash!=null&&database!=null&&"HASHED".equals(out.optString("hashStatus"))) {
                JSONArray matches=out.getJSONArray("matchedIoc");
                for(String collection:database.match(hash)) matches.put(new JSONObject().put("sha256",hash)
                        .put("fileId",target.id).put("collection",collection).put("name",ApkEvidence.collectionName(collection))
                        .put("sourceUrl",ApkEvidence.collectionSource(collection)).put("commit",ApkEvidence.IOC_COMMIT)
                        .put("matchType","exact-file-sha256"));
                out.put("matchConfirmed",matches.length()>0);
            }
        }
    }

    private static void verifySignature(RandomAccessFile input,JSONObject out,ApkEvidence.Budget budget,
            List<String> expectedSigners) throws Exception {
        int checkedApi=Math.min(ApkEvidence.ENGINE_MAX_API,Build.VERSION.SDK_INT);
        out.put("signatureEngine",ApkEvidence.ENGINE_VERSION).put("signatureCheckedApi",checkedApi)
                .put("deviceApi",Build.VERSION.SDK_INT).put("signatureCryptographicVerified",false)
                .put("signatureWarnings",new JSONArray()).put("signatureErrors",new JSONArray());
        try {
            budget.check();
            ApkVerifier.Result result=new ApkVerifier.Builder(new BoundedSource(input.getChannel(),0,input.length(),budget))
                    .setMinCheckedPlatformVersion(checkedApi).setMaxCheckedPlatformVersion(checkedApi).build().verify();
            budget.check();
            List<String> errors=new ArrayList<>();
            for(ApkVerifier.IssueWithParams issue:result.getAllErrors()) {
                errors.add(issue.getIssue().name()); out.getJSONArray("signatureErrors").put(issue.getIssue().name());
            }
            for(ApkVerifier.IssueWithParams issue:result.getWarnings()) out.getJSONArray("signatureWarnings").put(issue.getIssue().name());
            // Per-signer warnings are separate in the upstream result model.
            for(ApkVerifier.Result.V1SchemeSignerInfo signer:result.getV1SchemeSigners())
                for(ApkVerifier.IssueWithParams issue:signer.getWarnings()) out.getJSONArray("signatureWarnings").put(issue.getIssue().name());
            for(ApkVerifier.Result.V2SchemeSignerInfo signer:result.getV2SchemeSigners())
                for(ApkVerifier.IssueWithParams issue:signer.getWarnings()) out.getJSONArray("signatureWarnings").put(issue.getIssue().name());
            for(ApkVerifier.Result.V3SchemeSignerInfo signer:result.getV3SchemeSigners())
                for(ApkVerifier.IssueWithParams issue:signer.getWarnings()) out.getJSONArray("signatureWarnings").put(issue.getIssue().name());
            for(ApkVerifier.Result.V3SchemeSignerInfo signer:result.getV31SchemeSigners())
                for(ApkVerifier.IssueWithParams issue:signer.getWarnings()) out.getJSONArray("signatureWarnings").put(issue.getIssue().name());
            JSONArray schemes=new JSONArray();
            if(result.isVerifiedUsingV1Scheme()) schemes.put("v1");
            if(result.isVerifiedUsingV2Scheme()) schemes.put("v2");
            if(result.isVerifiedUsingV3Scheme()) schemes.put("v3");
            if(result.isVerifiedUsingV31Scheme()) schemes.put("v3.1");
            out.put("signatureSchemesVerified",schemes).put("signatureCryptographicVerified",result.isVerified());
            List<String> actualSigners=new ArrayList<>();
            for(X509Certificate certificate:result.getSignerCertificates()) actualSigners.add(ApkEvidence.sha256(certificate.getEncoded()));
            out.put("signerSha256",new JSONArray(actualSigners));
            String status=ApkEvidence.signatureStatus(result.isVerified(),errors,Build.VERSION.SDK_INT);
            if(result.isVerified()) {
                if(actualSigners.isEmpty()||expectedSigners.isEmpty()) {
                    out.put("signerMetadataMatch",JSONObject.NULL);
                    if("VERIFIED".equals(status)) status="UNKNOWN_SIGNER_METADATA";
                } else {
                    boolean same=ApkEvidence.sameSignerSets(actualSigners,expectedSigners);
                    out.put("signerMetadataMatch",same);
                    // On newer Android versions, a rotated signer may differ from this old API model.
                    if(!same&&"VERIFIED".equals(status)) status="SIGNER_MISMATCH";
                }
            }
            out.put("signatureStatus",status);
        } catch(ApkEvidence.LimitException e) {
            out.put("signatureStatus","UNKNOWN_LIMIT"); out.getJSONArray("errors").put(e.reason);
        } catch(java.security.NoSuchAlgorithmException e) {
            out.put("signatureStatus","UNKNOWN_UNSUPPORTED"); out.getJSONArray("errors").put(error(e));
        } catch(com.android.apksig.apk.ApkFormatException e) {
            out.put("signatureStatus","UNKNOWN_FORMAT"); out.getJSONArray("errors").put(error(e));
        } catch(IOException|RuntimeException|LinkageError e) {
            out.put("signatureStatus","UNKNOWN_VERIFIER"); out.getJSONArray("errors").put(error(e));
        }
    }

    private static void finish(ScanReport report,ApkEvidence.Budget budget,ApkEvidence.IocIndex database,
            int metadataFailures,String stopped,long started,long elapsed) throws Exception {
        try { budget.check(); } catch(ApkEvidence.LimitException e) { stopped=e.reason; }
        int files=0,hashed=0,verified=0,signatureInvalid=0,signerMismatch=0,matches=0,matchedPackages=0,completePackages=0;
        long fileBytes=0; boolean cryptoIssue=false;
        for(int i=0;i<report.inventory.length();i++) {
            JSONObject row=report.inventory.optJSONObject(i); if(row==null) continue;
            if(row.optBoolean("apkInspectionComplete",false)) completePackages++;
            if(row.optBoolean("confirmedIoc",false)) matchedPackages++;
            JSONArray entries=row.optJSONArray("apkFiles"); if(entries==null) continue;
            for(int j=0;j<entries.length();j++) {
                JSONObject file=entries.getJSONObject(j); files++;
                long size=file.optLong("size",-1L); if(size>=0&&Long.MAX_VALUE-fileBytes>=size) fileBytes+=size;
                if("HASHED".equals(file.optString("hashStatus"))) hashed++;
                String sig=file.optString("signatureStatus");
                if("VERIFIED".equals(sig)) verified++;
                if("INVALID".equals(sig)) signatureInvalid++;
                if("SIGNER_MISMATCH".equals(sig)) signerMismatch++;
                if(file.optBoolean("matchConfirmed",false)) matches++;
                JSONArray errs=file.optJSONArray("signatureErrors");
                if(errs!=null&&errs.length()>0) cryptoIssue=true;
            }
        }
        boolean hashesComplete=report.inventoryComplete&&report.inventory.length()>0&&metadataFailures==0
                &&completePackages==report.inventory.length()&&files>0&&files==hashed&&stopped.isEmpty();
        boolean signaturesComplete=hashesComplete&&verified+signatureInvalid+signerMismatch==files;
        boolean iocComplete=false; // legacy route disabled; malwareCoverage owns exact-reference completeness
        JSONObject coverage=new JSONObject().put("startedAt",started).put("completedAt",System.currentTimeMillis())
                .put("elapsedMillis",elapsed).put("timeBudgetMillis",ApkEvidence.DEFAULT_TIME_MILLIS)
                .put("perFileLimitBytes",ApkEvidence.MAX_FILE_BYTES).put("totalReadLimitBytes",ApkEvidence.MAX_TOTAL_BYTES)
                .put("visiblePackages",report.inventory.length()).put("metadataFailures",metadataFailures)
                .put("packagesWithAllHashes",completePackages).put("filesDiscovered",files).put("filesHashed",hashed)
                .put("filesHashUnknown",files-hashed).put("fileBytesDiscovered",fileBytes)
                .put("hashBytesRead",budget.hashBytesRead()).put("signatureBytesRead",budget.signatureBytesRead())
                .put("archiveBytesRead",budget.archiveBytesRead())
                .put("bytesRead",budget.hashBytesRead()+budget.signatureBytesRead()+budget.archiveBytesRead()).put("signatureVerifiedFiles",verified)
                .put("signatureInvalidFiles",signatureInvalid).put("signerMismatchFiles",signerMismatch)
                .put("signatureUnknownFiles",files-verified-signatureInvalid-signerMismatch)
                .put("iocMatchingFiles",matches).put("iocMatchingPackages",matchedPackages)
                .put("hashComplete",hashesComplete).put("signatureComplete",signaturesComplete)
                .put("iocComparisonComplete",iocComplete).put("legacyIocRouteDisabled",true).put("complete",hashesComplete&&signaturesComplete)
                .put("stopReason",stopped).put("engine",ApkEvidence.ENGINE_VERSION)
                .put("scanOrder","user-apps-first, then system apps; inventory output retains its original ordering")
                .put("timeLimitMode","Cooperative checks before/after work and during reads. A verifier CPU operation or an OS call can delay cancellation; a late result is not accepted as complete.")
                .put("engineMaximumModelledApi",ApkEvidence.ENGINE_MAX_API).put("deviceApi",Build.VERSION.SDK_INT)
                .put("scope","현재 프로필에서 OS가 노출한 base/split APK의 읽을 수 있는 파일. 시스템 앱도 포함. 앱 내부 데이터·동적 다운로드 코드·다른 프로필·커널·펌웨어·물리 하드웨어는 제외.");
        report.evidence.put("apkCoverage",coverage);
        report.add(new Finding("apk.contents",CATEGORY,"설치 APK 내용 SHA-256",hashesComplete?Finding.Status.INFO:Finding.Status.UNKNOWN,
                "발견한 파일 "+files+"개 중 "+hashed+"개 해시 수집. 앱 "+completePackages+" / "+report.inventory.length()+"개. "+(stopped.isEmpty()?"":("중단 사유: "+stopped+". ")),
                "base와 split 파일을 스트리밍으로 읽고 전후 크기·수정시간·파일 식별자를 확인합니다. 해시는 관측한 내용의 지문이며 제조사 순정 판정은 신뢰할 기준 해시가 별도로 필요합니다."));
        Finding.Status sigStatus=signatureInvalid>0||signerMismatch>0||cryptoIssue?Finding.Status.WARN:
                signaturesComplete?Finding.Status.INFO:Finding.Status.UNKNOWN;
        report.add(new Finding("apk.signatures",CATEGORY,"APK 암호학적 서명·설치 메타데이터 대조",sigStatus,
                "확인 "+verified+"개, 검증 실패 "+signatureInvalid+"개, 설치 서명과 차이 "+signerMismatch+"개, 확인 불가 "+(files-verified-signatureInvalid-signerMismatch)+"개. "+
                        (Build.VERSION.SDK_INT>ApkEvidence.ENGINE_MAX_API?"현재 Android API "+Build.VERSION.SDK_INT+"는 엔진의 API 36 모델보다 새로워 최종 판정은 확인 불가입니다.":""),
                "AOSP Android16 QPR2 apksig 소스를 사용합니다(ba8f1f1 고정, API26–36 모델). 실제 Galaxy 설치 검증과 동일하다는 보증은 아니며 미래 API·SDK 범위 모호성은 확인 불가로 남깁니다. 각 파일의 실제 서명과 내용 다이제스트를 검증합니다. 정상 서명도 악성 앱에 존재할 수 있고, 설치 API의 인증서 정보도 OS 자체가 제공한 증거입니다."));

    }

    private static void invalidate(JSONObject out) throws Exception {
        MalwareInspection.invalidate(out);
        if(out.has("sha256")) { out.put("observedSha256",out.getString("sha256")); out.remove("sha256"); }
        out.put("hashStatus","CHANGED").put("signatureStatus","UNKNOWN_CHANGED")
                .put("signatureCryptographicVerified",false).put("fileStable",false)
                .put("matchConfirmed",false).put("matchedIoc",new JSONArray());
    }
    private static List<String> strings(JSONArray array) {
        List<String> result=new ArrayList<>(); if(array==null) return result;
        for(int i=0;i<array.length();i++) { Object value=array.opt(i); if(!(value instanceof String)||!ApkEvidence.validSha256((String)value)) return Collections.emptyList(); result.add((String)value); }
        return result;
    }
    private static byte[] readAsset(Context c,String name,int max) throws IOException {
        try(InputStream in=c.getAssets().open(name);ByteArrayOutputStream out=new ByteArrayOutputStream()) {
            byte[] buffer=new byte[8192]; int n;
            while((n=in.read(buffer))!=-1) { if(out.size()+n>max) throw new IOException("ASSET_TOO_LARGE"); out.write(buffer,0,n); }
            return out.toByteArray();
        }
    }
    private static ApkEvidence.Stamp pathStamp(File file) throws Exception {
        StructStat st=Os.lstat(file.getPath());
        if(!OsConstants.S_ISREG(st.st_mode)) throw new IOException("SOURCE_IS_NOT_REGULAR_FILE");
        return new ApkEvidence.Stamp(st.st_size,file.lastModified(),st.st_ctime,st.st_dev,st.st_ino,true);
    }
    private static ApkEvidence.Stamp fdStamp(FileDescriptor fd) throws Exception {
        StructStat st=Os.fstat(fd);
        if(!OsConstants.S_ISREG(st.st_mode)) throw new IOException("OPENED_SOURCE_IS_NOT_REGULAR_FILE");
        return new ApkEvidence.Stamp(st.st_size,st.st_mtime*1000L,st.st_ctime,st.st_dev,st.st_ino,true);
    }
    private static boolean sameIdentity(ApkEvidence.Stamp path,ApkEvidence.Stamp fd) {
        return path.size==fd.size&&path.mtime/1000L==fd.mtime/1000L&&path.device==fd.device&&path.inode==fd.inode;
    }
    @SuppressWarnings("deprecation") private static Snapshot snapshot(PackageManager pm,String pkg) throws Exception {
        ApplicationInfo app=pm.getApplicationInfo(pkg,0); PackageInfo p=pm.getPackageInfo(pkg,0);
        return new Snapshot(app,Build.VERSION.SDK_INT>=28?p.getLongVersionCode():p.versionCode,p.lastUpdateTime);
    }
    private static final class Snapshot {
        final ApplicationInfo info; final long version,updated;
        Snapshot(ApplicationInfo info,long version,long updated) { this.info=info;this.version=version;this.updated=updated; }
        boolean same(Snapshot other) {
            return version==other.version&&updated==other.updated&&java.util.Objects.equals(info.sourceDir,other.info.sourceDir)
                    &&Arrays.equals(info.splitSourceDirs,other.info.splitSourceDirs)&&Arrays.equals(info.splitNames,other.info.splitNames);
        }
    }
    private static final class Target {
        final String id,splitName,path; final boolean base;
        Target(String id,String splitName,String path,boolean base) { this.id=id;this.splitName=splitName;this.path=path;this.base=base; }
    }
    private static List<Target> targets(ApplicationInfo app) throws IOException {
        if(app.sourceDir==null||app.sourceDir.isEmpty()) throw new IOException("BASE_APK_PATH_MISSING");
        List<Target> out=new ArrayList<>(); out.add(new Target("base","",app.sourceDir,true));
        String[] splits=app.splitSourceDirs,names=app.splitNames;
        if(splits==null||splits.length==0) { if(names!=null&&names.length>0) throw new IOException("SPLIT_METADATA_INCONSISTENT"); return out; }
        if(splits.length>=MAX_FILES_PER_PACKAGE||names==null||splits.length!=names.length) throw new IOException("SPLIT_METADATA_INCONSISTENT");
        Set<String> ids=new HashSet<>(),paths=new HashSet<>(); paths.add(app.sourceDir);
        for(int i=0;i<splits.length;i++) {
            if(splits[i]==null||splits[i].isEmpty()||names[i]==null||names[i].isEmpty()||!ids.add(names[i])||!paths.add(splits[i]))
                throw new IOException("SPLIT_METADATA_INCONSISTENT");
            out.add(new Target("split:"+names[i],names[i],splits[i],false));
        }
        return out;
    }
    private static String error(Throwable error) {
        String text=error.getClass().getSimpleName()+": "+String.valueOf(error.getMessage());
        return text.length()>300?text.substring(0,300):text;
    }
    private static void update(ScanEngine.Progress progress,String message) {
        if(progress!=null) try { progress.update(message); } catch(RuntimeException ignored) { }
    }

    /** Public apksig interface only: no custom cryptography, memory mapping or internal APIs. */
    static final class BoundedSource implements DataSource {
        private static final int BUFFER_LIMIT=16*1024*1024,CHUNK=64*1024;
        private final FileChannel channel; private final long start,length; private final ApkEvidence.Budget budget;
        BoundedSource(FileChannel channel,long start,long length,ApkEvidence.Budget budget) {
            this.channel=channel;this.start=start;this.length=length;this.budget=budget;
        }
        @Override public long size() { return length; }
        private void range(long offset,long count) {
            if(offset<0||count<0||offset>length||count>length-offset) throw new IndexOutOfBoundsException("APK source range");
        }
        @Override public DataSource slice(long offset,long count) { range(offset,count); return new BoundedSource(channel,start+offset,count,budget); }
        @Override public void feed(long offset,long count,DataSink sink) throws IOException {
            range(offset,count); byte[] bytes=new byte[(int)Math.min(CHUNK,count)]; long done=0;
            while(done<count) { int n=(int)Math.min(bytes.length,count-done); read(offset+done,ByteBuffer.wrap(bytes,0,n)); sink.consume(bytes,0,n); done+=n; }
        }
        @Override public ByteBuffer getByteBuffer(long offset,int count) throws IOException {
            range(offset,count); budget.check(); if(count>BUFFER_LIMIT) throw new ApkEvidence.LimitException("VERIFIER_BUFFER_LIMIT");
            ByteBuffer buffer=ByteBuffer.allocate(count); read(offset,buffer); buffer.flip(); return buffer;
        }
        @Override public void copyTo(long offset,int count,ByteBuffer destination) throws IOException {
            range(offset,count); if(count>destination.remaining()) throw new java.nio.BufferOverflowException();
            byte[] bytes=new byte[Math.min(CHUNK,count)]; int done=0;
            while(done<count) { int n=Math.min(bytes.length,count-done); read(offset+done,ByteBuffer.wrap(bytes,0,n)); destination.put(bytes,0,n); done+=n; }
        }
        private void read(long offset,ByteBuffer destination) throws IOException {
            int done=0,stalls=0;
            while(destination.hasRemaining()) {
                int allowed=budget.allowedRead(Math.min(CHUNK,destination.remaining())),oldLimit=destination.limit();
                destination.limit(destination.position()+allowed);
                int count;
                try { count=channel.read(destination,start+offset+done); } finally { destination.limit(oldLimit); }
                if(count<0) throw new IOException("APK_TRUNCATED_DURING_VERIFICATION");
                if(count==0) { if(++stalls>3) throw new IOException("VERIFIER_READ_STALLED"); continue; }
                stalls=0; budget.read(count,true); done+=count;
            }
        }
    }
}

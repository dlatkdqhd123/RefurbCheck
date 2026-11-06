package io.github.refurbcheck;

import android.content.Context;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.HttpsURLConnection;

/** Foreground, data-only updates. No report, APK, app list or identifier is uploaded. */
public final class CatalogUpdateManager {
    private static final Object LOCK=new Object();
    private static final String PREFERENCES="refurbcheck-catalog-updates",LAST_CHECK="last_check";
    private CatalogUpdateManager() { }

    public static final class Selection {
        public final CatalogUpdateVerifier.Snapshot snapshot;
        public final String origin,state,error;
        public final boolean automaticRemovalAllowed;
        private final JSONObject check;
        private final long selectedAtEpochMillis;
        private Selection(CatalogUpdateVerifier.Snapshot snapshot,String error,JSONObject check,long now) {
            this.snapshot=snapshot;this.error=error;this.check=check;
            selectedAtEpochMillis=now;
            origin=snapshot.signedUpdate?"signed-update":"bundled";
            state=error.isEmpty()?snapshot.freshness(now):"FALLBACK_OR_STORAGE_ERROR";
            automaticRemovalAllowed=error.isEmpty()&&"CURRENT".equals(snapshot.freshness(now));
        }
        public JSONObject diagnostics() throws Exception {
            String currentState=error.isEmpty()?snapshot.freshness(System.currentTimeMillis()):"FALLBACK_OR_STORAGE_ERROR";
            return new JSONObject().put("origin",origin).put("state",currentState).put("error",error)
                    .put("selectedAtEpochMillis",selectedAtEpochMillis).put("stateAtSelection",state)
                    .put("sequence",snapshot.sequence).put("bundleSha256",snapshot.bundleSha256)
                    .put("signedUpdate",snapshot.signedUpdate).put("signatureAlgorithm",snapshot.signedUpdate?"SHA256withRSA-3072":"APK-bundled digest pins")
                    .put("updatePublicKeySha256",CatalogUpdateConfig.UPDATE_PUBLIC_KEY_SHA256)
                    .put("publishedAtEpochMillis",snapshot.createdAtEpochMillis).put("expiresAtEpochMillis",snapshot.expiresAtEpochMillis)
                    .put("sourceRetrievedAtEpochMillis",snapshot.retrievedAtEpochMillis).put("sourceSnapshotDate",snapshot.snapshotDate)
                    .put("automaticRemovalAllowed",error.isEmpty()&&"CURRENT".equals(currentState)).put("lastCheck",new JSONObject(check.toString()))
                    .put("clockSource","device clock, not independently authenticated")
                    .put("rollbackScope","signed sequence and SHA-256, private app storage; cleared by app-data reset/uninstall; not resistant to a hostile OS")
                    .put("thresholdSignatures",false).put("tufCompliance",false).put("fileUploads",false);
        }
    }

    public static final class Result {
        public final boolean changed;
        public final long sequence;
        public final String message;
        private final String bundleSha256,warning;
        private Result(CatalogUpdateStore.Applied applied) {
            changed=applied.changed;sequence=applied.snapshot.sequence;bundleSha256=applied.snapshot.bundleSha256;warning=applied.warning;
            message=warning.isEmpty()?(changed?"서명·구성 검증을 마친 검사 자료를 적용했습니다.":"현재 서명된 검사 자료와 동일합니다.")
                    :"검사 자료는 적용했지만 버전 보관 상태를 확인해야 합니다. 자동 삭제 연결은 보류합니다.";
        }
        public JSONObject diagnostics() throws Exception {
            return new JSONObject().put("changed",changed).put("sequence",sequence).put("bundleSha256",bundleSha256)
                    .put("warning",warning).put("message",message);
        }
    }

    /** Call on a worker. One immutable selection serves an entire APK scan. */
    public static Selection current(final Context context,ApkEvidence.Budget budget) throws IOException {
        if(context==null||budget==null) throw new IllegalArgumentException("context and budget required");
        synchronized(LOCK) {
            long now=System.currentTimeMillis();String error="";CatalogUpdateVerifier.Snapshot snapshot=null;
            try {
                CatalogUpdateStore.Stored stored=store(context).read(now,budget);
                snapshot=stored.snapshot;error=stored.error;
            } catch(Exception failure) {error=description(failure);}
            if(snapshot==null) {
                snapshot=CatalogUpdateVerifier.bundled((name,limit)->asset(context,name,limit),budget);
            }
            return new Selection(snapshot,error,lastCheck(context),now);
        }
    }

    /** Input is a user-selected signed ZIP. The caller owns/closes the stream. */
    public static Result importUpdate(Context context,InputStream input,AtomicBoolean cancelled) throws IOException {
        ApkEvidence.Budget budget=new ApkEvidence.Budget(cancelled,45_000L,32L*1024*1024,System::nanoTime);
        try {
            byte[] bundle=CatalogUpdateVerifier.readBounded(input,CatalogUpdateVerifier.MAX_BUNDLE_BYTES,budget);
            Result result=apply(context,bundle,budget);
            record(context,"file",true,result,"");return result;
        } catch(IOException failure) {record(context,"file",false,null,description(failure));throw failure;}
    }

    /**
     * Fixed HTTPS endpoint, no redirects, bounded data/time, system TLS validation.
     * Root UI owns Wi-Fi-only auto-check policy and calls this only in foreground.
     */
    public static Result downloadAndInstall(Context context,AtomicBoolean cancelled) throws IOException {
        ApkEvidence.Budget budget=new ApkEvidence.Budget(cancelled,20_000L,32L*1024*1024,System::nanoTime);
        HttpsURLConnection connection=null;
        try {
            budget.check();
            URL url=new URL(CatalogUpdateConfig.UPDATE_URL);
            if(!"https".equals(url.getProtocol())||!"raw.githubusercontent.com".equals(url.getHost())
                    ||url.getPort()!=-1||url.getUserInfo()!=null||url.getRef()!=null||url.getQuery()!=null)
                throw new IOException("CATALOG_UPDATE_ENDPOINT_INVALID");
            connection=(HttpsURLConnection)url.openConnection();connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(5000);connection.setReadTimeout(5000);connection.setUseCaches(false);
            connection.setRequestMethod("GET");connection.setRequestProperty("Accept","application/zip, application/octet-stream");
            connection.setRequestProperty("Accept-Encoding","identity");connection.setRequestProperty("User-Agent","RefurbCheck/1.3 catalog-updater");
            int status=connection.getResponseCode();budget.check();
            if(status!=HttpURLConnection.HTTP_OK) throw new IOException("CATALOG_UPDATE_HTTP_"+status);
            String encoding=connection.getContentEncoding();
            if(encoding!=null&&!encoding.isEmpty()&&!"identity".equalsIgnoreCase(encoding)) throw new IOException("CATALOG_UPDATE_CONTENT_ENCODING");
            long length=connection.getContentLengthLong();
            if(length==0||length>CatalogUpdateVerifier.MAX_BUNDLE_BYTES) throw new IOException("CATALOG_UPDATE_DOWNLOAD_SIZE");
            byte[] bundle;
            try(InputStream input=connection.getInputStream()) {
                bundle=CatalogUpdateVerifier.readBounded(input,CatalogUpdateVerifier.MAX_BUNDLE_BYTES,budget);
            }
            if(length>=0&&length!=bundle.length) throw new IOException("CATALOG_UPDATE_DOWNLOAD_TRUNCATED");
            budget.check();Result result=apply(context,bundle,budget);
            record(context,"https",true,result,"");return result;
        } catch(IOException failure) {record(context,"https",false,null,description(failure));throw failure;}
        catch(RuntimeException failure) {
            IOException error=new IOException("CATALOG_UPDATE_DOWNLOAD_FAILED",failure);
            record(context,"https",false,null,description(error));throw error;
        } finally {if(connection!=null) connection.disconnect();}
    }

    public static JSONObject lastCheck(Context context) {
        try {
            String raw=context.getSharedPreferences(PREFERENCES,Context.MODE_PRIVATE).getString(LAST_CHECK,"");
            if(raw==null||raw.isEmpty()) return new JSONObject().put("state","NOT_CHECKED");
            if(raw.length()>4096) return new JSONObject().put("state","UNREADABLE");
            return ReportJson.parse(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch(Exception ignored) {return new JSONObject();}
    }
    private static Result apply(Context context,byte[] bundle,ApkEvidence.Budget budget) throws IOException {
        synchronized(LOCK) {budget.check();return new Result(store(context).install(bundle,System.currentTimeMillis(),budget));}
    }
    private static CatalogUpdateStore store(Context context) throws IOException {
        byte[] key=asset(context,"catalog_update_key.der",1024);
        if(!ApkEvidence.sha256(key).equals(CatalogUpdateConfig.UPDATE_PUBLIC_KEY_SHA256)) throw new IOException("CATALOG_UPDATE_PUBLIC_KEY_DIGEST");
        return new CatalogUpdateStore(new File(context.getNoBackupFilesDir(),"catalog-updates"),key,
                CatalogUpdateConfig.INITIAL_SEQUENCE,CatalogUpdateConfig.INITIAL_BUNDLE_SHA256);
    }
    private static byte[] asset(Context context,String name,int limit) throws IOException {
        try(InputStream input=context.getAssets().open(name)) {return CatalogUpdateVerifier.readBounded(input,limit,null);}
    }
    private static void record(Context context,String channel,boolean success,Result result,String error) {
        try {
            JSONObject value=new JSONObject().put("state",success?"CHECK_SUCCEEDED":"CHECK_FAILED")
                    .put("checkedAtEpochMillis",System.currentTimeMillis()).put("channel",channel)
                    .put("error",error).put("latestAvailableVersionGuaranteed",false).put("fileUploads",false);
            if(result!=null) value.put("result",result.diagnostics());
            context.getSharedPreferences(PREFERENCES,Context.MODE_PRIVATE).edit().putString(LAST_CHECK,value.toString()).apply();
        } catch(Exception ignored) { /* Diagnostic persistence never authorizes or activates an update. */ }
    }
    private static String description(Exception error) {
        String result=error.getClass().getSimpleName()+": "+error.getMessage();
        return result.length()>512?result.substring(0,512):result;
    }
}

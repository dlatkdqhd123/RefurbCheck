package io.github.refurbcheck;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/** User-confirmed settings navigation and tightly scoped known-IOC app removal. */
final class RemediationController {
    private RemediationController() { }
    static Intent intent(Context context,RemediationAction action) {
        switch(action.kind) {
            case ACCESSIBILITY:return new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
            case NOTIFICATIONS:return new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS);
            case DEVELOPER:return new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS);
            case SECURITY:case AUTO_BLOCKER:return new Intent(Settings.ACTION_SECURITY_SETTINGS);
            case KEYBOARDS:return new Intent(Settings.ACTION_INPUT_METHOD_SETTINGS);
            case VPN:return new Intent(Settings.ACTION_VPN_SETTINGS);
            case WIFI:return new Intent(Settings.ACTION_WIFI_SETTINGS);
            case APPS:return action.packageName.isEmpty()?new Intent(Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS):
                    new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:"+action.packageName));
            case UNKNOWN_SOURCES:return new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES);
            case DEVICE_CARE:return launchOrSettings(context,GalaxyInspector.DEVICE_CARE);
            case MEMBERS:return launchOrSettings(context,GalaxyInspector.MEMBERS);
            case PLAY_PROTECT:return launchOrSettings(context,"com.android.vending");
            case UPDATE:return new Intent(Settings.ACTION_SETTINGS);
            case SERVICE:return new Intent(Intent.ACTION_VIEW,Uri.parse("https://www.samsungsvc.co.kr/solution/618789"));
            case UNINSTALL:return new Intent(Intent.ACTION_UNINSTALL_PACKAGE,Uri.parse("package:"+action.packageName));
            default:return new Intent(Settings.ACTION_SETTINGS);
        }
    }
    private static Intent launchOrSettings(Context context,String pkg) {
        Intent launch=context.getPackageManager().getLaunchIntentForPackage(pkg);
        return launch==null?new Intent(Settings.ACTION_SETTINGS):launch;
    }
    static JSONObject findPackage(ScanReport report,String name) {
        if(report==null) return null;
        for(int i=0;i<report.inventory.length();i++) {
            JSONObject row=report.inventory.optJSONObject(i);
            if(row!=null&&name.equals(row.optString("packageName"))) return row;
        }
        return null;
    }
    static boolean canRemove(JSONObject row,String ownPackage) {
        return RemediationRules.eligible(row,ownPackage)||MalwareRemediationRules.eligible(row,ownPackage);
    }
    @SuppressWarnings("deprecation")
    static void preflightUninstall(Context context,JSONObject row) throws Exception {
        if(!RemediationRules.eligible(row,context.getPackageName())&&MalwareRemediationRules.eligible(row,context.getPackageName())) {
            MalwareRemovalVerifier.preflight(context,row);return;
        }
        if(!RemediationRules.eligible(row,context.getPackageName())) throw new IOException("삭제 대상 근거가 불완전합니다. 다시 검사하세요.");
        PackageManager pm=context.getPackageManager();String pkg=row.getString("packageName");
        PackageInfo before=pm.getPackageInfo(pkg,0);ApplicationInfo info=before.applicationInfo;
        if(info==null||(info.flags&(ApplicationInfo.FLAG_SYSTEM|ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))!=0)
            throw new IOException("시스템 앱은 삭제 대상으로 처리하지 않습니다.");
        long version=Build.VERSION.SDK_INT>=28?before.getLongVersionCode():before.versionCode;
        if(version!=row.getLong("versionCode")||before.lastUpdateTime!=row.getLong("lastUpdateTime"))
            throw new IOException("검사 이후 앱이 변경되었습니다. 다시 검사하세요.");
        Map<String,String> paths=paths(info);ApkEvidence.IocIndex db=loadDatabase(context);
        ApkEvidence.Budget budget=new ApkEvidence.Budget(new AtomicBoolean(false),30_000,2L<<30,System::nanoTime);
        JSONArray matches=row.getJSONArray("iocMatches");
        Map<String,String> checked=new HashMap<>();
        for(int i=0;i<matches.length();i++) {
            JSONObject match=matches.getJSONObject(i);String id=match.getString("fileId"),expected=match.getString("sha256");
            String path=paths.get(id);if(path==null) throw new IOException("APK 구성 변경으로 삭제를 보류했습니다.");
            if(!checked.containsKey(id)) {
                StructStat start=Os.lstat(path);
                if(!OsConstants.S_ISREG(start.st_mode)) throw new IOException("일반 APK 파일이 아니므로 삭제를 보류했습니다.");
                try(FileInputStream input=new FileInputStream(path)) {
                    StructStat opened=Os.fstat(input.getFD());if(!OsConstants.S_ISREG(opened.st_mode)||!same(start,opened)) throw new IOException("APK 파일이 변경되었습니다.");
                    String actual=ApkEvidence.hash(input,start.st_size,budget);
                    if(!same(opened,Os.fstat(input.getFD()))||!same(start,Os.lstat(path))) throw new IOException("APK 파일이 변경되었습니다.");
                    checked.put(id,actual);
                }
            }
            String actual=checked.get(id);
            if(!expected.equalsIgnoreCase(actual)||db.match(actual).isEmpty())
                throw new IOException("현재 APK가 탐지 당시 파일과 다릅니다. 다시 검사하세요.");
        }
        PackageInfo after=pm.getPackageInfo(pkg,0);
        long afterVersion=Build.VERSION.SDK_INT>=28?after.getLongVersionCode():after.versionCode;
        if(after.applicationInfo==null||afterVersion!=version||after.lastUpdateTime!=before.lastUpdateTime
                ||!paths.equals(paths(after.applicationInfo))
                ||(after.applicationInfo.flags&(ApplicationInfo.FLAG_SYSTEM|ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))!=0)
            throw new IOException("검증 중 앱이 변경되어 삭제를 보류했습니다.");
        // The Android system still owns the final confirmation and uninstall operation.
    }
    private static boolean same(StructStat a,StructStat b) {
        return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_size==b.st_size&&a.st_mtime==b.st_mtime&&a.st_ctime==b.st_ctime;
    }
    private static Map<String,String> paths(ApplicationInfo info) throws IOException {
        Map<String,String> result=new HashMap<>();
        if(info.sourceDir==null||info.sourceDir.isEmpty()) throw new IOException("기본 APK를 확인할 수 없습니다.");
        result.put("base",info.sourceDir);
        String[] names=info.splitNames,files=info.splitSourceDirs;
        if(files==null||files.length==0) {
            if(names!=null&&names.length>0) throw new IOException("split APK 정보가 불완전합니다.");
        } else {
            if(names==null||names.length!=files.length||files.length>2048) throw new IOException("split APK 정보가 불완전합니다.");
            for(int i=0;i<files.length;i++) if(names[i]==null||names[i].isEmpty()||files[i]==null||files[i].isEmpty()
                    ||result.put("split:"+names[i],files[i])!=null) throw new IOException("split APK 정보가 중복되거나 불완전합니다.");
        }
        return result;
    }
    private static ApkEvidence.IocIndex loadDatabase(Context context) throws Exception {
        try(InputStream in=context.getAssets().open("ioc_sha256.txt");ByteArrayOutputStream out=new ByteArrayOutputStream()) {
            byte[] buffer=new byte[8192];int n;
            while((n=in.read(buffer))!=-1) { if(out.size()+n>128*1024) throw new IOException("IOC 자료 한도 초과");out.write(buffer,0,n); }
            return ApkEvidence.bundledIocs(out.toByteArray());
        }
    }
    static String removalOutcome(Context context,String pkg) {
        try { context.getPackageManager().getPackageInfo(pkg,0);return "PACKAGE_STILL_PRESENT"; }
        catch(PackageManager.NameNotFoundException e) {
            boolean visibility=Build.VERSION.SDK_INT<30||context.checkSelfPermission("android.permission.QUERY_ALL_PACKAGES")==PackageManager.PERMISSION_GRANTED;
            return visibility?"PACKAGE_NOT_PRESENT":"VERIFICATION_UNAVAILABLE";
        } catch(RuntimeException e) { return "VERIFICATION_UNAVAILABLE"; }
    }
}

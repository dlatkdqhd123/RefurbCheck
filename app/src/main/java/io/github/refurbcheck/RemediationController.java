package io.github.refurbcheck;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import org.json.JSONArray;
import org.json.JSONObject;

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
        return MalwareRemediationRules.eligible(row,ownPackage);
    }
    static void preflightUninstall(Context context,JSONObject row) throws Exception {
        // One live signed/current catalog; no legacy stale IOC bypass.
        MalwareRemovalVerifier.preflight(context,row);
    }
    static String removalOutcome(Context context,String pkg) {
        try { context.getPackageManager().getPackageInfo(pkg,0);return "PACKAGE_STILL_PRESENT"; }
        catch(PackageManager.NameNotFoundException e) {
            boolean visibility=Build.VERSION.SDK_INT<30||context.checkSelfPermission("android.permission.QUERY_ALL_PACKAGES")==PackageManager.PERMISSION_GRANTED;
            return visibility?"PACKAGE_NOT_PRESENT":"VERIFICATION_UNAVAILABLE";
        } catch(RuntimeException e) { return "VERIFICATION_UNAVAILABLE"; }
    }
}

package io.github.refurbcheck;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.content.pm.Signature;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.os.Build;
import android.provider.Settings;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.view.accessibility.AccessibilityManager;
import android.view.inputmethod.InputMethodInfo;
import android.view.inputmethod.InputMethodManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static io.github.refurbcheck.Finding.Status.*;

/** Read-only, current-profile observations from an unprivileged Android process. */
public final class ScanEngine {
    public interface Progress { void update(String stage); }
    private interface Probe { void run() throws Exception; }
    private final Context context;
    private final PackageManager pm;
    private static final String SYSTEM="부팅·시스템", ROOT="루팅·개조", APPS="앱·설정";
    private static final String NETWORK="인증서·네트워크", LIMITS="검증 범위";
    private static final String SELF_REPORT="운영체제가 알려 주는 값이며, 침해된 기기에서는 위조될 수 있습니다.";
    private static final Set<String> ROOT_PACKAGES=new HashSet<>(Arrays.asList(
            "com.topjohnwu.magisk", "me.weishu.kernelsu", "me.bmax.apatch",
            "org.lsposed.manager", "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager", "com.solohsu.android.edxp.manager",
            "eu.chainfire.supersu", "com.noshufou.android.su", "com.koushikdutta.superuser"));
    private static final Set<String> SENSITIVE_PERMISSIONS=new HashSet<>(Arrays.asList(
            "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
            "android.permission.READ_CALL_LOG", "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA", "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_PHONE_STATE", "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO"));

    public ScanEngine(Context context) {
        this.context=context.getApplicationContext(); this.pm=this.context.getPackageManager();
    }

    public ScanReport scan(Progress progress) {
        return scan(progress,new AtomicBoolean(false));
    }
    public ScanReport scan(Progress progress,AtomicBoolean cancelled) {
        ScanReport r=new ScanReport();
        update(progress,"부팅 상태와 보안 설정 확인 중");
        guard(r,"system.read",SYSTEM,"시스템 정보 수집",()->inspectSystem(r));
        guard(r,"root.paths",ROOT,"루팅 관련 경로",()->inspectRootPaths(r));
        guard(r,"root.maps",ROOT,"현재 앱의 후킹 라이브러리 흔적",()->inspectMaps(r));
        if(cancelled.get()) { addLimits(r);return r; }
        update(progress,"설치 앱과 서명 정보 확인 중");
        guard(r,"apps.inventory",APPS,"설치 앱 목록",()->inspectPackages(r));
        if(cancelled.get()) { addLimits(r);return r; }
        update(progress,"접근성·기기 관리자·입력기 확인 중");
        guard(r,"settings.accessibility",APPS,"사용 중인 접근성 서비스",()->inspectAccessibility(r));
        guard(r,"settings.admin",APPS,"활성 기기 관리자",()->inspectAdmins(r));
        guard(r,"settings.notifications",APPS,"알림 접근 앱",()->inspectNotifications(r));
        guard(r,"settings.keyboards",APPS,"사용 가능한 키보드",()->inspectKeyboards(r));
        inspectSwitch(r,"settings.developer","개발자 옵션",Settings.Global.DEVELOPMENT_SETTINGS_ENABLED);
        inspectSwitch(r,"settings.adb","USB 디버깅",Settings.Global.ADB_ENABLED);
        if(Build.VERSION.SDK_INT>=30) inspectSwitch(r,"settings.wireless_adb","무선 디버깅","adb_wifi_enabled");
        if(cancelled.get()) { addLimits(r);return r; }
        update(progress,"네트워크와 사용자 인증서 확인 중");
        guard(r,"network.vpn",NETWORK,"앱에 보이는 VPN 연결",()->inspectVpn(r));
        guard(r,"network.proxy",NETWORK,"앱에 적용된 프록시",()->inspectProxy(r));
        guard(r,"network.user_ca",NETWORK,"사용자 설치 CA 인증서",()->inspectUserCertificates(r));
        if(cancelled.get()) { addLimits(r);return r; }
        update(progress,"하드웨어 키 증명 확인 중");
        guard(r,"attestation.read","하드웨어 키 증명","키 증명 수집",()->AttestationProbe.check(context,r));
        addLimits(r);
        r.completedAt=System.currentTimeMillis();
        update(progress,"점검 완료");
        return r;
    }

    private void inspectSystem(ScanReport r) throws Exception {
        JSONObject d=new JSONObject();
        d.put("manufacturer",Build.MANUFACTURER); d.put("brand",Build.BRAND); d.put("model",Build.MODEL);
        d.put("device",Build.DEVICE); d.put("product",Build.PRODUCT); d.put("hardware",Build.HARDWARE);
        d.put("fingerprint",Build.FINGERPRINT); d.put("securityPatch",Build.VERSION.SECURITY_PATCH);
        d.put("androidRelease",Build.VERSION.RELEASE); d.put("apiLevel",Build.VERSION.SDK_INT);
        d.put("buildType",Build.TYPE); d.put("buildTags",Build.TAGS); d.put("abis",new JSONArray(Arrays.asList(Build.SUPPORTED_ABIS)));
        d.put("source","Android Build API; OS self-report, not independently authenticated");
        r.evidence.put("device",d);
        Map<String,String> props=new LinkedHashMap<>();
        try { props=readProperties(); } catch(Exception e) { r.evidence.put("propertyReadError",error(e)); }
        JSONObject selected=new JSONObject();
        for(String key:Arrays.asList("ro.boot.verifiedbootstate","ro.boot.flash.locked","ro.boot.vbmeta.device_state",
                "ro.boot.veritymode","ro.debuggable","ro.secure","ro.boot.warranty_bit","ro.warranty_bit",
                "ro.vendor.build.security_patch","ro.bootimage.build.version.security_patch","ro.build.version.oneui"))
            selected.put(key,value(props,key));
        r.evidence.put("bootProperties",selected);
        d.put("oneUiVersionRaw",value(props,"ro.build.version.oneui"));
        String state=value(props,"ro.boot.verifiedbootstate"), locked=value(props,"ro.boot.flash.locked");
        String vbmeta=value(props,"ro.boot.vbmeta.device_state");
        Finding.Status boot=Finding.Status.valueOf(SignalRules.bootLevel(state,locked,vbmeta));
        if(boot==PASS) boot=INFO;
        add(r,"boot.verified",SYSTEM,"부팅 검증·부트로더 잠금 (자기 보고)",boot,
                "Verified Boot="+shown(state)+", flash.locked="+shown(locked)+", vbmeta="+shown(vbmeta)+". "+SELF_REPORT,
                boot==INFO ? "green/잠금 신호만 관측했습니다. 아래 키 증명과 제조사 확인을 함께 참고하세요."
                        : "잠금 해제·검증 실패 신호가 있으면 판매자나 제조사에 확인하세요. 확인 전 임의로 부트로더를 다시 잠그지 마세요.");
        String verity=value(props,"ro.boot.veritymode");
        add(r,"boot.verity",SYSTEM,"파일시스템 검증 모드 (자기 보고)",verity.isEmpty()?UNKNOWN:"disabled".equals(verity)?WARN:INFO,
                "ro.boot.veritymode="+shown(verity)+". "+SELF_REPORT,"이 속성이 없거나 읽히지 않으면 검증 비활성이라는 뜻은 아닙니다.");
        boolean debug="eng".equals(Build.TYPE)||"userdebug".equals(Build.TYPE)||"1".equals(value(props,"ro.debuggable"))
                ||"0".equals(value(props,"ro.secure"));
        String tags=Build.TAGS==null?"":Build.TAGS;
        boolean test=tags.contains("test-keys")||tags.contains("dev-keys");
        add(r,"build.type",SYSTEM,"개발용 빌드·테스트 키 표시",debug||test?WARN:INFO,
                "type="+shown(Build.TYPE)+", tags="+shown(tags)+", ro.debuggable="+shown(value(props,"ro.debuggable"))
                        +", ro.secure="+shown(value(props,"ro.secure"))+". "+SELF_REPORT,
                debug||test?"개발용·커스텀 OS에서도 나타납니다. 출고용 공식 펌웨어인지 제조사에 확인하세요.":"출고용처럼 표시되어도 실제 펌웨어의 원본 일치 여부를 증명하지는 않습니다.");
        String patch=Build.VERSION.SECURITY_PATCH;
        LocalDate today=LocalDate.now();
        Finding.Status patchStatus=Finding.Status.valueOf(SignalRules.patchLevel(patch,today));
        String patchDetail="표시된 보안 패치: "+shown(patch)+". ";
        if(patchStatus!=UNKNOWN) {
            long age=SignalRules.patchAgeDays(patch,today); r.evidence.put("patchAgeDays",age);
            patchDetail+=age>=0?"기기 날짜 기준 "+age+"일 경과. ":"기기 날짜보다 "+(-age)+"일 뒤입니다. ";
        }
        add(r,"build.patch",SYSTEM,"보안 패치 날짜",patchStatus,patchDetail+SELF_REPORT,
                "이 앱은 180일 초과 또는 31일 넘는 미래 날짜를 확인 대상으로 표시합니다. 오래된 패치는 변조 증거가 아니며, 최신 여부는 제조사 업데이트에서 확인하세요.");
        guard(r,"system.selinux",SYSTEM,"SELinux 강제 적용",()->{
            String mode=readFile("/sys/fs/selinux/enforce",16).trim();
            add(r,"system.selinux",SYSTEM,"SELinux 강제 적용","1".equals(mode)?INFO:"0".equals(mode)?ALERT:UNKNOWN,
                    "enforce="+shown(mode)+". 1은 강제 적용, 0은 permissive입니다. "+SELF_REPORT,
                    "0이면 개발용 OS 또는 보안 정책 변경 가능성을 확인하세요. 읽기 차단은 정상 판정이 아닙니다.");
        });
        String warranty=value(props,"ro.boot.warranty_bit");
        if(warranty.isEmpty()) warranty=value(props,"ro.warranty_bit");
        if(!warranty.isEmpty()) add(r,"build.warranty",SYSTEM,"제조사 warranty bit (자기 보고)",
                "1".equals(warranty)||"0x1".equals(warranty)?WARN:INFO,"표시값="+warranty+". "+SELF_REPORT,
                "제조사·모델별 의미가 다릅니다. 삼성 Knox 여부 등을 제조사 서비스센터에서 확인하세요.");
    }

    private void inspectRootPaths(ScanReport r) throws Exception {
        String[] paths={"/system/bin/su","/system/xbin/su","/sbin/su","/su/bin/su","/system/bin/.ext/.su",
                "/system/app/Superuser.apk","/system/app/SuperSU.apk","/data/adb/magisk","/data/adb/ksu","/data/adb/ap"};
        List<String> found=new ArrayList<>(), denied=new ArrayList<>();
        int missing=0;
        for(String path:paths) {
            try { Os.lstat(path); found.add(path); }
            catch(ErrnoException e) { if(e.errno==OsConstants.ENOENT||e.errno==OsConstants.ENOTDIR) missing++; else denied.add(path); }
            catch(SecurityException e) { denied.add(path); }
        }
        JSONObject ev=new JSONObject(); ev.put("found",new JSONArray(found)); ev.put("notAccessible",new JSONArray(denied)); ev.put("notFound",missing);
        r.evidence.put("rootPaths",ev);
        add(r,"root.paths",ROOT,"루팅 관련 경로",!found.isEmpty()?ALERT:!denied.isEmpty()?UNKNOWN:INFO,
                "발견 "+found.size()+"개, 없음으로 응답한 경로 "+missing+"개, 읽기 제한 "+denied.size()+"개. "+join(found,8),
                "고정된 소수 경로의 존재만 확인합니다. su 실행·루트 권한 요청은 하지 않으며, 숨김·경로 변경·접근 제한을 우회하지 않습니다.");
    }

    private void inspectMaps(ScanReport r) throws Exception {
        String maps=readFile("/proc/self/maps",1024*1024).toLowerCase(Locale.ROOT);
        List<String> hits=new ArrayList<>();
        for(String marker:Arrays.asList("libfrida-gadget","frida-agent","libxposed","liblsposed","libsubstrate","libzygisk"))
            if(maps.contains(marker)) hits.add(marker);
        r.evidence.put("ownProcessLibraryMarkers",new JSONArray(hits));
        add(r,"root.maps",ROOT,"현재 앱의 후킹 라이브러리 흔적",hits.isEmpty()?INFO:WARN,
                hits.isEmpty()?"현재 앱의 읽을 수 있는 메모리 매핑에서 지정된 라이브러리 이름이 보이지 않았습니다.":"관측된 이름: "+join(hits,8),
                "현재 앱 프로세스의 일부 이름만 확인합니다. 합법적 디버깅·분석에도 쓰일 수 있으며, 다른 프로세스나 숨겨진 후킹의 부재를 증명하지 않습니다.");
    }

    @SuppressWarnings("deprecation")
    private void inspectPackages(ScanReport r) throws Exception {
        boolean visibility=Build.VERSION.SDK_INT<30||context.checkSelfPermission("android.permission.QUERY_ALL_PACKAGES")==PackageManager.PERMISSION_GRANTED;
        int flags=PackageManager.GET_PERMISSIONS|(Build.VERSION.SDK_INT>=28?PackageManager.GET_SIGNING_CERTIFICATES:PackageManager.GET_SIGNATURES);
        List<PackageInfo> packages=pm.getInstalledPackages(flags);
        if(packages==null||packages.isEmpty()) throw new IOException("설치 앱 목록이 비어 있어 범위를 확인할 수 없습니다");
        Collections.sort(packages,(a,b)->a.packageName.compareTo(b.packageName));
        List<String> rootApps=new ArrayList<>(), sensitiveApps=new ArrayList<>(), missingSource=new ArrayList<>();
        int user=0, signaturesMissing=0, omitted=0;
        for(PackageInfo p:packages) {
            if(p.applicationInfo==null||p.packageName==null) { omitted++; continue; }
            ApplicationInfo ai=p.applicationInfo;
            JSONObject row=new JSONObject(); boolean system=(ai.flags&(ApplicationInfo.FLAG_SYSTEM|ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))!=0;
            row.put("packageName",p.packageName); row.put("label",label(ai)); row.put("system",system);
            row.put("versionCode",Build.VERSION.SDK_INT>=28?p.getLongVersionCode():(long)p.versionCode);
            row.put("versionName",p.versionName==null?"":p.versionName); row.put("enabled",ai.enabled);
            row.put("firstInstallTime",p.firstInstallTime);row.put("lastUpdateTime",p.lastUpdateTime);
            JSONArray signing=new JSONArray(); boolean signingReadable=true;
            try {
                Signature[] sigs=Build.VERSION.SDK_INT>=28?(p.signingInfo==null?null:p.signingInfo.getApkContentsSigners()):p.signatures;
                if(sigs==null||sigs.length==0) signingReadable=false;
                else for(Signature sig:sigs) signing.put(sha256(sig.toByteArray()));
            } catch(Exception e) { signingReadable=false; }
            row.put("signingSha256",signing); row.put("signingReadable",signingReadable);
            if(!signingReadable) signaturesMissing++;
            String installer=""; boolean installerReadable=false;
            try {
                String source=Build.VERSION.SDK_INT>=30?pm.getInstallSourceInfo(p.packageName).getInstallingPackageName():pm.getInstallerPackageName(p.packageName);
                if(source!=null) { installer=source; installerReadable=true; }
            } catch(Exception ignored) { }
            row.put("installer",installer); row.put("installerReadable",installerReadable);
            JSONArray granted=new JSONArray();
            if(p.requestedPermissions!=null&&p.requestedPermissionsFlags!=null)
                for(int i=0;i<Math.min(p.requestedPermissions.length,p.requestedPermissionsFlags.length);i++)
                    if((p.requestedPermissionsFlags[i]&PackageInfo.REQUESTED_PERMISSION_GRANTED)!=0&&SENSITIVE_PERMISSIONS.contains(p.requestedPermissions[i]))
                        granted.put(p.requestedPermissions[i]);
            row.put("grantedSensitivePermissions",granted); r.inventory.put(row);
            if(!system) {
                user++; if(granted.length()>0) sensitiveApps.add(label(ai)+" ("+p.packageName+")");
                if(!installerReadable) missingSource.add(p.packageName);
            }
            if(ROOT_PACKAGES.contains(p.packageName)) rootApps.add(label(ai)+" ("+p.packageName+")");
        }
        r.inventoryComplete=visibility&&omitted==0;
        r.evidence.put("inventoryScope","현재 사용자/프로필에서 OS가 노출한 설치 앱 메타데이터. QUERY_ALL_PACKAGES 가시성과 열거 성공 여부이며, 다른 사용자·업무/비공개 프로필·앱 내부 데이터·펌웨어·악성코드 검사 완전성을 뜻하지 않습니다.");
        r.evidence.put("packageVisibilityGranted",visibility); r.evidence.put("signatureMetadataMissing",signaturesMissing);
        add(r,"apps.inventory",APPS,"설치 앱·서명 목록",r.inventoryComplete?INFO:UNKNOWN,
                "앱 "+r.inventory.length()+"개 (사용자 앱 "+user+"개), 서명 정보 미확인 "+signaturesMissing+"개. 현재 프로필 기준입니다.",
                "서명 SHA-256은 APK 파일 전체 해시가 아닙니다. 앱 이름·서명만으로 악성 여부를 판정하지 않습니다.");
        add(r,"root.packages",ROOT,"알려진 루팅·후킹 관리 앱",!rootApps.isEmpty()?WARN:r.inventoryComplete?INFO:UNKNOWN,
                rootApps.isEmpty()?"보이는 앱 목록에서 등록된 관리 앱 패키지 이름이 발견되지 않았습니다.":join(rootApps,12),
                "관리 앱이 있다는 사실만으로 실제 루팅·악성코드·불법성을 확정하지 않습니다. 이름 변경·숨김 앱은 놓칠 수 있습니다.");
        add(r,"apps.sensitive",APPS,"민감 권한을 받은 사용자 앱",INFO,
                "선정한 민감 권한을 받은 사용자 앱 "+sensitiveApps.size()+"개. "+join(sensitiveApps,8),
                "카메라·마이크·문자·연락처·위치 등은 정상 앱에도 필요합니다. 목록에서 모르는 앱만 개별 확인하세요.");
        add(r,"apps.sources",APPS,"설치 출처 메타데이터",INFO,
                "설치 주체를 확인하지 못한 사용자 앱 "+missingSource.size()+"개. "+join(missingSource,8),
                "출처 미표시는 복원·ADB·수동 설치·스토어 정보 제한 등에서도 생깁니다. 악성 판정이나 공식 스토어 정품 확인에 해당하지 않습니다.");
    }

    private void inspectAccessibility(ScanReport r) throws Exception {
        AccessibilityManager manager=(AccessibilityManager)context.getSystemService(Context.ACCESSIBILITY_SERVICE);
        if(manager==null) throw new IOException("접근성 서비스 조회 불가");
        List<AccessibilityServiceInfo> enabled=manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
        if(enabled==null) throw new IOException("접근성 목록 응답 없음");
        List<String> names=new ArrayList<>(); JSONArray data=new JSONArray(); int unresolved=0;
        for(AccessibilityServiceInfo info:enabled) {
            if(info==null||info.getResolveInfo()==null||info.getResolveInfo().serviceInfo==null) { unresolved++; continue; }
            ServiceInfo si=info.getResolveInfo().serviceInfo; String name=si.packageName+"/"+si.name;
            names.add(name); data.put(name);
        }
        r.evidence.put("enabledAccessibilityServices",data); r.evidence.put("unresolvedAccessibilityServices",unresolved);
        add(r,"settings.accessibility",APPS,"사용 중인 접근성 서비스",!names.isEmpty()?WARN:unresolved>0?UNKNOWN:INFO,
                (names.isEmpty()?"현재 프로필의 조회 결과에서 이름을 확인한 활성 서비스가 없습니다.":join(names,12))
                        +(unresolved>0?"\n정보를 확인하지 못한 서비스 "+unresolved+"개.":""),
                "접근성 앱은 화면 내용 읽기·조작 권한을 가질 수 있습니다. 보조공학·자동화 앱도 사용하므로 본인이 허용했는지 확인하세요.");
    }

    private void inspectAdmins(ScanReport r) throws Exception {
        DevicePolicyManager manager=(DevicePolicyManager)context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        if(manager==null) throw new IOException("기기 관리자 조회 불가");
        List<ComponentName> enabled=manager.getActiveAdmins(); List<String> names=new ArrayList<>();
        if(enabled!=null) for(ComponentName component:enabled) names.add(component.flattenToShortString());
        r.evidence.put("activeDeviceAdmins",new JSONArray(names));
        add(r,"settings.admin",APPS,"활성 기기 관리자",names.isEmpty()?INFO:WARN,
                names.isEmpty()?"현재 프로필에 활성 기기 관리자가 보고되지 않았습니다.":join(names,12),
                "회사 관리·분실 방지 기능에도 사용됩니다. 모르는 관리자가 있으면 설정과 소유권을 확인하세요. 다른 프로필 관리까지 확인한 결과는 아닙니다.");
    }

    private void inspectNotifications(ScanReport r) throws Exception {
        String raw=Settings.Secure.getString(context.getContentResolver(),"enabled_notification_listeners");
        if(raw==null) throw new IOException("알림 접근 설정값 미제공");
        List<String> names=new ArrayList<>();
        for(String part:raw.split(":")) if(!part.trim().isEmpty()) names.add(part.trim());
        r.evidence.put("notificationListeners",new JSONArray(names));
        add(r,"settings.notifications",APPS,"알림 접근 앱",names.isEmpty()?INFO:WARN,
                names.isEmpty()?"현재 프로필에서 활성 알림 접근 항목이 보이지 않습니다.":join(names,12),
                "허용된 앱은 알림 내용을 볼 수 있습니다. 스마트워치·알림 관리 앱도 사용하므로 본인이 허용한 앱인지 확인하세요.");
    }

    private void inspectKeyboards(ScanReport r) throws Exception {
        InputMethodManager manager=(InputMethodManager)context.getSystemService(Context.INPUT_METHOD_SERVICE);
        if(manager==null) throw new IOException("입력기 목록 조회 불가");
        List<InputMethodInfo> enabled=manager.getEnabledInputMethodList();
        if(enabled==null) throw new IOException("입력기 목록 응답 없음");
        List<String> names=new ArrayList<>(); for(InputMethodInfo input:enabled) names.add(input.getPackageName());
        String current=Settings.Secure.getString(context.getContentResolver(),Settings.Secure.DEFAULT_INPUT_METHOD);
        r.evidence.put("enabledInputMethods",new JSONArray(names)); r.evidence.put("defaultInputMethod",current==null?JSONObject.NULL:current);
        add(r,"settings.keyboards",APPS,"사용 가능한 키보드",INFO,
                "기본 입력기="+shown(current)+". 활성 목록: "+join(names,12),
                "키보드는 입력 내용을 처리합니다. 본인이 선택한 입력기인지 확인하세요. 목록 등재만으로 악성이라고 판단하지 않습니다.");
    }

    private void inspectSwitch(ScanReport r,String id,String title,String key) {
        guard(r,id,APPS,title,()->{
            String value=Settings.Global.getString(context.getContentResolver(),key);
            r.evidence.put(key,value==null?JSONObject.NULL:value);
            boolean restrictedSetting=Settings.Global.ADB_ENABLED.equals(key)||Settings.Global.DEVELOPMENT_SETTINGS_ENABLED.equals(key)||"adb_wifi_enabled".equals(key);
            add(r,id,APPS,title,value==null?UNKNOWN:"1".equals(value)?WARN:"0".equals(value)&&!restrictedSetting?INFO:UNKNOWN,
                    "설정값="+shown(value)+". "+(restrictedSetting?"일부 Android는 일반 앱에 0을 고정 반환하거나 값을 제한하므로, 0만으로 꺼짐 또는 조치 성공을 확인할 수 없습니다. ":"")+"이 값은 설정 표시이며 실제 활성 연결을 모두 증명하지 않습니다.",
                    "개발·수리에도 쓰이는 기능입니다. 본인이 사용하지 않는다면 설정에서 확인하세요. 이 앱은 설정을 변경하지 않습니다.");
        });
    }

    private void inspectVpn(ScanReport r) throws Exception {
        ConnectivityManager manager=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if(manager==null) throw new IOException("네트워크 조회 불가");
        Network[] networks=manager.getAllNetworks(); int checked=0, unavailable=0, vpn=0;
        if(networks==null) throw new IOException("네트워크 목록 응답 없음");
        for(Network network:networks) {
            NetworkCapabilities caps=manager.getNetworkCapabilities(network);
            if(caps==null) { unavailable++; continue; }
            checked++; if(caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) vpn++;
        }
        r.evidence.put("visibleVpnNetworks",vpn); r.evidence.put("visibleNetworksChecked",checked);
        add(r,"network.vpn",NETWORK,"앱에 보이는 VPN 연결",vpn>0?WARN:unavailable>0||checked==0?UNKNOWN:INFO,
                "조회한 네트워크 "+checked+"개, VPN 전송 유형 "+vpn+"개, 정보 미제공 "+unavailable+"개.",
                "VPN은 회사망·광고 차단·보안 서비스에도 쓰입니다. 다른 프로필이나 이 앱에 보이지 않는 연결은 제외됩니다.");
    }

    private void inspectProxy(ScanReport r) throws Exception {
        ConnectivityManager manager=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if(manager==null) throw new IOException("프록시 조회 불가");
        ProxyInfo proxy=manager.getDefaultProxy();
        String detail=proxy==null?"현재 앱에 적용되는 기본 프록시가 보고되지 않았습니다.":proxy.toString();
        r.evidence.put("defaultProxy",proxy==null?JSONObject.NULL:detail);
        add(r,"network.proxy",NETWORK,"앱에 적용된 프록시",proxy==null?INFO:WARN,detail,
                "회사·학교망에서는 정상일 수 있습니다. 모르는 프록시라면 Wi-Fi 설정을 확인하세요. 개별 앱 내부 프록시·트래픽 내용은 검사하지 않습니다.");
    }

    private void inspectUserCertificates(ScanReport r) throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidCAStore"); store.load(null,null);
        Enumeration<String> aliases=store.aliases(); JSONArray user=new JSONArray(); int total=0, unknown=0;
        List<String> names=new ArrayList<>();
        while(aliases.hasMoreElements()) {
            String alias=aliases.nextElement(); total++;
            if(alias.startsWith("user:")) {
                Certificate cert=store.getCertificate(alias); JSONObject row=new JSONObject();
                row.put("alias",alias);
                if(cert!=null) row.put("sha256",sha256(cert.getEncoded()));
                if(cert instanceof X509Certificate) { String subject=((X509Certificate)cert).getSubjectX500Principal().getName(); row.put("subject",subject); names.add(subject); }
                else names.add(alias);
                user.put(row);
            } else if(!alias.startsWith("system:")) unknown++;
        }
        r.evidence.put("userCaCertificates",user); r.evidence.put("caStoreAliasCount",total);
        add(r,"network.user_ca",NETWORK,"사용자 설치 CA 인증서",user.length()>0?WARN:total==0||unknown>0?UNKNOWN:INFO,
                "AndroidCAStore에서 사용자 항목 "+user.length()+"개, 분류할 수 없는 항목 "+unknown+"개. "+join(names,6),
                "회사 보안망·개발용 인증서도 포함됩니다. 현재 프로필의 노출된 저장소만 보며, 비활성 인증서·다른 프로필·개별 앱 신뢰 저장소는 제외됩니다.");
    }

    private void addLimits(ScanReport r) {
        add(r,"coverage.malware",LIMITS,"악성코드 정밀 검사",UNKNOWN,
                "무료 백신·보안업체의 참조 해시로 APK와 직접 내부 파일을 자동 대조합니다. ClamAV 전체 엔진·동작 실행·미지 변종·중첩 압축 내부·다른 프로필은 검사하지 않습니다. 일치 없음은 악성코드 없음의 증명이 아닙니다.",
                "Google Play 스토어 → 프로필 → Play Protect에서 별도 검사를 실행하세요. 검사 통과도 모든 악성코드의 부재를 보증하지 않습니다.");
        add(r,"coverage.hardware",LIMITS,"물리적 하드웨어 변조",UNKNOWN,
                "보드·저장장치·통신 모듈·추가 부품·수리 이력은 일반 앱으로 검증할 수 없습니다.",
                "제조사 서비스센터의 모델별 하드웨어 진단·부품/보드 점검이 필요합니다. 키 증명은 물리 부품 전체의 정품 판정이 아닙니다.");
        add(r,"coverage.factory",LIMITS,"공장 출고 펌웨어와의 전체 일치",UNKNOWN,
                "공식 제조사 원본 이미지와 전체 파티션을 대조하지 않았습니다. 공장 초기화는 사용자 데이터 삭제이며 공식 OS 재설치와 같지 않습니다.",
                "동일 모델·지역·빌드의 제조사 공식 복구 절차나 서비스센터 확인이 필요합니다. 임의 펌웨어 플래싱은 하지 마세요.");
        add(r,"coverage.play_integrity",LIMITS,"Google Play Integrity 서버 검증",UNKNOWN,
                "이 앱에는 Play Integrity의 앱 등록·서버 검증이 연결되어 있지 않아 판정하지 않았습니다.",
                "오프라인 자기 점검 결과를 Google이 인증한 결과로 해석하지 마세요. 제조사 인증 여부는 Play 스토어 설정에서도 별도로 확인하세요.");
        add(r,"coverage.self_report",LIMITS,"검사 결과의 신뢰 경계",INFO,
                "모든 화면은 이 기기 안에서 실행한 검사 결과입니다. 운영체제 자체가 침해되면 값·앱 목록·실행 코드가 속을 수 있습니다.",
                "보고서에 개인정보가 포함될 수 있습니다. 공개하지 말고 신뢰할 수 있는 별도 기기나 전문가에게 필요한 부분만 전달하세요.");
    }

    private static Map<String,String> readProperties() throws Exception {
        Process process=new ProcessBuilder("/system/bin/getprop").redirectErrorStream(true).start();
        FutureTask<String> reader=new FutureTask<>(()->readStream(process.getInputStream(),256*1024));
        Thread thread=new Thread(reader,"refurbcheck-getprop"); thread.setDaemon(true); thread.start();
        try {
            if(!process.waitFor(1500,TimeUnit.MILLISECONDS)) throw new IOException("getprop 응답 시간 초과");
            if(process.exitValue()!=0) throw new IOException("getprop 읽기 거부 또는 실패");
            String output=reader.get(250,TimeUnit.MILLISECONDS); Map<String,String> result=new LinkedHashMap<>();
            for(String line:output.split("\n")) {
                int split=line.indexOf("]: [");
                if(line.startsWith("[")&&line.endsWith("]")&&split>1)
                    result.put(line.substring(1,split),line.substring(split+4,line.length()-1));
            }
            return result;
        } finally {
            process.destroy();
            if(process.isAlive()) process.destroyForcibly();
            reader.cancel(true);
            try { process.getInputStream().close(); } catch(IOException ignored) { }
            try { process.getOutputStream().close(); } catch(IOException ignored) { }
            try { process.getErrorStream().close(); } catch(IOException ignored) { }
        }
    }

    private static String readFile(String path,int limit) throws IOException {
        try(InputStream stream=new FileInputStream(path)) { return readStream(stream,limit); }
    }
    private static String readStream(InputStream stream,int limit) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream(); byte[] buffer=new byte[4096]; int n;
        while((n=stream.read(buffer))!=-1) { if(out.size()+n>limit) throw new IOException("읽기 크기 한도 초과"); out.write(buffer,0,n); }
        return new String(out.toByteArray(),StandardCharsets.UTF_8);
    }
    private static String sha256(byte[] bytes) throws Exception {
        byte[] hash=MessageDigest.getInstance("SHA-256").digest(bytes); StringBuilder s=new StringBuilder();
        for(byte b:hash) s.append(String.format(Locale.ROOT,"%02x",b&255)); return s.toString();
    }
    private String label(ApplicationInfo app) {
        try { return pm.getApplicationLabel(app).toString(); } catch(RuntimeException e) { return app.packageName; }
    }
    private static String value(Map<String,String> props,String key) { String v=props.get(key); return v==null?"":v.trim().toLowerCase(Locale.ROOT); }
    private static String shown(String s) { return s==null||s.isEmpty()?"확인 불가":s; }
    private static String join(List<String> list,int max) {
        StringBuilder s=new StringBuilder();
        for(int i=0;i<Math.min(list.size(),max);i++) { if(i>0)s.append("\n"); s.append(list.get(i)); }
        if(list.size()>max) s.append("\n외 ").append(list.size()-max).append("개 (전체 정보는 보고서 참고)");
        return s.toString();
    }
    private static void add(ScanReport r,String id,String category,String title,Finding.Status status,String detail,String action) {
        r.add(new Finding(id,category,title,status,detail,action));
    }
    private static void guard(ScanReport r,String id,String category,String title,Probe probe) {
        try { probe.run(); }
        catch(Exception|LinkageError e) { add(r,id,category,title,UNKNOWN,"확인하지 못했습니다: "+error(e),"읽기 제한·미지원·일시 오류는 정상이나 변조로 확정하지 않습니다."); }
    }
    private static String error(Throwable e) {
        String message=e.getMessage(); if(message==null) message="";
        if(message.length()>180) message=message.substring(0,180);
        return e.getClass().getSimpleName()+(message.isEmpty()?"":": "+message);
    }
    private static void update(Progress progress,String stage) {
        if(progress!=null) try { progress.update(stage); } catch(RuntimeException ignored) { }
    }
}

package io.github.refurbcheck;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.Instrumentation;
import android.app.UiAutomation;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;

import com.android.apksig.ApkVerifier;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Separate test APK, never a production component. Uses the real target APK's
 * classes and its installed APK bytes, with isolated catalog test storage.
 * Public benign APK fixtures are verified as files, never installed or run.
 */
public final class V14Instrumentation extends Instrumentation {
    private final JSONArray assertions = new JSONArray();
    private final JSONObject observations = new JSONObject();
    private JSONObject config;
    private IsolatedContext isolated;
    private long start;
    private volatile MainActivity latestActivity;
    private volatile MainActivity resumedActivity;
    private volatile int activityResumes;
    private boolean lifecycleStarted;

    @Override public void callActivityOnResume(Activity activity) {
        super.callActivityOnResume(activity);
        if (activity instanceof MainActivity) {
            latestActivity = (MainActivity) activity;
            resumedActivity = (MainActivity) activity;
            activityResumes++;
        }
    }

    @Override public void callActivityOnPause(Activity activity) {
        super.callActivityOnPause(activity);
        if (resumedActivity == activity) resumedActivity = null;
    }

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        start();
    }

    @Override public void onStart() {
        start = SystemClock.elapsedRealtime();
        Throwable failure = null;
        try {
            Context target = getTargetContext();
            config = new JSONObject(new String(asset("smoke-config.json", 32768), "UTF-8"));
            require("io.github.refurbcheck".equals(target.getPackageName()), "correct production target package");
            isolated = new IsolatedContext(target);
            phase("Live package metadata");
            ScanReport report = liveInventory(target);
            phase("Management and post-reset policy");
            ManagementInspection.inspect(target, report);
            JSONObject management = report.evidence.getJSONObject("management");
            require(!management.getBoolean("allDeviceProfilesVerified"), "management never claims complete cross-profile inspection");
            require(management.has("activeAdminEnumerationComplete") && management.has("roles"), "management completeness and roles are explicit");
            if (Build.VERSION.SDK_INT < 30)
                require("UNSUPPORTED_API".equals(management.getString("organizationOwnedQueryStatus")), "API26 organization-owned query guarded");
            else require(!"UNSUPPORTED_API".equals(management.getString("organizationOwnedQueryStatus")), "modern management API branch reached");
            FactoryResetPolicy.inspect(report, target.getPackageName(), true);
            ManifestRiskInspection.inspect(report, target.getPackageName());
            JSONObject self = report.inventory.getJSONObject(0);
            require("EXCLUDED_SELF".equals(self.getJSONObject("factoryResetPolicy").getString("outcome")), "post-reset policy excludes scanner itself");
            require(!report.evidence.getJSONObject("factoryResetPolicy").getBoolean("automaticRemovalAuthorized"), "policy does not authorize removal");
            require("EXCLUDED_SELF".equals(self.getJSONObject("capabilityRiskReview").getString("outcome")), "manifest risk review excludes scanner itself");
            observations.put("management", management);
            phase("Signed data channel and failed update retention");
            catalogUpdates();
            phase("Installed target APK hashing and signature verification");
            ApkInspection.inspect(isolated, report, null, new AtomicBoolean(false));
            require(self.getBoolean("apkInspectionComplete"), "installed target APK inspection completes");
            JSONArray files = self.getJSONArray("apkFiles");
            require(files.length() >= 1, "installed base APK is present");
            boolean baseSeen = false;
            for (int i = 0; i < files.length(); i++) {
                JSONObject file = files.getJSONObject(i);
                require("HASHED".equals(file.getString("hashStatus")) && file.getBoolean("fileStable"), "stable APK hash " + file.getString("fileId"));
                require("VERIFIED".equals(file.getString("signatureStatus")), "current runtime APK signature model " + file.getString("fileId"));
                require(file.getBoolean("signatureCryptographicVerified") && file.getBoolean("signerMetadataMatch"), "cryptographic signer matches PackageManager " + file.getString("fileId"));
                require(file.getInt("signatureCheckedApi") == Build.VERSION.SDK_INT, "runtime API is actually covered by APK model");
                JSONObject malware = file.getJSONObject("malware");
                require(malware.getBoolean("complete") && malware.getBoolean("archiveComplete")
                        && malware.getBoolean("wholeFileCompared") && malware.getBoolean("databaseLoaded")
                        && "COMPLETE".equals(malware.getString("state")), "whole-file and direct-entry malware scan completes " + file.getString("fileId"));
                require(malware.getInt("entriesHashed") > 0 && malware.getInt("entriesSkipped") == 0
                        && malware.getJSONArray("archiveIssues").length() == 0 && malware.getString("stopReason").isEmpty()
                        && "COMPLETE".equals(malware.getString("archiveStatus")), "APK direct entries scanned without skips or gaps " + file.getString("fileId"));
                require(file.getString("sha256").equals(malware.getString("outerApkSha256"))
                        && malware.getBoolean("fileStable") && !malware.getBoolean("matchesTruncated"), "malware evidence binds to stable exact APK " + file.getString("fileId"));
                if ("base".equals(file.getString("fileId"))) {
                    baseSeen = true;
                    require(config.getString("appSha256").equals(file.getString("sha256")), "scanner hashed the exact APK supplied to CI");
                }
            }
            require(baseSeen, "base APK identity checked against build artifact");
            require(!self.getBoolean("confirmedIoc") && self.getInt("malwareReferenceMatchCount") == 0, "benign own APK has no bundled reference match");
            require(!RemediationRules.eligible(self, target.getPackageName()) && !MalwareRemediationRules.eligible(self, target.getPackageName()), "neither remediation path can remove the scanner");
            observations.put("ownApkFiles", files);
            observations.put("malwareDatabase", report.evidence.opt("malwareDatabase"));
            require(!report.toJson().getBoolean("factoryOriginalVerified") && !report.toJson().getBoolean("malwareAbsenceVerified"), "scan JSON keeps unverified assurance domains false");
            phase("Exact original release APK malware archive coverage");
            originalReleaseApk();
            phase("Benign upstream v3.1 and ECDSA files on Android crypto providers");
            apkSignatureFixtures();
            phase("Attestation date-policy fixtures and live guarded probe");
            attestationFixtures(target);
            AttestationProbe.check(target, report);
            boolean externalLimit = false;
            for (Finding finding : report.findings) {
                if (finding.id.startsWith("attestation_"))
                    require(finding.status != Finding.Status.PASS, "attestation never makes a clean-device PASS claim: " + finding.id);
                if ("attestation_external".equals(finding.id)) externalLimit = finding.status == Finding.Status.UNKNOWN;
            }
            require(externalLimit, "live probe retains external-verification UNKNOWN");
            JSONObject attestation = report.evidence.optJSONObject("attestation");
            if (attestation != null) {
                require(!attestation.getBoolean("fullAttestationTrusted") && !attestation.getBoolean("offDeviceVerified"), "live probe does not certify itself");
                if (attestation.has("devicePropertiesRequested"))
                    require(attestation.getBoolean("devicePropertiesRequested") == (Build.VERSION.SDK_INT >= 31), "device-property API31 guard executed correctly");
                observations.put("attestationRequestStatus", attestation.optString("devicePropertiesRequestStatus", "UNAVAILABLE_BEFORE_REQUEST"));
                observations.put("attestationProbeError", attestation.optString("probeError", ""));
                observations.put("localAttestationChainValid", attestation.optBoolean("localChainValid", false));
            }
            phase("Automatic one-run UI, cancellation, rotation, task resume and fresh launcher");
            oneRunLifecycle(target);
        } catch (Throwable error) {
            failure = error;
        } finally {
            if (lifecycleStarted) {
                try {
                    onMain(() -> {
                        if (ScanSession.INSTANCE.running || ScanSession.INSTANCE.remediationBusy)
                            ScanSession.INSTANCE.cancel();
                        if (latestActivity != null && !latestActivity.isFinishing()) latestActivity.finish();
                    });
                    getUiAutomation().setRotation(UiAutomation.ROTATION_FREEZE_0);
                } catch (Throwable cleanupFailure) { if (failure == null) failure = cleanupFailure; }
            }
            if (isolated != null) {
                try { isolated.cleanup(); }
                catch (Exception cleanupFailure) { if (failure == null) failure = cleanupFailure; }
            }
        }
        JSONObject summary = new JSONObject();
        try {
            summary.put("schema", "refurbcheck-android-v14-smoke-v1").put("passed", failure == null)
                    .put("apiLevel", Build.VERSION.SDK_INT).put("androidRelease", Build.VERSION.RELEASE)
                    .put("assertionCount", assertions.length()).put("assertions", assertions)
                    .put("elapsedMillis", SystemClock.elapsedRealtime() - start).put("observations", observations)
                    .put("actualGalaxyTest", false).put("malwareDetectionRateMeasured", false)
                    .put("hardwareIntegrityCertified", false).put("fixtureApksInstalled", false);
            if (failure != null) {
                StringWriter trace = new StringWriter(); failure.printStackTrace(new PrintWriter(trace));
                String value = trace.toString();
                summary.put("failureType", failure.getClass().getName()).put("failureMessage", String.valueOf(failure.getMessage()))
                        .put("failureTrace", value.substring(0, Math.min(5000, value.length())));
            }
        } catch (Exception serializationFailure) {
            failure = serializationFailure;
        }
        Bundle result = new Bundle();
        result.putString("summary", summary.toString());
        result.putString("stream", "\nREFURBCHECK_SMOKE=" + summary + "\n");
        finish(failure == null ? 0 : 1, result);
    }

    /**
     * Uses the actual production Activity and Android task/configuration changes.
     * No test-only production endpoint, fake IOC, deletion target or granted
     * management permission is introduced. The emulator is disposable.
     */
    private void oneRunLifecycle(Context target) throws Exception {
        ScanSession session = ScanSession.INSTANCE;
        JSONObject lifecycle = new JSONObject();
        observations.put("oneRunLifecycle", lifecycle);
        require(getUiAutomation().setRotation(UiAutomation.ROTATION_FREEZE_0),
                "test display starts in natural orientation");
        lifecycleStarted = true;
        Activity opened = startActivitySync(launcherIntent(target));
        require(opened instanceof MainActivity && resumedActivity == opened,
                "real launcher Activity resumes without a start-button press");
        JSONObject launched = session.flowSnapshot();
        String firstRun = launched.getString("runId");
        require(!firstRun.isEmpty() && launched.getLong("startedAt") > 0
                && !"IDLE".equals(launched.getString("phase")), "launcher automatically creates a dated one-run cycle");
        require(session.automaticCatalogUpdates && session.automaticRemovalPrompts,
                "fresh-install update and post-reset confirmation preferences default on");
        conservativeFlow(launched, "launcher");
        lifecycle.put("launched", launched);

        // Stop the first cycle immediately, while its real UI still owns the
        // action. Cancellation must become authoritative before a worker exits.
        onMain(() -> {
            Button stop = findButton(latestActivity.getWindow().getDecorView(), "자동 점검 중단");
            require(stop != null && stop.isEnabled(), "real automatic-stop button is available");
            require(stop.performClick(), "actual automatic-stop button accepts the click");
        });
        JSONObject stopped = session.flowSnapshot();
        require(firstRun.equals(stopped.getString("runId")) && "CANCELLED".equals(stopped.getString("phase"))
                && stopped.getBoolean("cancelled") && stopped.getBoolean("cancellationRequested"),
                "stop immediately cancels the current cycle");
        onMain(() -> require(session.nextAutomaticRemoval(target.getPackageName()) == null,
                "cancelled cycle exposes no automatic removal candidate"));
        require(await(120000, () -> !session.running && !session.catalogBusy && !session.remediationBusy),
                "cancelled workers settle within the runtime deadline");
        stopped = session.flowSnapshot();
        require("CANCELLED".equals(stopped.getString("phase")) && stopped.getInt("removedCount") == 0,
                "worker completion cannot convert cancellation into completion or a removal");
        onMain(() -> require(session.pendingRemediation == null,
                "benign cancelled cycle never opens an uninstall confirmation"));
        conservativeFlow(stopped, "cancelled");
        lifecycle.put("stopped", stopped).put("stopBlocksAutomaticActions", true);

        // Rotate the actual display. A new Activity object and changed
        // orientation prove recreation, rather than calling lifecycle methods.
        MainActivity beforeRotation = resumedActivity;
        int beforeOrientation = beforeRotation.getResources().getConfiguration().orientation;
        require(getUiAutomation().setRotation(UiAutomation.ROTATION_FREEZE_90), "Android accepts display rotation");
        require(await(15000, () -> resumedActivity != null && resumedActivity != beforeRotation
                        && resumedActivity.getResources().getConfiguration().orientation != beforeOrientation),
                "real display rotation recreates the production Activity");
        JSONObject rotatedStopped = session.flowSnapshot();
        require(firstRun.equals(rotatedStopped.getString("runId"))
                        && "CANCELLED".equals(rotatedStopped.getString("phase")),
                "rotation preserves a cancelled cycle instead of restarting it");
        lifecycle.put("rotatedStopped", rotatedStopped);

        backgroundAndResume(target);
        JSONObject resumedStopped = session.flowSnapshot();
        require(firstRun.equals(resumedStopped.getString("runId"))
                        && "CANCELLED".equals(resumedStopped.getString("phase")),
                "returning from background preserves cancellation without a duplicate cycle");
        onMain(() -> require(session.nextAutomaticRemoval(target.getPackageName()) == null,
                "foreground return cannot restart stopped automatic actions"));
        lifecycle.put("resumedStopped", resumedStopped).put("backgroundResumePreservesCycle", true);

        // A launcher intent is deliberately different from task resumption.
        // SINGLE_TOP exercises MainActivity.onNewIntent with the retained
        // process/session. The first launch above already covers onCreate.
        onMain(() -> target.startActivity(launcherIntent(target).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)));
        require(await(15000, () -> !firstRun.equals(session.flowSnapshot().optString("runId"))),
                "a fresh launcher entry creates a new cycle after cancellation");
        JSONObject fresh = session.flowSnapshot();
        String secondRun = fresh.getString("runId");
        require(!secondRun.isEmpty() && !fresh.getBoolean("cancelled")
                        && fresh.getLong("startedAt") >= launched.getLong("startedAt"),
                "new launcher clears only the previous cycle cancellation");
        require(fresh.getInt("removedCount") == 0 && fresh.getInt("attemptedCount") == 0,
                "new launcher resets per-cycle removal counters");
        conservativeFlow(fresh, "fresh launcher");
        lifecycle.put("freshLauncher", fresh).put("freshLauncherStartsNewCycle", true);

        MainActivity activeBeforeRotation = resumedActivity;
        int activeOrientation = activeBeforeRotation.getResources().getConfiguration().orientation;
        require(getUiAutomation().setRotation(UiAutomation.ROTATION_FREEZE_0), "display can return to natural orientation");
        require(await(15000, () -> resumedActivity != null && resumedActivity != activeBeforeRotation
                        && resumedActivity.getResources().getConfiguration().orientation != activeOrientation),
                "second-cycle display rotation recreates the Activity");
        JSONObject rotatedFresh = session.flowSnapshot();
        require(secondRun.equals(rotatedFresh.getString("runId")) && rotatedFresh.getInt("scanCount") <= 1,
                "rotation preserves the new cycle without an extra initial scan");
        lifecycle.put("rotatedFresh", rotatedFresh).put("rotationPreservesCycle", true);
        backgroundAndResume(target);
        JSONObject resumedFresh = session.flowSnapshot();
        require(secondRun.equals(resumedFresh.getString("runId")) && resumedFresh.getInt("scanCount") <= 1,
                "foreground return preserves the new cycle without an extra initial scan");
        lifecycle.put("resumedFresh", resumedFresh);

        phase("Waiting for the automatically started benign-emulator cycle to finish");
        require(await(300000, () -> !session.running && !session.catalogBusy && !session.remediationBusy
                        && ("COMPLETE".equals(session.flowSnapshot().optString("phase"))
                        || "PAUSED".equals(session.flowSnapshot().optString("phase"))
                        || "CANCELLED".equals(session.flowSnapshot().optString("phase")))),
                "automatic cycle reaches a terminal result within the runtime deadline");
        JSONObject completed = session.flowSnapshot();
        require(secondRun.equals(completed.getString("runId")) && "COMPLETE".equals(completed.getString("phase"))
                        && completed.getBoolean("initialScanComplete") && completed.getLong("finishedAt") > 0,
                "benign-emulator automatic cycle reaches its final summary");
        require(completed.getInt("scanCount") == 1 && !completed.getBoolean("recheckPerformed"),
                "a no-removal cycle does not run an unnecessary duplicate full scan");
        require(completed.getInt("eligibleCount") == 0 && completed.getInt("remainingRemovalCount") == 0
                        && completed.getInt("removedCount") == 0 && completed.getInt("attemptedCount") == 0,
                "benign-emulator completion reports no invented removal or removal target");
        require(!completed.getString("networkUpdateState").isEmpty(),
                "final cycle records its real update outcome");
        conservativeFlow(completed, "completed");
        require(session.report != null, "automatic cycle publishes the real scan report");
        JSONObject report = session.report.toJson();
        require(!report.getBoolean("allRequiredDomainsVerified") && !report.getBoolean("factoryOriginalVerified")
                        && !report.getBoolean("malwareAbsenceVerified") && !report.getBoolean("physicalHardwareVerified"),
                "completed report never turns workflow completion into whole-device safety");
        JSONObject reportedFlow = report.getJSONObject("evidence").getJSONObject("oneRun");
        require(secondRun.equals(reportedFlow.getString("runId"))
                        && "COMPLETE".equals(reportedFlow.getString("phase")),
                "exported report binds the final one-run state to this cycle");
        lifecycle.put("completed", completed).put("completionKeepsAssuranceLimits", true)
                .put("realDisplayRotation", true).put("taskResumedWithoutLauncherIntent", true)
                .put("realStopButtonClicked", true).put("automaticFlowCompleted", true)
                .put("activityResumeCount", activityResumes).put("actualUninstallationPerformed", false)
                .put("reportVerdict", report.getString("verdict"))
                .put("allRequiredDomainsVerified", report.getBoolean("allRequiredDomainsVerified"));
        phase("Stop while a manual catalog operation is queued");
        manualCatalogCancellation(target, completed, report.getString("reportId"));
    }

    private void manualCatalogCancellation(Context target, JSONObject completed, String reportId) throws Exception {
        ScanSession session = ScanSession.INSTANCE;
        CountDownLatch parked = new CountDownLatch(1), release = new CountDownLatch(1);
        AtomicBoolean gateExpired = new AtomicBoolean(false);
        session.worker.execute(() -> {
            parked.countDown();
            try {
                if (!release.await(60, TimeUnit.SECONDS)) gateExpired.set(true);
            } catch (InterruptedException interrupted) {
                gateExpired.set(true);Thread.currentThread().interrupt();
            }
        });
        JSONObject requested;
        try {
            require(parked.await(5000, TimeUnit.MILLISECONDS), "test worker barrier is reached before manual update");
            onMain(() -> session.updateCatalog(target, null));
            onMain(() -> {
                require(session.catalogBusy, "manual catalog operation is queued as busy");
                Button stop = findButton(latestActivity.getWindow().getDecorView(), "자동 점검 중단");
                require(stop != null && stop.isEnabled() && stop.performClick(),
                        "actual Stop button cancels a queued manual catalog operation");
            });
            requested = session.flowSnapshot();
            require(!gateExpired.get() && requested.getBoolean("catalogUpdateCancellationRequested"),
                    "manual update has its own cancellation token before the worker can run");
            require("CANCELLED".equals(requested.getString("phase"))
                            && completed.getString("runId").equals(requested.getString("runId")),
                    "manual update cancellation retains the current cycle identity");
        } finally { release.countDown(); }
        require(await(15000, () -> !session.catalogBusy && !session.running && !session.remediationBusy),
                "cancelled catalog callback clears busy without starting a scan");
        JSONObject after = session.flowSnapshot();
        require("CANCELLED".equals(after.getString("phase"))
                        && completed.getString("runId").equals(after.getString("runId"))
                        && after.getInt("scanCount") == completed.getInt("scanCount")
                        && session.report != null && reportId.equals(session.report.reportId),
                "late catalog callback cannot replace the report or restart the cancelled cycle");
        JSONObject lastCheck = CatalogUpdateManager.lastCheck(target);
        require("CHECK_FAILED".equals(lastCheck.optString("state"))
                        && lastCheck.optString("error").contains("CANCELLED"),
                "manual catalog cancellation reaches the pre-download budget check");
        conservativeFlow(after, "manual catalog cancelled");
        observations.put("manualCatalogCancellation", new JSONObject()
                .put("before", completed).put("requested", requested).put("after", after)
                .put("realStopButtonClicked", true).put("cancellationTokenSetBeforeWorkerRelease", true)
                .put("lateCallbackDidNotRestart", true).put("reportIdentityPreserved", true)
                .put("preDownloadCancellationRecorded", true));
    }

    private static Intent launcherIntent(Context target) {
        return new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
                .setClass(target, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED);
    }

    private void backgroundAndResume(Context target) throws Exception {
        MainActivity foreground = resumedActivity;
        require(foreground != null, "production Activity is resumed before backgrounding");
        final int taskId = foreground.getTaskId();
        ActivityManager manager = (ActivityManager) target.getSystemService(Context.ACTIVITY_SERVICE);
        ActivityManager.AppTask selected = null;
        for (ActivityManager.AppTask task : manager.getAppTasks()) {
            if (task.getTaskInfo().id == taskId) selected = task;
        }
        require(selected != null, "own application task is available for ordinary resumption");
        ActivityManager.AppTask ownTask = selected;
        onMain(() -> require(foreground.moveTaskToBack(true), "own task moves to background"));
        require(await(15000, () -> resumedActivity == null), "Android pauses the backgrounded Activity");
        onMain(ownTask::moveToFront);
        require(await(15000, () -> resumedActivity != null && resumedActivity.getTaskId() == taskId),
                "Android resumes the existing task without a launcher intent");
    }

    private void conservativeFlow(JSONObject flow, String context) throws Exception {
        require(!flow.getBoolean("factoryOriginalVerified") && !flow.getBoolean("malwareAbsenceVerified")
                        && !flow.getBoolean("physicalHardwareVerified"),
                context + " flow does not certify factory state, malware absence or physical hardware");
        require(!flow.getBoolean("silentRemoval") && flow.getBoolean("systemRemovalApprovalRequired"),
                context + " flow keeps Android removal approval explicit");
    }

    private static Button findButton(View view, String label) {
        if (view instanceof Button) {
            Button button = (Button) view;
            if (label.contentEquals(button.getText()) || label.contentEquals(String.valueOf(button.getContentDescription())))
                return button;
        }
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            for (int index = 0; index < group.getChildCount(); index++) {
                Button result = findButton(group.getChildAt(index), label);
                if (result != null) return result;
            }
        }
        return null;
    }

    private interface CheckedAction { void run() throws Exception; }
    private interface Condition { boolean matches() throws Exception; }

    private void onMain(CheckedAction action) throws Exception {
        Throwable[] error = new Throwable[1];
        runOnMainSync(() -> {
            try { action.run(); } catch (Throwable failure) { error[0] = failure; }
        });
        if (error[0] instanceof Exception) throw (Exception) error[0];
        if (error[0] instanceof Error) throw (Error) error[0];
        if (error[0] != null) throw new RuntimeException(error[0]);
    }

    private static boolean await(long timeoutMillis, Condition condition) throws Exception {
        long deadline = SystemClock.elapsedRealtime() + timeoutMillis;
        do {
            if (condition.matches()) return true;
            SystemClock.sleep(50);
        } while (SystemClock.elapsedRealtime() < deadline);
        return condition.matches();
    }

    @SuppressWarnings("deprecation")
    private ScanReport liveInventory(Context target) throws Exception {
        PackageManager pm = target.getPackageManager();
        int flags = PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES
                | (Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES);
        PackageInfo info = pm.getPackageInfo(target.getPackageName(), flags);
        require(info.applicationInfo != null, "own ApplicationInfo accessible");
        require(config.getString("appSha256").equals(fileSha256(new File(info.applicationInfo.sourceDir))), "installed artifact SHA256 independently matches build");
        JSONObject row = new JSONObject().put("packageName", info.packageName).put("label", "RefurbCheck")
                .put("system", (info.applicationInfo.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0)
                .put("versionCode", Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : ((long) info.versionCode & 0xffffffffL))
                .put("versionName", info.versionName).put("lastUpdateTime", info.lastUpdateTime);
        PackageProvenance.collect(pm, info, row);
        ManifestRiskInspection.collectDeclared(info, row);
        require(row.getBoolean("signingReadable") && row.getJSONArray("signingSha256").length() == 1, "own signer collected on this runtime");
        JSONObject source = row.getJSONObject("installProvenance");
        require(!source.getBoolean("authenticatedDistribution"), "installer metadata not treated as authenticated distribution");
        require(!"ERROR".equals(source.getString("queryStatus")), "live install-source API does not throw");
        if (Build.VERSION.SDK_INT < 28) {
            require("LEGACY".equals(row.getString("signingMode")), "API26 uses legacy signer API");
            require("UNSUPPORTED_API".equals(row.getString("signingHistoryStatus")), "API26 unavailable signer history remains explicit");
        } else {
            require("SINGLE".equals(row.getString("signingMode")) && row.getBoolean("signingHistoryReadable"), "modern single-signer history is readable");
        }
        require(Build.VERSION.SDK_INT < 30 ? "LEGACY_API".equals(source.getString("queryStatus"))
                : "COLLECTED".equals(source.getString("queryStatus")), "install-source branch matches runtime API");
        require(Build.VERSION.SDK_INT < 33 ? "UNSUPPORTED_API".equals(source.getString("packageSourceStatus"))
                : "COLLECTED".equals(source.getString("packageSourceStatus")), "package-source API33 guard correct");
        require(Build.VERSION.SDK_INT < 34 ? "UNSUPPORTED_API".equals(source.getString("updateOwnerPackageStatus"))
                : !"UNSUPPORTED_API".equals(source.getString("updateOwnerPackageStatus"))
                && !"ERROR".equals(source.getString("updateOwnerPackageStatus")), "update-owner API34 guard correct");
        observations.put("installProvenance", source).put("signingMode", row.getString("signingMode"));
        ScanReport report = new ScanReport(); report.inventory.put(row);
        // This is a one-package sample, never a complete phone inventory.
        report.inventoryComplete = false;
        JSONObject device = new JSONObject().put("androidRelease", Build.VERSION.RELEASE).put("securityPatch", Build.VERSION.SECURITY_PATCH)
                .put("brand", Build.BRAND).put("device", Build.DEVICE).put("product", Build.PRODUCT)
                .put("manufacturer", Build.MANUFACTURER).put("model", Build.MODEL);
        report.evidence.put("device", device).put("runtimeTestScope", "INSTALLED_SCANNER_PACKAGE_ONLY");
        return report;
    }

    private void catalogUpdates() throws Exception {
        CatalogUpdateManager.Selection before = CatalogUpdateManager.current(isolated, budget());
        require("bundled".equals(before.origin), "isolated catalog starts with bundled data");
        require(before.snapshot.entryCount == MalwareCatalog.ENTRY_COUNT, "runtime bundled catalog verifies pinned count");
        byte[] bundle = asset("catalog-update.zip", CatalogUpdateVerifier.MAX_BUNDLE_BYTES);
        CatalogUpdateManager.Result installed = CatalogUpdateManager.importUpdate(isolated,
                new ByteArrayInputStream(bundle), new AtomicBoolean(false));
        require(installed.changed, "first signed catalog accepted in isolated store");
        CatalogUpdateManager.Selection accepted = CatalogUpdateManager.current(isolated, budget());
        require("signed-update".equals(accepted.origin) && accepted.snapshot.signedUpdate, "runtime uses authenticated active catalog");
        require(ApkEvidence.sha256(bundle).equals(accepted.snapshot.bundleSha256), "active catalog has exact signed bundle hash");
        File active = new File(isolated.getNoBackupFilesDir(), "catalog-updates/active.zip");
        String previousFile = fileSha256(active);
        boolean rejected = false;
        try {
            CatalogUpdateManager.importUpdate(isolated, new ByteArrayInputStream(
                    asset("catalog-invalid-signature.zip", CatalogUpdateVerifier.MAX_BUNDLE_BYTES)), new AtomicBoolean(false));
        } catch (IOException expected) {
            rejected = true;
            require(expected.getMessage() != null && expected.getMessage().contains("SIGNATURE"), "tampered signature rejected by crypto verification");
        }
        require(rejected, "tampered signed update cannot install");
        CatalogUpdateManager.Selection retained = CatalogUpdateManager.current(isolated, budget());
        require(retained.snapshot.sequence == accepted.snapshot.sequence
                && retained.snapshot.bundleSha256.equals(accepted.snapshot.bundleSha256), "failed update retains prior catalog identity");
        require(fileSha256(active).equals(previousFile), "failed update leaves active bytes unchanged");
        require("CHECK_FAILED".equals(CatalogUpdateManager.lastCheck(isolated).getString("state")), "failed update is visible in diagnostics");
        observations.put("catalog", retained.diagnostics());
    }

    private void originalReleaseApk() throws Exception {
        JSONObject expected = config.getJSONObject("productionRelease");
        File fixture = new File(isolated.directory, "original-production.apk");
        byte[] bytes = asset("original-production.apk", 8 * 1024 * 1024);
        try (FileOutputStream output = new FileOutputStream(fixture)) { output.write(bytes); }
        final ApkEvidence.Budget scanBudget = budget();
        CatalogUpdateManager.Selection selection = CatalogUpdateManager.current(isolated, scanBudget);
        require(selection.snapshot.database != null && selection.snapshot.signedUpdate && selection.error.isEmpty(),
                "original release scan uses authenticated selected catalog");
        MalwareEvidence.Hashes hashes;
        try (InputStream input = new FileInputStream(fixture)) {
            hashes = MalwareEvidence.hash(input, expected.getLong("sizeBytes"), scanBudget);
        }
        require(expected.getString("sha256").equals(hashes.sha256) && hashes.size == expected.getLong("sizeBytes"),
                "malware engine hashes exact original published release bytes");
        MalwareEvidence.ZipResult zip;
        try (final RandomAccessFile input = new RandomAccessFile(fixture, "r")) {
            final long length = input.length();
            zip = MalwareEvidence.scanZip(new MalwareEvidence.RandomSource() {
                @Override public long length() throws IOException { scanBudget.check(); return input.length(); }
                @Override public int read(long offset, byte[] buffer, int off, int count) throws IOException {
                    scanBudget.check();
                    if (offset < 0 || offset > length || off < 0 || count < 0 || off > buffer.length - count)
                        throw new IOException("ZIP_READ_RANGE");
                    if (count == 0) return 0;
                    int request = scanBudget.allowedRead((int) Math.min(count, length - offset));
                    if (request == 0) return -1;
                    input.seek(offset);
                    int read = input.read(buffer, off, request);
                    if (read > 0) scanBudget.readArchive(read);
                    return read;
                }
            }, selection.snapshot.database, new MalwareEvidence.ZipBudget(scanBudget));
        }
        int wholeMatches = selection.snapshot.database.match(hashes).size();
        observations.put("originalProductionApk", new JSONObject().put("sha256", hashes.sha256).put("sizeBytes", hashes.size)
                .put("catalogSha256", selection.snapshot.catalogSha256).put("archiveComplete", zip.complete)
                .put("archiveStatus", zip.status).put("entriesSeen", zip.entriesSeen).put("entriesHashed", zip.entriesHashed)
                .put("entriesSkipped", zip.entriesSkipped).put("archiveIssues", new JSONArray(zip.issues))
                .put("nestedArchivesNotExpanded", zip.nestedArchivesNotExpanded).put("referenceMatchCount", wholeMatches + zip.matchCount));
        require(zip.complete && "COMPLETE".equals(zip.status) && zip.stopReason.isEmpty()
                && zip.issues.isEmpty() && !zip.issuesTruncated && !zip.matchesTruncated,
                "original release direct-entry scan completes without gaps or truncated evidence");
        require(zip.entriesHashed > 0 && zip.entriesSkipped == 0
                && zip.entriesSeen == expected.getInt("entryCount")
                && zip.fileEntriesSeen == expected.getInt("fileEntryCount") && zip.entriesHashed == expected.getInt("fileEntryCount"),
                "original release hashes every direct file counted independently at build time");
        require(wholeMatches == 0 && zip.matchCount == 0, "benign original release has no selected reference match");
        require(expected.getString("sha256").equals(fileSha256(fixture)), "original release fixture bytes remain unchanged after scan");
    }

    private void apkSignatureFixtures() throws Exception {
        File good = copyFixture("v2-only-with-ecdsa-sha256-p256.apk");
        File bad = copyFixture("v2-only-with-ecdsa-sha256-p256-digest-mismatch.apk");
        File rotation = copyFixture("v31-rsa-2048_2-tgt-34-1-tgt-28.apk");
        File stripped = copyFixture("v31-block-stripped-v3-attr-value-33.apk");
        for (int api : new int[]{26, 36}) {
            require(verify(good, api).isVerified(), "Android provider verifies ECDSA fixture using API" + api + " model");
            require(!verify(bad, api).isVerified(), "Android provider rejects changed ECDSA content using API" + api + " model");
        }
        ApkVerifier.Result pre = verify(rotation, 32), post = verify(rotation, 36);
        require(pre.isVerified() && post.isVerified(), "v3.1 rotated APK verifies before and after target API");
        require(post.isVerifiedUsingV31Scheme(), "API36 model actually verifies the v3.1 block");
        require(pre.getSignerCertificates().size() == 1 && post.getSignerCertificates().size() == 1,
                "v3.1 selected signer is unambiguous");
        require(!ApkEvidence.sha256(pre.getSignerCertificates().get(0).getEncoded()).equals(
                ApkEvidence.sha256(post.getSignerCertificates().get(0).getEncoded())), "v3.1 rotation changes selected certificate");
        require(!verify(stripped, 36).isVerified(), "stripped v3.1 block rejected by API36 model");
    }

    private void attestationFixtures(Context target) throws Exception {
        List<X509Certificate> roots;
        try (InputStream input = target.getAssets().open("google_attestation_roots.pem")) { roots = certificates(input); }
        List<X509Certificate> factory = certificates(new ByteArrayInputStream(asset("google-v04-factory-blueline.pem", 32768)));
        List<X509Certificate> rkp = certificates(new ByteArrayInputStream(asset("google-v04-rkp-caiman.pem", 32768)));
        Date later = new Date(1893456000000L); // 2030-01-01T00:00:00Z, independent of emulator wall time.
        AttestationChain.Validation validation = AttestationChain.validateDetailed(factory, roots, later);
        require(validation.legacyFactoryExpiryApplied && validation.expiredFactoryCaCount == 2,
                "Android PKIX provider supports constrained official factory expiry fixture");
        boolean rejected = false;
        try { AttestationChain.validateDetailed(rkp, roots, later); }
        catch (java.security.GeneralSecurityException expected) { rejected = true; }
        require(rejected, "Android PKIX provider still rejects expired official RKP fixture");
    }

    private static List<X509Certificate> certificates(InputStream input) throws Exception {
        List<X509Certificate> result = new ArrayList<>();
        for (Certificate certificate : CertificateFactory.getInstance("X.509").generateCertificates(input))
            result.add((X509Certificate) certificate);
        return result;
    }
    private static ApkVerifier.Result verify(File apk, int api) throws Exception {
        return new ApkVerifier.Builder(apk).setMinCheckedPlatformVersion(api).setMaxCheckedPlatformVersion(api).build().verify();
    }
    private File copyFixture(String name) throws Exception {
        byte[] bytes = asset("apk-fixtures/" + name, 4 * 1024 * 1024);
        require(config.getJSONObject("fixtureSha256").getString(name).equals(ApkEvidence.sha256(bytes)), "exact upstream fixture bytes: " + name);
        File file = new File(isolated.directory, name);
        try (FileOutputStream output = new FileOutputStream(file)) { output.write(bytes); }
        return file;
    }
    private byte[] asset(String name, int maximum) throws IOException {
        try (InputStream input = getContext().getAssets().open(name)) {
            return CatalogUpdateVerifier.readBounded(input, maximum, budget());
        }
    }
    private static ApkEvidence.Budget budget() {
        return new ApkEvidence.Budget(new AtomicBoolean(false), 30000, 64L * 1024 * 1024, System::nanoTime);
    }
    private static String fileSha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[32768]; int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return ApkEvidence.hex(digest.digest());
    }
    private void require(boolean value, String label) throws Exception {
        assertions.put(new JSONObject().put("check", label).put("passed", value));
        if (!value) throw new AssertionError(label);
    }
    private void phase(String name) {
        Bundle progress = new Bundle(); progress.putString("stream", "RefurbCheck smoke: " + name + "\n");
        sendStatus(0, progress);
    }

    /** Catalog writes are redirected into a unique test cache directory/pref namespace. */
    private static final class IsolatedContext extends ContextWrapper {
        final File directory;
        final String prefix = "v14-smoke-" + UUID.randomUUID() + "-";
        final Set<String> preferenceNames = new HashSet<>();
        IsolatedContext(Context base) throws IOException {
            super(base);
            directory = new File(base.getCacheDir(), prefix + "data");
            if (!directory.mkdirs()) throw new IOException("Could not create isolated test directory");
        }
        @Override public File getNoBackupFilesDir() { return directory; }
        @Override public SharedPreferences getSharedPreferences(String name, int mode) {
            String isolatedName = prefix + name; preferenceNames.add(isolatedName);
            return getBaseContext().getSharedPreferences(isolatedName, mode);
        }
        void cleanup() throws IOException {
            for (String name : preferenceNames) {
                // Drain this namespace's pending apply() writes before deleting it.
                getBaseContext().getSharedPreferences(name, Context.MODE_PRIVATE).edit().clear().commit();
                getBaseContext().deleteSharedPreferences(name);
            }
            remove(directory);
        }
        private static void remove(File file) throws IOException {
            if (file.isDirectory()) {
                File[] children = file.listFiles();
                if (children == null) throw new IOException("Cannot enumerate own test directory");
                for (File child : children) remove(child);
            }
            if (!file.delete() && file.exists()) throw new IOException("Cannot delete own test file");
        }
    }
}

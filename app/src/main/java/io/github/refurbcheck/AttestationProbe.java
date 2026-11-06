package io.github.refurbcheck;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/** A local diagnostic, explicitly not a remote attestation service or a malware verdict. */
public final class AttestationProbe {
    private static final String CATEGORY = "하드웨어 키 증명";
    private static final String ROOT_ASSET = "google_attestation_roots.pem";
    private static final AtomicBoolean IN_FLIGHT = new AtomicBoolean(false);
    private AttestationProbe() { }

    /** Runs off the UI thread; this boundary also prevents broken OEM Keystore calls from blocking the scan. */
    public static void check(Context context, ScanReport report) {
        if (!IN_FLIGHT.compareAndSet(false, true)) {
            report.add(finding("attestation_busy", "키 증명 확인 대기", Finding.Status.UNKNOWN,
                    "이전 키 저장소 요청이 아직 끝나지 않았습니다. 동시에 새 요청을 만들지 않았습니다.",
                    "잠시 후 다시 검사하거나 기기를 재시작한 뒤 확인하세요."));
            addLimits(report);
            return;
        }
        final Context app = context.getApplicationContext();
        final Observations observations = new Observations(report);
        FutureTask<ScanReport> task = new FutureTask<>(() -> {
            ScanReport isolated = new ScanReport();
            perform(app, isolated, observations);
            return isolated;
        });
        Thread worker = new Thread(() -> {
            try { task.run(); } finally { IN_FLIGHT.set(false); }
        }, "RefurbCheck-attestation");
        worker.setDaemon(true);
        worker.start();
        try {
            ScanReport isolated = task.get(15, TimeUnit.SECONDS);
            report.findings.addAll(isolated.findings);
            if (isolated.evidence.has("attestation"))
                report.evidence.put("attestation", isolated.evidence.get("attestation"));
        } catch (TimeoutException exception) {
            task.cancel(true);
            report.add(finding("attestation_timeout", "키 증명 시간 초과", Finding.Status.UNKNOWN,
                    "기기의 키 저장소가 15초 안에 응답하지 않았습니다. 이를 변조 또는 정상으로 판정하지 않습니다.",
                    "시스템 업데이트·날짜 설정·네트워크 상태를 확인하고 다시 검사하세요. 앱은 직접 통신하지 않지만 시스템 키 발급에 네트워크가 필요할 수 있습니다."));
        } catch (InterruptedException exception) {
            task.cancel(true);
            Thread.currentThread().interrupt();
            report.add(finding("attestation_interrupted", "키 증명 중단", Finding.Status.UNKNOWN,
                    "검사가 중단되어 하드웨어 키 증명을 확인하지 못했습니다.", "다시 검사하세요."));
        } catch (Exception exception) {
            report.add(finding("attestation_unavailable", "키 증명 확인 불가", Finding.Status.UNKNOWN,
                    "인증서 생성 또는 결과 처리에 실패했습니다. " + exception.getClass().getSimpleName(),
                    "제조사 공식 점검 또는 신뢰하는 다른 기기의 검증을 이용하세요."));
        } finally {
            addLimits(report);
        }
    }

    private static void perform(Context context, ScanReport report, Observations observations) {
        String alias = "refurbcheck.ephemeral." + UUID.randomUUID();
        KeyStore keyStore = null;
        JSONObject evidence = new JSONObject();
        try {
            evidence.put("rootSource", "https://android.googleapis.com/attestation/root");
            evidence.put("rootsRetrievedOn", "2026-11-06");
            evidence.put("revocationChecked", false);
            evidence.put("offDeviceVerified", false);
            evidence.put("fullAttestationTrusted", false);
            evidence.put("localValidationClock", System.currentTimeMillis());
            evidence.put("validationScope", "offline-local-only");
            report.evidence.put("attestation", evidence);
            AppIdentity identityBefore = null;
            try { identityBefore = AppIdentity.read(context); }
            catch (Exception exception) { evidence.put("expectedApplicationReadError", exception.getClass().getSimpleName()); }
            byte[] challenge = new byte[32];
            new SecureRandom().nextBytes(challenge);
            evidence.put("challengeBase64", Base64.encodeToString(challenge, Base64.NO_WRAP));
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .setAttestationChallenge(challenge)
                    .build());
            KeyPair pair = generator.generateKeyPair();
            if (Thread.currentThread().isInterrupted()) return;
            Certificate[] rawChain = keyStore.getCertificateChain(alias);
            if (rawChain == null || rawChain.length == 0 || rawChain.length > 8)
                throw new IllegalStateException("Attestation certificate chain unavailable");
            List<X509Certificate> chain = new ArrayList<>();
            JSONArray pemChain = new JSONArray();
            JSONArray certificateDigests = new JSONArray();
            for (Certificate certificate : rawChain) {
                if (!(certificate instanceof X509Certificate)) throw new IllegalStateException("Non-X509 certificate");
                X509Certificate x509 = (X509Certificate) certificate;
                byte[] encoded = x509.getEncoded();
                if (encoded.length > DerReader.MAX_BYTES) throw new IllegalStateException("Oversize certificate");
                chain.add(x509);
                pemChain.put(pem(encoded));
                certificateDigests.put(sha256(encoded));
            }
            evidence.put("certificateChainPem", pemChain);
            evidence.put("certificateSha256", certificateDigests);
            evidence.put("generatedPublicKeySha256", sha256(pair.getPublic().getEncoded()));

            boolean chainValid = false;
            X509Certificate validatedAnchor = null;
            try {
                Collection<X509Certificate> roots = loadRoots(context);
                X509Certificate anchor = AttestationChain.validate(chain, roots, new Date());
                validatedAnchor = anchor;
                chainValid = true;
                evidence.put("trustedRootSha256", sha256(anchor.getEncoded()));
                report.add(finding("attestation_chain", "공개 루트와 인증서 연결 확인", Finding.Status.INFO,
                        "앱에 포함된 Google 루트(2026 회전 포함), 인증서 서명·기간·경로를 기기 내부에서 확인했습니다. 최신 폐기 여부는 확인하지 않았습니다.",
                        "인증서 결과는 참고 자료입니다. 다른 신뢰 기기에서 폐기 목록까지 확인해야 합니다."));
            } catch (Exception exception) {
                evidence.put("chainValidationError", exception.getClass().getSimpleName());
                report.add(finding("attestation_chain", "인증서 신뢰 확인 불가", Finding.Status.UNKNOWN,
                        "고정된 Google 루트에 대한 경로·서명·기간 검증을 완료하지 못했습니다. 비지원 제조사, 구형 인증서 만료, 잘못된 기기 날짜도 원인일 수 있습니다.",
                        "보고서를 신뢰할 수 있는 다른 기기에서 확인하세요. 만료나 미지원만으로 OS 변조라고 판단하지 마세요."));
            }
            evidence.put("localChainValid", chainValid);
            List<X509Certificate> revocationChain = new ArrayList<>(chain);
            boolean anchorAppended = validatedAnchor != null && !revocationChain.contains(validatedAnchor);
            if (anchorAppended) revocationChain.add(validatedAnchor);
            evidence.put("revocationAnchorAppended", anchorAppended);
            boolean knownRevoked = checkRevocations(context, revocationChain, chainValid, evidence, report);
            int selected = AttestationChain.attestationIndex(chain);
            if (selected < 0) throw new IllegalStateException("Key attestation extension missing");
            X509Certificate selectedCertificate = chain.get(selected);
            AttestationRecord record = AttestationRecord.parseExtension(
                    selectedCertificate.getExtensionValue(AttestationChain.ATTESTATION_OID));
            evidence.put("selectedCertificateIndex", selected);
            evidence.put("attestedPublicKeySha256", sha256(selectedCertificate.getPublicKey().getEncoded()));
            boolean challengeMatches = MessageDigest.isEqual(challenge, record.challenge);
            boolean keyMatches = MessageDigest.isEqual(pair.getPublic().getEncoded(), selectedCertificate.getPublicKey().getEncoded());
            boolean possession = false;
            if (keyMatches && challengeMatches) {
                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(pair.getPrivate());
                signer.update(challenge);
                byte[] signature = signer.sign();
                Signature verifier = Signature.getInstance("SHA256withECDSA");
                verifier.initVerify(selectedCertificate.getPublicKey());
                verifier.update(challenge);
                possession = verifier.verify(signature);
                evidence.put("challengeSignatureBase64", Base64.encodeToString(signature, Base64.NO_WRAP));
                evidence.put("challengeSignatureAlgorithm", "SHA256withECDSA");
            }
            evidence.put("challengeMatches", challengeMatches);
            evidence.put("generatedKeyMatches", keyMatches);
            evidence.put("keyPossessionVerified", possession);
            evidence.put("attestationVersion", record.attestationVersion);
            evidence.put("keymasterVersion", record.keymasterVersion);
            evidence.put("attestationSecurityLevel", record.attestationSecurityLevel);
            evidence.put("keymasterSecurityLevel", record.keymasterSecurityLevel);
            evidence.put("softwareRootPresent", record.softwareRootPresent);
            evidence.put("hardwareOsVersion", record.hardwareOsVersion == null ? JSONObject.NULL : record.hardwareOsVersion);
            evidence.put("hardwareOsPatchLevel", record.hardwareOsPatchLevel == null ? JSONObject.NULL : record.hardwareOsPatchLevel);
            evidence.put("vendorPatchLevel", record.vendorPatchLevel == null ? JSONObject.NULL : record.vendorPatchLevel);
            evidence.put("bootPatchLevel", record.bootPatchLevel == null ? JSONObject.NULL : record.bootPatchLevel);
            boolean bound = AttestationChecks.requestBound(challenge, pair.getPublic().getEncoded(),
                    selectedCertificate.getPublicKey().getEncoded(), record, possession);
            if (!bound) {
                report.add(finding("attestation_binding", "검사 요청과 키 증명 불일치", Finding.Status.WARN,
                        "새로 만든 요청값·공개키·키 소유 확인 중 하나가 인증서와 맞지 않습니다. 이번 인증서로 부팅 상태를 신뢰할 수 없습니다.",
                        "재검사 후 같은 결과가 나오면 신뢰할 수 있는 다른 기기로 증명 체인을 확인하세요."));
            }
            boolean appBound = reportApplicationBinding(context, identityBefore, record, chainValid && bound, evidence, report);
            boolean locallySupported = AttestationChecks.supportsLocalHardwareEvidence(
                    chainValid, bound, appBound, record.hardwareBacked() && record.recognizedVersionPair(), knownRevoked);
            JSONObject criteria = new JSONObject();
            criteria.put("chainValid", chainValid);
            criteria.put("freshLocalChallengeAndKeyBound", bound);
            criteria.put("applicationPackageVersionSignerBound", appBound);
            criteria.put("hardwareBacked", record.hardwareBacked());
            criteria.put("recognizedVersionPair", record.recognizedVersionPair());
            criteria.put("knownRevokedOrSuspended", knownRevoked);
            criteria.put("localHardwareEvidenceSupported", locallySupported);
            criteria.put("liveRevocationVerified", false);
            criteria.put("independentVerifierUsed", false);
            criteria.put("factoryFirmwareCompared", false);
            evidence.put("trustCriteria", criteria);
            report.add(finding("attestation_level", "키 증명 보안 수준", locallySupported ? Finding.Status.INFO : Finding.Status.UNKNOWN,
                    "인증서에 기록된 증명 수준: " + level(record.attestationSecurityLevel)
                            + ", 키 저장 수준: " + level(record.keymasterSecurityLevel)
                            + ". " + (locallySupported ? "이번 요청과의 연결을 기기 내부에서 확인했습니다." : "하드웨어 기반 증명으로 신뢰할 조건을 모두 확인하지 못했습니다."),
                    "TEE/StrongBox 표시는 물리 부품 전체의 정품 여부나 악성코드 부재를 뜻하지 않습니다."));
            reportBoot(record, locallySupported, evidence, report);
            reportCorrelations(record, locallySupported, observations, evidence, report);
        } catch (Exception exception) {
            try { evidence.put("probeError", exception.getClass().getSimpleName()); } catch (Exception ignored) { }
            report.add(finding("attestation_result", "키 증명 생성·해석 확인 불가", Finding.Status.UNKNOWN,
                    "이 기기에서 키 증명을 완성하지 못했습니다. 미지원, 시스템 키 발급 문제, 인증서 형식 차이 등이 원인일 수 있습니다. "
                            + exception.getClass().getSimpleName(),
                    "제조사 업데이트·날짜 설정을 확인한 뒤 재검사하세요. 확인 불가는 정상이나 변조 확정이 아닙니다."));
        } finally {
            if (keyStore != null) {
                try { keyStore.deleteEntry(alias); }
                catch (Exception exception) {
                    report.add(finding("attestation_cleanup", "임시 검사 키 정리 확인 불가", Finding.Status.INFO,
                            "앱 전용 키 저장소의 임시 키 삭제 요청이 완료되지 않았습니다.",
                            "앱을 삭제하면 이 앱의 키도 제거됩니다."));
                }
            }
        }
    }

    private static void reportBoot(AttestationRecord record, boolean locallySupported,
            JSONObject evidence, ScanReport report) throws Exception {
        AttestationRecord.RootOfTrust root = record.hardwareRoot;
        if (root == null) {
            report.add(finding("attestation_boot", "증명서의 부팅 상태 확인 불가", Finding.Status.UNKNOWN,
                    "하드웨어가 관리하는 영역의 RootOfTrust 정보가 없습니다. 소프트웨어 영역 값은 대체 증거로 사용하지 않습니다.",
                    "제조사 공식 부팅 모드 또는 외부 증명 도구로 확인하세요."));
            return;
        }
        JSONObject boot = new JSONObject();
        boot.put("deviceLocked", root.deviceLocked);
        boot.put("verifiedBootState", root.verifiedBootState);
        boot.put("verifiedBootKeyHex", hex(root.verifiedBootKey));
        boot.put("verifiedBootHashHex", root.verifiedBootHash == null ? JSONObject.NULL : hex(root.verifiedBootHash));
        evidence.put("hardwareRootOfTrust", boot);
        String description = "기록된 부트로더: " + (root.deviceLocked ? "잠김" : "잠금 해제")
                + ", Verified Boot: " + bootState(root.verifiedBootState) + ". ";
        if (!locallySupported) {
            report.add(finding("attestation_boot", "부팅 상태 기록 — 신뢰 확인 불가", Finding.Status.UNKNOWN,
                    description + "인증서 경로·요청·앱 신원·하드웨어 수준·알려진 폐기 여부 조건이 충족되지 않아 정상 판정에 사용하지 않습니다.",
                    "다른 신뢰 기기에서 인증서를 검증하세요."));
        } else if (root.deviceLocked && root.verifiedBootState == 0 && root.hasRecognizedBootDigests(record.attestationVersion)) {
            report.add(finding("attestation_boot", "로컬 증명 기록: 잠김·Verified", Finding.Status.INFO,
                    description + "기기 내부에서 확인한 범위의 증거입니다. 제조사 순정 이미지와의 해시 대조, 최신 폐기 조회, 외부 검증은 하지 않았습니다.",
                    "공장 출고 상태 보증으로 사용하지 마세요. 보고서의 부팅 키·해시는 검증된 동일 모델 기준과 별도로 비교할 수 있습니다."));
        } else if (root.verifiedBootState == 1) {
            report.add(finding("attestation_boot", "사용자 지정 부팅 신뢰 키 기록", Finding.Status.WARN,
                    description + "SelfSigned는 사용자가 설정한 신뢰 키로 검증한 상태입니다. 정당한 사용자 지정 OS일 수도 있습니다.",
                    "순정 OS로 판매된 기기라면 제조사 또는 판매자에게 확인하세요."));
        } else if (!root.deviceLocked || root.verifiedBootState == 2 || root.verifiedBootState == 3) {
            report.add(finding("attestation_boot", "부팅 잠금·검증 이상 징후", Finding.Status.ALERT,
                    description + "잠금 해제 또는 검증 실패가 기록되어 있습니다. 이 정보만으로 악성코드 감염을 확정하지 않습니다.",
                    "순정 상태가 필요한 경우 제조사 공식 점검·복구 절차로 확인하세요. 임의 재잠금은 하지 마세요."));
        } else {
            report.add(finding("attestation_boot", "부팅 키 정보 불완전", Finding.Status.UNKNOWN,
                    description + "Verified 상태에 필요한 부팅 키 해시를 확인하지 못했습니다.",
                    "외부 검증 또는 제조사 공식 점검이 필요합니다."));
        }
    }

    private static boolean reportApplicationBinding(Context context, AppIdentity before, AttestationRecord record,
            boolean requestAndChainValid, JSONObject evidence, ScanReport report) throws Exception {
        AppIdentity after = null;
        try { after = AppIdentity.read(context); }
        catch (Exception exception) { evidence.put("applicationRereadError", exception.getClass().getSimpleName()); }
        boolean stable = before != null && before.sameIdentity(after);
        AttestationChecks.ApplicationBinding result = AttestationChecks.bindApplication(record,
                before == null ? null : before.packageName, before == null ? -1 : before.versionCode,
                before == null ? null : before.signers, before != null && before.exclusiveUid);
        boolean matches = result == AttestationChecks.ApplicationBinding.MATCH && stable;
        JSONObject binding = new JSONObject();
        binding.put("matches", matches);
        binding.put("status", !stable && result == AttestationChecks.ApplicationBinding.MATCH
                ? "PACKAGE_CHANGED_OR_REREAD_UNAVAILABLE" : result.name());
        binding.put("expectationStableAcrossProbe", stable);
        binding.put("expectationSource", "PackageManager self-observation; not an independent identity authority");
        binding.put("attestationApplicationIdSource", "softwareEnforced; platform-supplied identity");
        binding.put("hardwareApplicationIdPresent", record.hardwareApplicationIdPresent);
        if (before != null) binding.put("expected", before.json());
        if (record.applicationId != null) {
            JSONArray packages = new JSONArray();
            for (AttestationRecord.PackageIdentity identity : record.applicationId.packages) {
                JSONObject item = new JSONObject(); item.put("packageName", identity.packageName); item.put("versionCode", identity.versionCode);
                packages.put(item);
            }
            JSONArray signers = new JSONArray();
            for (byte[] digest : record.applicationId.signerSha256) signers.put(hex(digest));
            binding.put("attestedPackages", packages); binding.put("attestedSignerSha256", signers);
        }
        evidence.put("applicationBinding", binding);
        report.add(finding("attestation_application", "검사 앱과 증명서의 신원 대조",
                matches && requestAndChainValid ? Finding.Status.INFO : Finding.Status.UNKNOWN,
                matches && requestAndChainValid
                        ? "이번 앱의 패키지명·설치 버전 코드·현재 서명 인증서 SHA-256 집합이 증명서 [709] 기록과 일치합니다. 검사 전후 앱 메타데이터도 일치했습니다."
                        : "증명서 [709]와 이번 앱의 패키지·버전·서명을 연결할 조건을 확인하지 못했습니다. 사유: " + binding.getString("status") + ".",
                "앱 신원은 Android가 제공한 값입니다. 공유 UID·서명 키 회전·구형 증명서는 확인 불가가 될 수 있으며, 일치도 순정 OS 증명이 아닙니다."));
        return matches;
    }

    private static boolean checkRevocations(Context context, List<X509Certificate> chain, boolean chainValid,
            JSONObject evidence, ScanReport report) throws Exception {
        JSONObject snapshot = new JSONObject();
        snapshot.put("source", AttestationRevocations.SOURCE);
        snapshot.put("liveQueryPerformed", false);
        snapshot.put("absenceProvesUnrevoked", false);
        snapshot.put("certificateCount", chain.size());
        evidence.put("revocationSnapshot", snapshot);
        try {
            byte[] body = readAsset(context, "attestation_revocations.json", AttestationRevocations.MAX_SNAPSHOT_BYTES);
            byte[] metadata = null;
            try { metadata = readAsset(context, "attestation_revocations_meta.json", 16384); }
            catch (IOException exception) { snapshot.put("metadataAvailable", false); }
            AttestationRevocations.Result result = AttestationRevocations.check(body, metadata, chain, System.currentTimeMillis());
            snapshot.put("checked", true); snapshot.put("entryCount", result.entryCount);
            snapshot.put("sha256", result.snapshotSha256);
            snapshot.put("metadataAvailable", metadata != null);
            snapshot.put("retrievedAtEpochMillis", result.retrievedAtEpochMillis);
            snapshot.put("maxAgeSeconds", result.maxAgeSeconds);
            snapshot.put("age", result.age.name());
            JSONArray matches = new JSONArray();
            for (AttestationRevocations.Match match : result.matches) {
                JSONObject item = new JSONObject(); item.put("certificateIndex", match.certificateIndex);
                item.put("serialHex", match.serial); item.put("status", match.status); item.put("reason", match.reason); matches.put(item);
            }
            snapshot.put("matches", matches);
            snapshot.put("knownRevokedOrSuspended", result.knownRevokedOrSuspended());
            if (result.knownRevokedOrSuspended()) {
                report.add(finding("attestation_revocation_snapshot", chainValid ? "알려진 폐기·중지 인증서 발견" : "폐기 목록 일련번호 일치 — 체인 미검증",
                        chainValid ? Finding.Status.ALERT : Finding.Status.UNKNOWN,
                        "앱에 포함한 공식 상태 목록 사본에서 체인 인증서 " + result.matches.size() + "개의 일련번호가 REVOKED 또는 SUSPENDED와 일치합니다. "
                                + (chainValid ? "이 체인의 부팅 정보를 정상 근거로 사용하지 않습니다." : "체인 자체가 검증되지 않아 이 일치의 출처는 확인 불가입니다."),
                        "신뢰하는 다른 기기에서 최신 상태 목록과 체인을 재검증하세요. 기기 제조사에 증명 키 관련 점검을 요청할 수 있습니다."));
            } else {
                report.add(finding("attestation_revocation_snapshot", "동봉 폐기 목록 사본 대조", Finding.Status.INFO,
                        "사본의 " + result.entryCount + "개 항목에서 이번 체인 일련번호의 일치를 찾지 못했습니다. 사본 나이 상태: " + result.age.name() + ". 최신 폐기 여부를 통과했다는 뜻은 아닙니다.",
                        "최신 폐기 상태는 다른 신뢰 기기의 공식 검증기에서 확인하세요."));
            }
            if (result.age != AttestationRevocations.Age.CURRENT_BY_LOCAL_CLOCK)
                report.add(finding("attestation_revocation_age", "폐기 목록 사본 최신성 확인 불가", Finding.Status.UNKNOWN,
                        "포함된 사본은 유효 캐시 기간이 지났거나 수집 시각·기기 시각을 확인할 수 없습니다. 알려진 일치는 유지하고 미일치를 정상 근거로 사용하지 않습니다.",
                        "최신 앱의 목록 또는 별도 신뢰 기기의 최신 공식 목록으로 다시 확인하세요."));
            return result.knownRevokedOrSuspended();
        } catch (Exception exception) {
            snapshot.put("checked", false); snapshot.put("error", exception.getClass().getSimpleName());
            report.add(finding("attestation_revocation_snapshot", "동봉 폐기 목록 대조 확인 불가", Finding.Status.UNKNOWN,
                    "상태 목록 사본 또는 메타데이터를 읽거나 검증하지 못했습니다. " + exception.getClass().getSimpleName(),
                    "최신 공식 목록을 신뢰하는 다른 기기에서 조회하세요."));
            return false;
        }
    }

    private static void reportCorrelations(AttestationRecord record, boolean locallySupported, Observations observations,
            JSONObject evidence, ScanReport report) throws Exception {
        List<AttestationChecks.Comparison> comparisons = AttestationChecks.correlate(record,
                observations.androidRelease, observations.securityPatch, observations.properties);
        JSONArray rows = new JSONArray();
        int comparable = 0, mismatches = 0;
        StringBuilder mismatchFields = new StringBuilder();
        for (AttestationChecks.Comparison comparison : comparisons) {
            JSONObject row = new JSONObject(); row.put("field", comparison.field); row.put("attested", comparison.attested);
            row.put("osObserved", comparison.observed); row.put("state", comparison.state.name()); row.put("comparison", comparison.explanation);
            rows.put(row);
            if (comparison.state != AttestationChecks.ComparisonState.NOT_COMPARABLE) comparable++;
            if (comparison.state == AttestationChecks.ComparisonState.MISMATCH) {
                if (mismatches++ > 0) mismatchFields.append(", ");
                mismatchFields.append(comparison.field);
            }
        }
        JSONObject result = new JSONObject(); result.put("comparisons", rows);
        result.put("comparable", comparable); result.put("mismatches", mismatches);
        result.put("localHardwareEvidenceSupported", locallySupported);
        evidence.put("crossChecks", result);
        report.add(finding("attestation_correlation", "증명서와 OS 관측값 교차 확인",
                !locallySupported || comparable == 0 ? Finding.Status.UNKNOWN : mismatches > 0 ? Finding.Status.WARN : Finding.Status.INFO,
                "형식과 자료가 맞아 비교한 항목 " + comparable + "/" + comparisons.size() + "개, 차이 " + mismatches + "개. "
                        + (mismatches > 0 ? "차이 항목: " + mismatchFields + ". " : "")
                        + (locallySupported ? "차이는 추가 확인 근거이며 악성코드 확정이 아닙니다." : "증명서의 신뢰 조건이 부족하여 비교값을 정상 근거로 사용하지 않습니다."),
                "업데이트 후 재부팅하여 재검사하고, 차이가 지속되면 제조사 공식 점검과 외부 증명 검증을 이용하세요."));
        if (comparable < comparisons.size()) report.add(finding("attestation_correlation_coverage", "일부 증명 교차 확인 자료 부족", Finding.Status.UNKNOWN,
                "값이 없거나 날짜·버전 형식이 달라 " + (comparisons.size() - comparable) + "개 항목은 비교하지 못했습니다. 읽을 수 없는 값은 일치로 계산하지 않습니다.",
                "보고서 crossChecks에서 비교하지 못한 항목과 원래 값을 확인하세요."));
    }

    private static byte[] readAsset(Context context, String name, int maximum) throws IOException {
        try (InputStream input = context.getAssets().open(name); ByteArrayOutputStream result = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192]; int count;
            while ((count = input.read(buffer)) >= 0) {
                if (Thread.currentThread().isInterrupted()) throw new IOException("Attestation interrupted");
                if (count > maximum - result.size()) throw new IOException("Attestation asset too large");
                result.write(buffer, 0, count);
            }
            return result.toByteArray();
        }
    }

    private static final class Observations {
        final String androidRelease, securityPatch;
        final Map<String, String> properties = new HashMap<>();
        Observations(ScanReport report) {
            JSONObject device = report.evidence.optJSONObject("device");
            androidRelease = device == null ? "" : device.optString("androidRelease", "");
            securityPatch = device == null ? "" : device.optString("securityPatch", "");
            JSONObject boot = report.evidence.optJSONObject("bootProperties");
            String[] names = {"ro.boot.verifiedbootstate", "ro.boot.flash.locked", "ro.boot.vbmeta.device_state",
                    "ro.vendor.build.security_patch", "ro.bootimage.build.version.security_patch"};
            for (String name : names) properties.put(name, boot == null ? "" : boot.optString(name, ""));
        }
    }

    private static final class AppIdentity {
        String packageName;
        long versionCode, lastUpdateTime;
        boolean exclusiveUid, signingHistoryPresent;
        final List<byte[]> signers = new ArrayList<>();
        @SuppressWarnings("deprecation")
        static AppIdentity read(Context context) throws Exception {
            PackageManager pm = context.getPackageManager();
            PackageInfo own = pm.getPackageInfo(context.getPackageName(), Build.VERSION.SDK_INT >= 28
                    ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES);
            if (!context.getPackageName().equals(own.packageName)) throw new IllegalStateException("Unexpected app package identity");
            AppIdentity result = new AppIdentity();
            result.packageName = own.packageName;
            result.versionCode = Build.VERSION.SDK_INT >= 28 ? own.getLongVersionCode() : ((long) own.versionCode & 0xffffffffL);
            result.lastUpdateTime = own.lastUpdateTime;
            String[] names = pm.getPackagesForUid(context.getApplicationInfo().uid);
            result.exclusiveUid = names != null && names.length == 1 && context.getPackageName().equals(names[0]);
            android.content.pm.Signature[] signatures;
            if (Build.VERSION.SDK_INT >= 28) {
                signatures = own.signingInfo == null ? null : own.signingInfo.getApkContentsSigners();
                result.signingHistoryPresent = own.signingInfo != null && !own.signingInfo.hasMultipleSigners()
                        && own.signingInfo.getSigningCertificateHistory() != null && own.signingInfo.getSigningCertificateHistory().length > 1;
            } else signatures = own.signatures;
            if (signatures == null || signatures.length == 0 || signatures.length > 32)
                throw new IllegalStateException("Current app signing certificates unavailable");
            for (android.content.pm.Signature signature : signatures)
                result.signers.add(MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()));
            return result;
        }
        boolean sameIdentity(AppIdentity other) {
            return other != null && packageName.equals(other.packageName) && versionCode == other.versionCode
                    && lastUpdateTime == other.lastUpdateTime && exclusiveUid == other.exclusiveUid
                    && AttestationChecks.sameDigestSet(signers, other.signers);
        }
        JSONObject json() throws Exception {
            JSONObject value = new JSONObject(); value.put("packageName", packageName); value.put("versionCode", versionCode);
            value.put("lastUpdateTime", lastUpdateTime); value.put("exclusiveUid", exclusiveUid);
            value.put("signingHistoryPresent", signingHistoryPresent);
            JSONArray digests = new JSONArray(); for (byte[] signer : signers) digests.put(hex(signer));
            value.put("currentSignerSha256", digests); return value;
        }
    }

    private static Collection<X509Certificate> loadRoots(Context context) throws Exception {
        List<X509Certificate> roots = new ArrayList<>();
        try (InputStream input = context.getAssets().open(ROOT_ASSET)) {
            for (Certificate certificate : CertificateFactory.getInstance("X.509").generateCertificates(input))
                roots.add((X509Certificate) certificate);
        }
        if (roots.size() != 2) throw new IllegalStateException("Pinned attestation roots unavailable");
        return roots;
    }

    private static void addLimits(ScanReport report) {
        report.add(finding("attestation_external", "외부 검증·최신 인증서 폐기 조회 미실시", Finding.Status.UNKNOWN,
                "이 앱은 네트워크 권한 없이 기기 안에서 검사합니다. 동봉 폐기 목록 사본은 최신 조회를 대신하지 않습니다. 침해된 OS는 관측·검증 결과를 속일 수 있으며, 새로 폐기된 키도 사본 대조를 통과할 수 있습니다.",
                "더 높은 신뢰가 필요하면 다른 신뢰 기기에서 Auditor 또는 공식 Android Key Attestation 검증기와 최신 폐기 목록으로 확인하세요."));
    }
    private static Finding finding(String id, String title, Finding.Status status, String detail, String action) {
        return new Finding(id, CATEGORY, title, status, detail, action);
    }
    private static String level(int value) { return value == 1 ? "TEE" : value == 2 ? "StrongBox" : "Software"; }
    private static String bootState(int value) {
        switch (value) { case 0: return "Verified"; case 1: return "SelfSigned"; case 2: return "Unverified"; case 3: return "Failed"; default: return "알 수 없음"; }
    }
    private static String sha256(byte[] bytes) throws Exception { return hex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static String hex(byte[] bytes) {
        char[] digits = "0123456789abcdef".toCharArray();
        char[] result = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) { result[i * 2] = digits[(bytes[i] >>> 4) & 15]; result[i * 2 + 1] = digits[bytes[i] & 15]; }
        return new String(result);
    }
    private static String pem(byte[] encoded) {
        String base64 = Base64.encodeToString(encoded, Base64.NO_WRAP);
        StringBuilder value = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < base64.length(); i += 64) value.append(base64, i, Math.min(i + 64, base64.length())).append('\n');
        return value.append("-----END CERTIFICATE-----\n").toString();
    }
}

package io.github.refurbcheck;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Read-only comparison of untrusted reports. Never feeds a remediation action or changes a scan. */
public final class BaselineComparator {
    private static final String SELF = "io.github.refurbcheck";
    private static final int MAX_DETAIL = 24000;
    private BaselineComparator() { }

    public static String compare(JSONObject reference, JSONObject current) {
        String referenceSchema = schema(reference), currentSchema = schema(current);
        boolean fileSchema = "refurbcheck-report-v2".equals(referenceSchema) && "refurbcheck-report-v2".equals(currentSchema);
        JSONObject a = device(reference), b = device(current);
        StringBuilder out = new StringBuilder("선택한 참고 보고서와 현재 결과의 차이입니다. 참고 파일의 진위·작성 기기·공장 출고 상태는 인증하지 않습니다. 정상 업데이트도 차이로 표시됩니다. 이 비교는 읽기 전용이며, 가져온 보고서로 앱 삭제나 설정 변경을 실행하지 않습니다.\n\n");
        for (String key : new String[]{"manufacturer", "brand", "model", "device", "product"}) {
            String before = knownString(a, key), after = knownString(b, key);
            if (before == null || after == null)
                return out + "기기 식별 정보가 부족하여 비교를 중단했습니다: " + key;
            if (!before.equals(after))
                return out + "서로 다른 모델/제품의 보고서이므로 비교를 중단했습니다.\n" + key + ": " + display(before, 400) + " → " + display(after, 400);
        }
        int changes = 0;
        for (String key : new String[]{"fingerprint", "securityPatch", "androidRelease", "apiLevel", "buildType", "buildTags"}) {
            String before = metadata(a, key), after = metadata(b, key);
            if (before == null || after == null) out.append(key).append(": 자료 부족\n");
            else if (!before.equals(after)) {
                changes++;
                out.append(key).append(":\n  이전 ").append(display(before, 800)).append("\n  현재 ").append(display(after, 800)).append('\n');
            }
        }
        String oldFingerprint = knownString(a, "fingerprint"), newFingerprint = knownString(b, "fingerprint");
        boolean sameFingerprint = oldFingerprint != null && oldFingerprint.equals(newFingerprint);
        Map<String, JSONObject> old = packages(reference.opt("inventory")), now = packages(current.opt("inventory"));
        if (!trueValue(reference, "inventoryComplete") || !trueValue(current, "inventoryComplete"))
            out.append("\n앱 목록 수집이 불완전합니다. 추가/누락 표시는 수집된 목록 안에서만 비교합니다. 완료된 공통 패키지의 APK만 별도로 비교할 수 있습니다.\n");
        if (!fileSchema) out.append("\n이전 v1 형식이 포함되어 APK 파일 내용은 비교하지 않습니다. v1의 서명 다이제스트는 APK 파일 SHA-256이 아닙니다.\n");
        int added = 0, removed = 0, changed = 0, unknown = 0, versionUnknown = 0;
        int forwardRotations = 0, backwardRotations = 0, lineageConflicts = 0;
        int contentEqual = 0, contentDifferent = 0, unexplained = 0, distributionChanged = 0, contentUnknown = 0;
        StringBuilder details = new StringBuilder();
        List<String> names = new ArrayList<>(now.keySet()); Collections.sort(names);
        for (String name : names) {
            if (SELF.equals(name)) continue;
            JSONObject n = now.get(name), o = old.get(name);
            if (o == null) { added++; append(details, "추가: " + name); continue; }
            SignatureLineage.Relation relation = SignatureLineage.compare(o, n);
            if (relation == SignatureLineage.Relation.UNKNOWN) { unknown++; append(details, "서명 확인 불가: " + name); }
            else if (relation != SignatureLineage.Relation.SAME_SIGNERS) {
                changed++;
                if (relation == SignatureLineage.Relation.FORWARD_ROTATION_REPORTED) {
                    forwardRotations++;
                    append(details, "서명 교체 이력 연결 (자기 보고): " + name
                            + " (현재 보고서의 단일 서명 이력에 이전 키가 포함됩니다. 정상 키 교체 가능성을 구분하며, 보고서 진위·APK 서명·앱 안전성을 인증하지 않습니다.)");
                } else if (relation == SignatureLineage.Relation.BACKWARD_ROTATION_REPORTED) {
                    backwardRotations++;
                    append(details, "서명 이력상 이전 키로 변경: " + name + " (이전 보고서에 기록된 과거 키입니다. 역방향 변경을 정상 새 키 교체로 간주하지 않습니다.)");
                } else if (relation == SignatureLineage.Relation.CONFLICTING_LINEAGE_REPORTED) {
                    lineageConflicts++;
                    append(details, "서명 이력 모순: " + name + " (두 보고서의 키 교체 순서가 연결되지 않아 정상 교체로 분류하지 않습니다.)");
                } else append(details, "서명 차이: " + name + " (정상 서명 교체 여부도 확인)");
            }
            Long ov = integer(o.opt("versionCode")), nv = integer(n.opt("versionCode"));
            if (ov == null || nv == null) { versionUnknown++; append(details, "버전 확인 불가: " + name); }
            else if (!ov.equals(nv)) {
                changed++;
                append(details, "버전 차이: " + name + "  " + versionName(o, ov) + " → " + versionName(n, nv));
            }
            FileSet oldFiles = files(o, fileSchema), newFiles = files(n, fileSchema);
            if (!oldFiles.complete || !newFiles.complete) {
                contentUnknown++;
                append(details, "APK 내용 확인 불가: " + name + " (이전: " + oldFiles.reason + "; 현재: " + newFiles.reason + ")");
                continue;
            }
            boolean sameFileSet = oldFiles.files.keySet().equals(newFiles.files.keySet());
            if (!sameFileSet) {
                distributionChanged++;
                append(details, "APK 구성 차이: " + name + " (base/split 식별자 집합이 다릅니다. 언어·기기 구성·배포 split 변화일 수 있어 동일 구성의 내용 차이로 분류하지 않습니다.)");
                append(details, "  이전 파일 " + fileIds(oldFiles) + " / 현재 파일 " + fileIds(newFiles));
            }
            List<String> different = new ArrayList<>(); boolean inconsistent = false;
            for (String id : oldFiles.files.keySet()) {
                FileHash before = oldFiles.files.get(id), after = newFiles.files.get(id);
                if (after == null) continue;
                if (!before.sha256.equals(after.sha256)) different.add(id);
                else if (before.size != after.size) inconsistent = true;
            }
            if (inconsistent) {
                contentUnknown++;
                append(details, "APK 내용 확인 불가: " + name + " (같은 SHA-256에 서로 다른 파일 크기가 기록되어 보고서가 모순됩니다.)");
                continue;
            }
            if (different.isEmpty()) { if (sameFileSet) contentEqual++; continue; }
            contentDifferent++; Collections.sort(different);
            boolean sameVersion = ov != null && ov.equals(nv);
            if (sameVersion && sameFingerprint && sameFileSet) {
                unexplained++;
                append(details, "동일 버전·펌웨어 지문의 APK 내용 차이: " + name + " (" + different.size() + "개 파일; 보고서만으로 원인을 설명할 수 없어 추가 확인이 필요합니다.)");
            } else {
                append(details, "APK 내용 차이 — 비교 조건 다름/미확인: " + name + " (" + different.size()
                        + "개 파일; 버전·펌웨어 지문·파일 구성이 같다고 확인되지 않았습니다. 정상 업데이트·배포 경로·기기 구성 변화도 원인일 수 있습니다.)");
            }
            int shown = Math.min(different.size(), 8);
            for (int i = 0; i < shown; i++) {
                String id = different.get(i);
                append(details, "  " + id + ": " + oldFiles.files.get(id).sha256 + " → " + newFiles.files.get(id).sha256);
            }
            if (shown < different.size()) append(details, "  추가 " + (different.size() - shown) + "개 파일 차이는 원본 보고서에서 확인하세요.");
        }
        names = new ArrayList<>(old.keySet()); Collections.sort(names);
        for (String name : names) if (!SELF.equals(name) && !now.containsKey(name)) { removed++; append(details, "목록에서 누락: " + name); }
        out.append("\n기기 정보 차이 ").append(changes).append("건\n앱 추가 ").append(added).append("개 · 누락 ").append(removed)
                .append("개 · 버전/서명 차이 ").append(changed).append("건 · 서명 확인 불가 ").append(unknown).append("개\n")
                .append("버전 확인 불가 ").append(versionUnknown).append("개\n")
                .append("보고된 서명 교체 이력 연결 ").append(forwardRotations).append("건 · 이전 키 방향 변경 ").append(backwardRotations)
                .append("건 · 서명 이력 모순 ").append(lineageConflicts).append("건\n")
                .append("APK 내용 비교: 보고된 해시 동일 ").append(contentEqual).append("개 앱 · 내용 차이 ").append(contentDifferent)
                .append("개 앱 · 구성 차이 ").append(distributionChanged).append("개 앱 · 확인 불가 ").append(contentUnknown).append("개 앱\n")
                .append("동일 버전·펌웨어 지문·파일 구성의 원인 미확인 내용 차이 ").append(unexplained).append("개 앱\n\n").append(details);
        out.append("\nAPK 비교는 두 보고서가 모두 완전·안정적으로 해시를 수집했다고 기록한 공통 패키지만 대상으로 합니다. 같은 버전이라도 정상 배포 경로·재패키징·설정 split 차이가 있을 수 있으며, 차이를 악성코드나 불법 개조로 확정하지 않습니다.");
        out.append("\n차이가 없더라도 APK 내용 전체·펌웨어 파티션·개인 앱 데이터·물리 부품이 같다는 보증은 아닙니다. SHA-256 일치는 보고된 파일 값 사이의 일치이며, 참고 보고서를 제조사 순정 기준으로 인증하지 않습니다. 보고서 값은 위조될 수 있으며 다른 사용자/업무 프로필은 포함하지 않습니다.");
        return out.toString();
    }

    private static String schema(JSONObject report) {
        Object value = report == null ? null : report.opt("schema");
        if (!(value instanceof String) || (!"refurbcheck-report-v1".equals(value) && !"refurbcheck-report-v2".equals(value)))
            throw new IllegalArgumentException("지원하는 RefurbCheck v1/v2 결과 JSON 파일이 아닙니다.");
        return (String) value;
    }
    private static JSONObject device(JSONObject report) {
        JSONObject evidence = report.optJSONObject("evidence");
        JSONObject device = evidence == null ? null : evidence.optJSONObject("device");
        return device == null ? new JSONObject() : device;
    }
    private static String knownString(JSONObject object, String key) {
        Object raw = object.opt(key);
        if (!(raw instanceof String)) return null;
        String value = (String) raw, trimmed = value.trim();
        if (trimmed.isEmpty() || trimmed.equalsIgnoreCase("unknown") || trimmed.equalsIgnoreCase("null")) return null;
        for (int i = 0; i < value.length(); i++) if (Character.isISOControl(value.charAt(i))) return null;
        return value;
    }
    private static String metadata(JSONObject object, String key) {
        if ("apiLevel".equals(key)) { Long value = integer(object.opt(key)); return value == null ? null : value.toString(); }
        return knownString(object, key);
    }
    private static Map<String, JSONObject> packages(Object raw) {
        if (!(raw instanceof JSONArray)) throw new IllegalArgumentException("앱 목록이 없거나 배열 형식이 아닙니다. 빈 목록으로 간주하지 않습니다.");
        JSONArray array = (JSONArray) raw;
        if (array.length() > 20000) throw new IllegalArgumentException("앱 목록이 너무 큽니다.");
        Map<String, JSONObject> result = new HashMap<>();
        for (int i = 0; i < array.length(); i++) {
            JSONObject row = array.optJSONObject(i);
            Object name = row == null ? null : row.opt("packageName");
            if (!(name instanceof String) || ((String) name).length() > 255
                    || !((String) name).matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)*"))
                throw new IllegalArgumentException("앱 정보 또는 패키지 이름 형식이 잘못되었습니다.");
            if (result.put((String) name, row) != null) throw new IllegalArgumentException("패키지 이름이 중복된 보고서입니다.");
        }
        return result;
    }
    private static FileSet files(JSONObject row, boolean supportedSchema) {
        if (!supportedSchema) return new FileSet("v1에는 검증 가능한 APK 파일 수집 기록 없음");
        if (!trueValue(row, "apkInspectionComplete")) return new FileSet("APK 수집 미완료/완료 표시 없음");
        if (row.has("apkChangedDuringScan") && !Boolean.FALSE.equals(row.opt("apkChangedDuringScan")))
            return new FileSet("검사 중 패키지 변경 또는 안정성 표시 오류");
        if (row.has("apkInspectionError") && (!(row.opt("apkInspectionError") instanceof String)
                || !((String) row.opt("apkInspectionError")).isEmpty())) return new FileSet("패키지 수집 오류 기록");
        JSONArray array = row.optJSONArray("apkFiles");
        if (array == null || array.length() == 0 || array.length() > 2048) return new FileSet("APK 파일 목록 누락/크기 오류");
        Map<String, FileHash> hashes = new HashMap<>(); boolean base = false;
        for (int i = 0; i < array.length(); i++) {
            JSONObject file = array.optJSONObject(i);
            if (file == null) return new FileSet("APK 파일 행 형식 오류");
            Object rawId = file.opt("fileId"), rawKind = file.opt("kind"), rawSplit = file.opt("splitName");
            if (!(rawId instanceof String) || !(rawKind instanceof String) || !(rawSplit instanceof String))
                return new FileSet("APK 식별자/종류/split 이름 누락");
            String id = (String) rawId, kind = (String) rawKind, split = (String) rawSplit;
            if ("base".equals(kind)) {
                if (!"base".equals(id) || !split.isEmpty() || base) return new FileSet("base APK 식별자 오류/중복");
                base = true;
            } else if ("split".equals(kind)) {
                if (split.length() == 0 || split.length() > 255 || !split.matches("[A-Za-z0-9_.-]+")
                        || !id.equals("split:" + split)) return new FileSet("split APK 식별자 오류");
            } else return new FileSet("알 수 없는 APK 파일 종류");
            String hash = digest(file.opt("sha256"));
            Long size = integer(file.opt("size"));
            if (!"HASHED".equals(file.opt("hashStatus")) || !trueValue(file, "fileStable") || hash == null || size == null)
                return new FileSet("완전한 SHA-256/안정성/파일 크기 증거 없음");
            if (hashes.put(id, new FileHash(hash, size)) != null) return new FileSet("APK fileId 중복");
        }
        if (!base) return new FileSet("base APK 기록 누락");
        return new FileSet(hashes);
    }
    private static String digest(Object value) {
        return value instanceof String && ((String) value).matches("[0-9a-fA-F]{64}") ? ((String) value).toLowerCase(Locale.ROOT) : null;
    }
    private static Long integer(Object value) {
        if (!(value instanceof Number)) return null;
        String representation = value.toString();
        if (!representation.matches("0|[1-9][0-9]{0,18}")) return null;
        try { return Long.valueOf(representation); } catch (NumberFormatException exception) { return null; }
    }
    private static boolean trueValue(JSONObject object, String key) { return Boolean.TRUE.equals(object.opt(key)); }
    private static String versionName(JSONObject object, long fallback) {
        String name = knownString(object, "versionName"); return name == null ? Long.toString(fallback) : display(name, 120);
    }
    private static String display(String value, int maximum) { return value.length() <= maximum ? value : value.substring(0, maximum) + "…"; }
    private static String fileIds(FileSet files) {
        List<String> ids = new ArrayList<>(files.files.keySet()); Collections.sort(ids);
        int count = Math.min(ids.size(), 8);
        return ids.subList(0, count).toString() + (count < ids.size() ? " 외 " + (ids.size() - count) + "개" : "");
    }
    private static void append(StringBuilder output, String text) {
        if (output.length() >= MAX_DETAIL) return;
        int room = MAX_DETAIL - output.length();
        if (text.length() + 1 > room) output.append(display(text, Math.max(0, room - 1))).append('\n');
        else output.append(text).append('\n');
    }
    private static final class FileHash {
        final String sha256; final long size;
        FileHash(String hash, long size) { this.sha256 = hash; this.size = size; }
    }
    private static final class FileSet {
        final boolean complete; final String reason; final Map<String, FileHash> files;
        FileSet(String reason) { complete = false; this.reason = reason; files = Collections.emptyMap(); }
        FileSet(Map<String, FileHash> files) { complete = true; reason = "완료"; this.files = files; }
    }
}

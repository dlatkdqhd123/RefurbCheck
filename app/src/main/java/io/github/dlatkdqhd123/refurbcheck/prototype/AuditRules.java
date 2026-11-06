package io.github.dlatkdqhd123.refurbcheck.prototype;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

/** OBSERVED never means the phone is safe. */
public final class AuditRules {
    public enum Status { OBSERVED, REVIEW, UNKNOWN, MANUAL }
    public static final class Result {
        public final Status status;
        public final String detail;
        public Result(Status status, String detail) { this.status = status; this.detail = detail; }
    }
    private AuditRules() {}
    public static Result patch(String raw, LocalDate today) {
        try {
            if (raw == null || !raw.matches("\\d{4}-\\d{2}-\\d{2}")) throw new IllegalArgumentException();
            long days = ChronoUnit.DAYS.between(LocalDate.parse(raw), today);
            if (days < 0) return new Result(Status.UNKNOWN, raw + " · 미래 날짜입니다. 기기 시계와 패치 표시를 확인하세요.");
            return new Result(days > 180 ? Status.REVIEW : Status.OBSERVED,
                    raw + " · 표시 날짜로부터 " + days + "일. "
                    + (days > 180 ? "180일 초과: 업데이트를 확인하세요. " : "업데이트 제공 여부도 확인하세요. ")
                    + "180일은 이 앱의 참고 기준이며 제조사 지원 판정이 아닙니다. OS 자체 보고값으로 위조 여부를 검증하지 못합니다.");
        } catch (RuntimeException error) {
            return new Result(Status.UNKNOWN, "유효한 보안 패치 날짜를 읽지 못했습니다. 시스템 업데이트 화면에서 확인하세요.");
        }
    }
    public static boolean granted(int flags) { return (flags & 2) != 0; }
    public static String label(Status status) {
        switch (status) {
            case OBSERVED: return "관찰됨";
            case REVIEW: return "검토 필요";
            case MANUAL: return "직접 확인";
            default: return "확인 불가";
        }
    }
}

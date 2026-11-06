package io.github.dlatkdqhd123.refurbcheck.prototype;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

/** Buildable starting point. No diagnostics or antivirus claims. */
public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView content = new TextView(this);
        int padding = Math.round(24 * getResources().getDisplayMetrics().density);
        content.setPadding(padding, padding, padding, padding);
        content.setTextSize(20);
        content.setText("RefurbCheck\n\n새 프로젝트 준비 버전\n\n검사 기능은 아직 구현되지 않았습니다.\n기존 1.1.0의 업데이트가 아닙니다.\n백신 검사나 기기 정상 판정을 제공하지 않습니다.");
        setContentView(content);
    }
}

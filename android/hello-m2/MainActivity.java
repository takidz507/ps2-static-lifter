package org.ps2lifter.m2;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * MainActivity — Minimal Android UI for PS2 Static Lifter Milestone 2 (Path C).
 * Loads `libps2_lifted_hello.so` (compiled directly from `lifted_hello_kernel_min.c`
 * and `ps2_runtime.c` with zero emulator or MIPS interpreter components), executes
 * the statically lifted PS2 entry point (`fn_00100000__start`), and displays the
 * verbatim stdout (`Hello world!`) and exit code (`0`) on screen.
 */
public class MainActivity extends Activity {
    static {
        System.loadLibrary("ps2_lifted_hello");
    }

    public native String nativeRunLiftedProgram();
    public native int nativeRunAndGetExitCode();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scrollView = new ScrollView(this);
        scrollView.setBackgroundColor(Color.parseColor("#12161F"));

        TextView textView = new TextView(this);
        textView.setTextColor(Color.parseColor("#E6EDF3"));
        textView.setTypeface(Typeface.MONOSPACE);
        textView.setTextSize(15.0f);
        textView.setPadding(40, 48, 40, 48);

        String output = nativeRunLiftedProgram();
        textView.setText(output);

        scrollView.addView(textView);
        setContentView(scrollView);
    }
}

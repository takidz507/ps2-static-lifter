package org.ps2lifter.graph;

import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * PS2 Lifted Graph (Milestone 2.3 Part 4) — Android Surface & Telemetry Activity
 * ==============================================================================
 * Executes the AOT-lifted `graph.elf` (`lifted_graph.c` + `ps2_runtime.c` + GS boundary model)
 * via JNI (`libps2_lifted_graph.so`), blits the modeled 512x512 PSMCT32 framebuffer onto
 * an Android `Bitmap` (`ARGB_8888`) displayed on screen, and shows the frame counter,
 * guest instruction count, FPU ops, GIF/GS boundary stats, and pre-registered pixel probes.
 *
 * Zero emulator or interpreter components — 100% static AOT lifted R5900 C code.
 */
public class MainActivity extends Activity {

    static {
        System.loadLibrary("ps2_lifted_graph");
    }

    public static native String nativeRunGraphFrames(int targetFrames, int[] outArgbPixels);

    private int mCurrentFrames = 3;
    private Bitmap mFramebufferBitmap;
    private int[] mPixelBuffer;
    private ImageView mSurfaceImageView;
    private TextView mStatsTextView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mFramebufferBitmap = Bitmap.createBitmap(512, 512, Bitmap.Config.ARGB_8888);
        mPixelBuffer = new int[512 * 512];

        ScrollView scrollRoot = new ScrollView(this);
        scrollRoot.setBackgroundColor(Color.rgb(14, 18, 26));

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 32, 32, 32);
        root.setGravity(Gravity.CENTER_HORIZONTAL);

        TextView titleView = new TextView(this);
        titleView.setText("PS2 Lifted Graph — M2.3 AOT Framebuffer");
        titleView.setTextColor(Color.rgb(235, 242, 255));
        titleView.setTextSize(18.0f);
        titleView.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        titleView.setPadding(0, 0, 0, 16);
        root.addView(titleView);

        mSurfaceImageView = new ImageView(this);
        LinearLayout.LayoutParams imgParams = new LinearLayout.LayoutParams(768, 768);
        imgParams.bottomMargin = 20;
        mSurfaceImageView.setLayoutParams(imgParams);
        mSurfaceImageView.setScaleType(ImageView.ScaleType.FIT_CENTER);
        root.addView(mSurfaceImageView);

        LinearLayout btnRow = new LinearLayout(this);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        btnRow.setGravity(Gravity.CENTER);

        Button btnReset3 = new Button(this);
        btnReset3.setText("Run 3 Frames (PREREG Gate)");
        btnReset3.setOnClickListener(v -> {
            mCurrentFrames = 3;
            executeAndBlit(mCurrentFrames);
        });
        btnRow.addView(btnReset3);

        Button btnStep = new Button(this);
        btnStep.setText("Step +1 Frame");
        btnStep.setOnClickListener(v -> {
            mCurrentFrames++;
            executeAndBlit(mCurrentFrames);
        });
        btnRow.addView(btnStep);

        root.addView(btnRow);

        mStatsTextView = new TextView(this);
        mStatsTextView.setTextColor(Color.rgb(190, 225, 205));
        mStatsTextView.setTextSize(12.5f);
        mStatsTextView.setTypeface(Typeface.MONOSPACE);
        mStatsTextView.setPadding(8, 20, 8, 20);
        root.addView(mStatsTextView);

        scrollRoot.addView(root);
        setContentView(scrollRoot);

        /* Run the 3-frame pre-registered gate immediately on startup */
        executeAndBlit(mCurrentFrames);
    }

    private void executeAndBlit(int frames) {
        String telemetry = nativeRunGraphFrames(frames, mPixelBuffer);
        mFramebufferBitmap.setPixels(mPixelBuffer, 0, 512, 0, 0, 512, 512);
        mSurfaceImageView.setImageBitmap(mFramebufferBitmap);
        mStatsTextView.setText(telemetry);
    }
}

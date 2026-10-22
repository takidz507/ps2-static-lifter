# Android apps — how they are built

Four apps live here as source projects. None contains an emulator,
interpreter, or JIT: each native library is compiled directly from the
lifted C (`../lifted/`) plus the runtime model (`../tools/ps2_runtime.c`),
a small JNI bridge, and a single-Activity UI.

| Dir | Package | What it runs |
|---|---|---|
| `hello-m2/` | `org.ps2lifter.m2` | The synthetic 100-instruction sample (M2) — full run, `Hello world!`, exit 0 |
| `real/` | `org.ps2lifter.real` | The real 30,090-instruction ps2sdk program (M2.2 engine) — full run, statistics identical to the host |
| `probe/` | `org.ps2lifter.game500` | Execution probe for the homebrew card game — runs the lifted game and reports exactly where it stops (currently: 116,220 instructions, `SetSyscall` wall). Its bridge keeps the *run status* strictly separate from the *guest exit code* (a stopped guest legitimately returns negative codes such as −216; an earlier build conflated the two and misreported the run as an init failure — fixed and host-validated before redelivery) |
| `graph/` | `org.ps2lifter.graph` | The graphics app (M2.3): runs the lifted graph sample through the GS boundary model and blits the 512×512 framebuffer to a Bitmap, with **Run 3 Frames** / **Step +1 Frame** controls |

## Source sync for `graph/`

The graph app's `app/src/main/cpp/` intentionally contains only
`CMakeLists.txt` and `native_graph_jni.c`. Before building, copy the shared
sources in (this is step [6/6] of `../tools/run_m23.sh`):

```bash
cp ../tools/ps2_runtime.{c,h} ../lifted/lifted_graph.{c,h} \
   graph/app/src/main/cpp/
```

The other three apps keep their JNI bridge beside their Activity; they link
against the same `../lifted/` and `../tools/` sources the same way.

## The manual pipeline (why not Gradle)

The reference builds were produced on a machine where the Gradle daemon
cannot run, so the APKs were assembled with the SDK/NDK tools directly.
The pipeline is deterministic and scriptable:

1. **Native libraries** (both ABIs):
   `clang --target=aarch64-linux-android24` / `x86_64-linux-android24`,
   `-std=c11 -O1 -fPIC -shared`, sources = JNI bridge + `ps2_runtime.c` +
   the target's `lifted_*.c`, link `-ldl -lm`.
2. **Java → dex:** `javac --release 8` against `android-34/android.jar`,
   then `d8`.
3. **Package:** `aapt2 link` with the app manifest → stage `classes.dex` +
   `lib/<abi>/*.so` → `zip` → `zipalign -f 4`.
4. **Sign & verify:** `apksigner sign` (debug key) + `apksigner verify`,
   `aapt2 dump badging`, and a symbol check on the `.so` (JNI exports +
   the lifted entry function, e.g. `fn_00100b20___start`) before any APK
   is called done.

Prebuilt APKs built exactly this way are attached to this repository's
GitHub Release (`v1.0-ladder`).

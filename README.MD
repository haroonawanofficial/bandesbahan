# bandesbahan - AI Browser Fuzzer 
**Author:** Haroon Ahmad Awan
**Date:** 2025‑04‑18  
**Information:**
- Generates **3000+** AI‑mutated JS/HTML/WASM/WebAPI payloads
- Uses pretrained (and optionally fine‑tuned) CodeBERT for multi‑MASK top‑k substitutions  
- Runs **parallel generation** (16 threads) and **parallel execution** (8 threads)  
- Automatically **captures → de‑duplicates → auto‑minimizes** crashes  
- Supports **coverage‑based prioritization**, **continuous 24×7 loops**, and **systemd integration**  

## 🛠 Prerequisites

1. **Python 3.9+**  
2. **Virtual environment** (recommended)  
3. **Install AI model dependencies**  
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install torch transformers


## Build sanitised JavaScript shells
# 3.1 WebKit jsc
git clone https://github.com/WebKit/WebKit.git
cd WebKit
Tools/Scripts/update-webkitgtk-libs
Tools/Scripts/build-jsc --jsc-only --release --cmakeargs="-DENABLE_ADDRESS_SANITIZER=ON -DENABLE_UNDEFINED_BEHAVIOR_SANITIZER=ON"
cp WebKitBuild/*/bin/jsc /usr/local/bin/jsc

# 3.2 Chrome V8 d8
git clone https://chromium.googlesource.com/v8/v8
cd v8
tools/dev/v8gen.py x64.debug.asan
echo 'is_debug=true
is_component_build=false
v8_enable_sandbox=false
is_asan=true
v8_static_library=true' > out/x64.debug.asan/args.gn
ninja -C out/x64.debug.asan d8
cp out/x64.debug.asan/d8 /usr/local/bin/d8

# 3.3 Firefox SpiderMonkey js
git clone https://hg.mozilla.org/mozilla-unified spidermonkey
cd spidermonkey/js/src
autoconf-2.13
mkdir build && cd build
../configure --enable-address-sanitizer --enable-undefined-sanitizer
make -j$(nproc)
cp js/src/js /usr/local/bin/js


# 4. Edit fuzzer config (optional)
ENGINES = {
    "jsc": "/usr/local/bin/jsc",
    "d8" : "/usr/local/bin/d8",
    "js" : "/usr/local/bin/js",
}
TOTAL_PAYLOADS = 2500          # raise for marathon fuzzing
THREADS_GEN    = 12            # tweak for CPU count
THREADS_RUN    = 6


# Run the Fuzzer
source venv/bin/activate
python3 bandesbahan_fuzzer.py

# Output
Corpus → bandesbahan_corpus/run_YYYYMMDD_HHMMSS/
Crashes → bandesbahan_crashes/


### Safari (WebKit) Usage & Expectations
1. Build or install an ASAN‑instrumented `jsc` shell.  
2. Point `{"jsc":"/usr/local/bin/jsc"}` in `ENGINES` of `bandesbahan_fuzzer.py`.  
3. Activate your Python virtualenv (`source venv/bin/activate`).  
4. Ensure `ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1"` is exported.  
5. Run `python3 bandesbahan_fuzzer.py`.  
6. Generated payloads appear under `bandesbahan_corpus/run_<timestamp>/`.  
7. Fuzzer will launch each `.js` file with `jsc` in parallel.  
8. Crashes are automatically copied into `bandesbahan_crashes/` with a signature.  
9. Expect to see ASan reports for OOB reads/writes, type‑confusions, use‑after‑free.  
10. Each crash file is auto‑minimized to the smallest repro for quick analysis.

### Chrome (V8) Usage & Expectations
1. Build an ASAN‑enabled `d8` binary and install it (e.g. `/usr/local/bin/d8`).  
2. Update `ENGINES["d8"]` in the script to your `d8` path.  
3. Export `ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1"`.  
4. In your venv, run `python3 bandesbahan_fuzzer.py`.  
5. Chrome payloads (`.js`) land in `bandesbahan_corpus/run_<timestamp>/`.  
6. The fuzzer invokes `d8` on each payload concurrently.  
7. Crashes (SIGABRT/SIGSEGV) are logged under `bandesbahan_crashes/`.  
8. Expect V8‑specific faults: JIT miscompiles, OOB on arrays, GC‑use‑after‑free.  
9. Crash files are reduced via binary search minimization.  
10. Use `gdb --args d8 <crash.js>` to inspect and backtrace.

### Firefox (SpiderMonkey) Usage & Expectations
1. Compile `js` with ASAN/UBSAN and install it (e.g. `/usr/local/bin/js`).  
2. Set `ENGINES["js"]` in `bandesbahan_fuzzer.py` to your `js` shell path.  
3. Export `UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"`.  
4. Activate venv and run `python3 bandesbahan_fuzzer.py`.  
5. HTML+JS payloads (`.html`) and `.js` appear in `bandesbahan_corpus/`.  
6. The script drives `js` to execute each test in parallel.  
7. Crash cases (JS engine faults) are saved in `bandesbahan_crashes/`.  
8. Look for SpiderMonkey‑specific issues: deopt bailouts, OOB, DOM crashes.  
9. Each crash is minimized to the fewest lines needed to reproduce.  
10. Debug with `gdb --args js <crash.html>` and run `bt` to view the stack.


# Output
```
[*] Loading CodeBERT model…
[+] Model ready.
[+] Total templates loaded: 1200
[+] Injected advanced templates: 200, total now: 1400

[+] Starting fuzz run: bandesbahan_corpus/run_20250418_153045
[GEN-0] generated 100 payloads
[GEN-1] generated 200 payloads
…
[GEN-15] generated 3000 payloads
[+] Generation complete.

[+] Execution phase: launching 3000 tests across 3 engines
[CRASH-0] jsc_af3b1c2d.js
[CRASH-0] d8_4e5f6a7b.js
[CRASH-1] js_89ab0cde.html
…
[+] Execution complete. Crashes stored in: bandesbahan_crashes
```

**What each line means:**

1. **Loading CodeBERT model** — the AI mutation model is loaded (and optionally fine‑tuned).  
2. **Template counts** — shows how many base + advanced templates are in use.  
3. **Starting fuzz run** — the timestamped output folder where payloads and crashes go.  
4. **\[GEN‑X\] generated N payloads** — progress of the parallel generation threads (every 100 files).  
5. **Generation complete** — all `TOTAL_PAYLOADS` have been written to disk.  
6. **Execution phase…** — the fuzzer is now feeding each payload to your JS shells.  
7. **\[CRASH‑TID\] engine_signature.ext** — a unique crash was detected in engine `jsc`, `d8`, or `js` and saved+minimized.  
8. **Execution complete** — run finished; all unique crashes are in `bandesbahan_crashes/`.

After this, you can inspect the crash folder and reproduce individual failures in LLDB/GDB as described in the guide.


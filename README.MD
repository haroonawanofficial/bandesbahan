# bandesbahan - AI Browser Fuzzer 
- Highly Experimental and Fully Automated to fuzzer to find 0day in safari / chrome / firefox

**Author:** Haroon Ahmad Awan

**Date:** 2025‑04‑18  

**Information:**
- Generates **3000+** AI‑mutated JS/HTML/WASM/WebAPI payloads
- Uses pretrained (and optionally fine‑tuned) CodeBERT for multi‑MASK top‑k substitutions  
- Runs **parallel generation** (16 threads) and **parallel execution** (8 threads)  
- Automatically **captures → de‑duplicates → auto‑minimizes** crashes  
- Supports **coverage‑based prioritization**, **continuous 24×7 loops**, and **systemd integration**  

---

## 🛠 Prerequisites

1. **Python 3.9+**  
2. **Virtual environment** (recommended)  
3. **Install AI model dependencies**  
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install torch transformers


## Use the .py file and adjust
# Enable & start
systemctl enable bandesbahan
systemctl start bandesbahan


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

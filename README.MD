# bandesbahan

**Author:** Haroon Ahmad Awan  

## Overview
- Generates **3000+** AI‑mutated JS/HTML/WASM/WebAPI payloads  
– AI Browser Fuzzer to find 0 day in browsers
- Runs **parallel generation** (16 threads) and **parallel execution** (8 threads)  
- Automatically **captures → de‑duplicates → auto‑minimizes** crashes  
- Supports **coverage‑based prioritization**, **continuous 24×7 loops**, and **systemd integration**  


## Prerequisites

1. **Python 3.9+**  
2. **Virtual environment** (recommended)  
3. **Install AI model dependencies**  
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install torch transformers
   ```  
---

## What it finds using fuzzing (potential 0‑day)
- **Safari (WebKit)**: out‑of‑bounds reads/writes, type‑confusions, use‑after‑free in WebKit and its plugins  
- **Chrome (V8)**: JIT miscompilations, out‑of‑bounds accesses, garbage‑collector UAF  
- **Firefox (SpiderMonkey)**: deoptimization bailouts, out‑of‑bounds errors, DOM‑related crashes  

---

## Build sanitized JS shells** with ASAN/UBSAN:  
   - Safari (WebKit) `jsc`  
   - Chrome (V8)     `d8`  
   - Firefox (SpiderMonkey) `js`  


## Build Instrumented JS Shells

### Safari (WebKit `jsc`)
```bash
git clone https://github.com/WebKit/WebKit.git
cd WebKit
Tools/Scripts/update-webkitgtk-libs
Tools/Scripts/build-jsc --jsc-only --release \
  --cmakeargs="-DENABLE_ADDRESS_SANITIZER=ON \
               -DENABLE_UNDEFINED_BEHAVIOR_SANITIZER=ON"
cp WebKitBuild/**/bin/jsc /usr/local/bin/jsc
```

### Chrome (V8 `d8`)
```bash
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
```

### Firefox (SpiderMonkey `js`)
```bash
hg clone https://hg.mozilla.org/mozilla-unified spidermonkey
cd spidermonkey/js/src
autoconf-2.13
mkdir build && cd build
../configure --enable-address-sanitizer --enable-undefined-sanitizer
make -j$(nproc)
cp js/src/js /usr/local/bin/js
```

---

## Run the Fuzzer

```bash
source venv/bin/activate
python3 bandesbahan_fuzzer.py
```

**Output directories:**
- `bandesbahan_corpus/run_YYYYMMDD_HHMMSS/` (payloads)  
- `bandesbahan_crashes/`                (minimized crashes)  

---

## Usage

### Safari (WebKit)
1. Build/install ASAN `jsc`.  
2. Set `ENGINES["jsc"]` to the `jsc` path.  
3. Export `ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1"`.  
4. Run the fuzzer.  
5. Payloads appear in the corpus directory.  
6. Fuzzer invokes `jsc` on each `.js`.  
7. Crashes saved in `bandesbahan_crashes/`.  
8. Expect OOB reads/writes, type‑confusions, UAF.  
9. Each crash is auto‑minimized.  
10. Debug with `lldb -- /usr/local/bin/jsc <crash.js>`.

### Chrome (V8)
1. Build/install ASAN `d8`.  
2. Set `ENGINES["d8"]`.  
3. Export `ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1"`.  
4. Run the fuzzer.  
5. `.js` payloads in corpus.  
6. `d8` executes each test.  
7. Crashes in `bandesbahan_crashes/`.  
8. Expect JIT miscompiles, OOB, GC UAF.  
9. Crashes minimized.  
10. Debug with `gdb --args d8 <crash.js>`.

### Firefox (SpiderMonkey)
1. Build/install ASAN `js`.  
2. Set `ENGINES["js"]`.  
3. Export `UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"`.  
4. Run the fuzzer.  
5. `.js` & `.html` payloads in corpus.  
6. `js` executes each file.  
7. Crashes in `bandesbahan_crashes/`.  
8. Expect deopt bailouts, OOB, DOM crashes.  
9. Crashes minimized.  
10. Debug with `gdb --args js <crash.html>`.

---

##  Output

```bash
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

**Line meaning:**
1. **Loading CodeBERT** – AI model initialization.  
2. **Template counts** – core + advanced templates loaded.  
3. **Starting fuzz run** – output folder timestamp.  
4. **[GEN‑X] generated N** – generation progress.  
5. **Generation complete** – payloads written.  
6. **Execution phase** – feeding tests to engines.  
7. **[CRASH‑TID]** – unique crash detected & minimized.  
8. **Execution complete** – all tests done.

---

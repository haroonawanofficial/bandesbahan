# bandesbahan - AI Browser Fuzzer 

**Author:** Haroon Ahmad Awan
**Date:** 2025‑04‑18  
**Information:**

- Generates **3000+** AI‑mutated JS/HTML/WASM/WebAPI payloads  
- Uses pretrained (and optionally fine‑tuned) CodeBERT for multi‑MASK top‑k substitutions  
- Ships with **1200+** core templates and **200+** “never‑seen” advanced templates  
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

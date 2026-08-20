# 🛡️ Offensive Security Portfolio — HackTheBox Writeups & Research

> Hands-on writeups and research notes from solving **Hard** and **Insane** HackTheBox challenges across **web, cloud, reverse engineering, and binary exploitation**. Focus on *understanding and explaining* each technique — every writeup pairs the offensive chain with its **defensive mitigation** and interview-style Q&A.

**HackTheBox:** `ju5nxv` · **Focus:** Vulnerability Research / Reverse Engineering / Binary Exploitation

---

## 🔍 Vulnerability Research — real software, coordinated disclosure

Beyond CTF, I hunt memory-corruption bugs in real image decoders and submit them
through **Trend Micro's Zero Day Initiative** under coordinated disclosure.
**Five cases are currently in triage** (`ju4nxv0001`–`ju4nxv0005`).

All five are the *same bug class*, found by looking for one specific mistake:

> **one file-declared quantity sizes a buffer, while a *different* file-declared
> quantity bounds the loop that fills it.**

| # | Product | Component | Status |
|---|---|---|---|
| 1–4 | IrfanView | image decoders (4 distinct formats) | in triage — embargoed |
| 5 | GIMP | image decoder | in triage — embargoed |

One measurement I can share, because it shows the method rather than the bug: in
case 3 the allocation was **832 bytes** while the write loop was bounded by a
64-bit value near **4.29 GB** — a 32-bit truncation. I confirmed the exact
overflow threshold by binary search, at byte **833**. Reports go out with a
measured boundary, not an estimate.

Method — the part I care about more than the bugs:

- **static triage** — PE64 disassembly with Capstone (resynchronizing linear
  sweep), scoring byte-write loops by how the bound relates to the allocation
- **dynamic confirmation** — Page Heap via IFEO, `cdb` scripting, and a
  *ground-truth harness*: the scanner must re-find bugs I already verified by
  hand, or the scanner is broken, not the target
- **minimal PoC** — every report ships the smallest file that triggers it, plus
  a byte-level diff against a clean sample, so a triager reproduces in minutes

**All five remain embargoed until the vendors ship a fix** — that is the deal you
make when you file under coordinated disclosure, and it holds even when the
vulnerable code is open source and the analysis would look good here. Technical
write-ups will be published once the advisories are out.

---

## 📄 Original research

**[WordPress escapes your values — not your array keys](research-wordpress-array-keys.md)**

`wp_magic_quotes()` escapes every superglobal on every request — but
`add_magic_quotes()` maps over *values only*. Array keys arrive unescaped, which
makes `foreach ($_POST['f'] as $id => $v)` with `$id` in a query injectable
**even inside quotes**: the one case every WordPress SQLi scanner treats as safe.
Measured on a live install, with the detector and the four false-positive classes
that cost me candidates before I encoded them.

---

## 📂 Writeups

| Challenge | Difficulty | Category | Status | Key Techniques |
|---|---|---|---|---|
| [Resizer](Resizer.md) | 🔴 Hard | Web | ✅ Solved | Path traversal → arbitrary write → RCE via namespace-package `.so` shadowing |
| [Nimbus](Nimbus.md) | 🔴 Hard | Cloud / AWS | 🟡 User | SSRF (decimal/octal IP bypass) → IMDS creds → SQS YAML deserialization → RCE → LocalStack |
| [ArtificialUniversity](ArtificialUniversity.md) | ⚫ Insane | Web | ✅ Solved | Unauth checkout → admin bot → path traversal → CVE-2024-4367 (pdf.js) → SameSite bypass → gopher/gRPC prototype pollution → RCE |
| [Heapify](Heapify.md) | ⚫ Insane | Pwn (heap) | ✅ Solved | glibc 2.35 no-leak · safe-linking + comparison oracle · `malloc_consolidate` libc leak · OOB min-heap → arbitrary free · tcache poison · FSOP House of Apple 2 |
| [Sandcastle](Sandcastle.md) | ⚫ Insane | Pwn | ✅ Solved | VM sandbox escape · no-bounds arbitrary write · `open()`/`popen()` differential injection |
| [Callfuscated](Callfuscated.md) | ⚫ Insane | Reverse Eng. | ✅ Solved | VM devirtualization (8-opcode bytecode) · MBA · call-obfuscation · GDB Python API |
| [Wonky AES](WonkyAES.md) | ⚫ Insane | Crypto | ✅ Solved | Differential Fault Analysis on AES-128 (Piret) · round-key recovery · key-schedule inversion |
| [Poly](Poly.md) | ⚫ Insane | Reverse Eng. | 🟡 Analyzed | ARM64 multi-layer obfuscation · MD5/CRC32 constant ID · Unicorn emulation (no qemu) |
| [Blinded](Blinded_research-notes.md) | ⚫ Insane | Pwn (heap) | 🔬 Research | glibc 2.35 · House of Water · tcache stashing · deterministic no-leak analysis |

---

## 🧰 Technical Skills

**Web** — SQLi · SSTI · XXE · LFI/RFI · path traversal · file upload · SSRF · insecure deserialization · JWT attacks · IDOR

**Cloud / AWS** — SSRF→IMDS credential theft · IAM abuse · SQS/Lambda/Secrets Manager · LocalStack exploitation

**Reverse Engineering** — GDB scripting (Python API) · Capstone · Unicorn / angr · custom VM devirtualization · Mixed Boolean Arithmetic · crypto-primitive recognition (MD5/CRC32/AES)

**Binary Exploitation** — glibc 2.35 heap (tcache poisoning, House of Water, safe-linking bypass) · deterministic no-leak exploitation via side-channel comparison oracles · `malloc_consolidate` / unsorted-bin leaks · ASLR defeat · **FSOP House of Apple 2** · VM sandbox escape

**Crypto** — Differential Fault Analysis (AES) · key-schedule inversion · classic CTF primitives (padding/PRNG/LCG)

**Tooling** — `nmap` · `ffuf`/`feroxbuster` · BloodHound · impacket · `pwntools` · `gdb`+pwndbg · `one_gadget` · `patchelf`

---

## 🧭 Methodology

- **[PLAYBOOK.md](PLAYBOOK.md)** — reusable pentest methodology, born from real mistakes (enumeration order, avoiding tunnel-vision, spotting intended vs decoy paths).
- **[ARSENAL.md](ARSENAL.md)** — technique catalog: *what it is · how to detect · how to defend* (built for whiteboard/interview explanation).

**Core principle:** enumerate systematically (`ports → vhosts → dirs → params`), prefer dynamic instrumentation over fighting obfuscated static disassembly, and always distinguish the *intended* path from decoys.

---

## ⚖️ Disclaimer

All content is for **educational purposes** and documents work performed exclusively in **authorized lab environments** (HackTheBox). Every technique is presented alongside its defensive mitigation. Nothing here is intended for unauthorized use.

# 🛡️ Offensive Security Portfolio — HackTheBox Writeups & Research

> Hands-on writeups and research notes from solving **Hard** and **Insane** HackTheBox challenges across **web, cloud, reverse engineering, and binary exploitation**. Focus on *understanding and explaining* each technique — every writeup pairs the offensive chain with its **defensive mitigation** and interview-style Q&A.

**Handle:** `jushxv` · **Focus:** Offensive Security / Reverse Engineering / Exploit Analysis

---

## 📂 Writeups

| Challenge | Difficulty | Category | Status | Key Techniques |
|---|---|---|---|---|
| [Resizer](Resizer.md) | 🔴 Hard | Web | ✅ Solved | Path traversal → arbitrary write → RCE via namespace-package `.so` shadowing |
| [Nimbus](Nimbus.md) | 🔴 Hard | Cloud / AWS | 🟡 User | SSRF (decimal/octal IP bypass) → IMDS creds → SQS YAML deserialization → RCE → LocalStack |
| [Sandcastle](Sandcastle.md) | ⚫ Insane | Pwn | ✅ Solved | VM sandbox escape · no-bounds arbitrary write · `open()`/`popen()` differential injection |
| [Callfuscated](Callfuscated.md) | ⚫ Insane | Reverse Eng. | ✅ Solved | VM devirtualization (8-opcode bytecode) · MBA · call-obfuscation · GDB Python API |
| [Poly](Poly.md) | ⚫ Insane | Reverse Eng. | 🟡 Analyzed | ARM64 multi-layer obfuscation · MD5/CRC32 constant ID · Unicorn emulation (no qemu) |
| [Blinded](Blinded_research-notes.md) | ⚫ Insane | Pwn (heap) | 🔬 Research | glibc 2.35 · House of Water · tcache stashing · deterministic no-leak analysis |

---

## 🧰 Technical Skills

**Web** — SQLi · SSTI · XXE · LFI/RFI · path traversal · file upload · SSRF · insecure deserialization · JWT attacks · IDOR

**Cloud / AWS** — SSRF→IMDS credential theft · IAM abuse · SQS/Lambda/Secrets Manager · LocalStack exploitation

**Reverse Engineering** — GDB scripting (Python API) · Capstone · Unicorn / angr · custom VM devirtualization · Mixed Boolean Arithmetic · crypto-primitive recognition (MD5/CRC32/AES)

**Binary Exploitation** — glibc 2.35 heap (tcache poisoning, House of Water) · deterministic no-leak exploitation · ASLR · FSOP analysis

**Tooling** — `nmap` · `ffuf`/`feroxbuster` · BloodHound · impacket · `pwntools` · `gdb`+pwndbg · `one_gadget` · `patchelf`

---

## 🧭 Methodology

- **[PLAYBOOK.md](PLAYBOOK.md)** — reusable pentest methodology, born from real mistakes (enumeration order, avoiding tunnel-vision, spotting intended vs decoy paths).
- **[ARSENAL.md](ARSENAL.md)** — technique catalog: *what it is · how to detect · how to defend* (built for whiteboard/interview explanation).

**Core principle:** enumerate systematically (`ports → vhosts → dirs → params`), prefer dynamic instrumentation over fighting obfuscated static disassembly, and always distinguish the *intended* path from decoys.

---

## ⚖️ Disclaimer

All content is for **educational purposes** and documents work performed exclusively in **authorized lab environments** (HackTheBox). Every technique is presented alongside its defensive mitigation. Nothing here is intended for unauthorized use.

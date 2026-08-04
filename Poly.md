# 🦜 Poly — HTB Insane (Reversing)

> **Flag:** `HTB{i'm-A~prETTY_B!r6}`  ("I'm a PRETTY B1RD" — el loro 🦜)
> **Autor:** jb0 · **Rating:** 4.8 · Escenario: *"Can you find the flag?"* · Released 2020-02-28

Un crackme ARM64 auto-contenido que es **una trampa de 3 capas**. jb0 apila decoys: (1) un MD5-check con password plantado en rockyou, (2) un `HTB{...coffee lake!}` falso escondido en el banner, y (3) el flag REAL escrito **a un file descriptor oculto (`/dev/null`)**, intercalado carácter por carácter con el mensaje de error visible. El título "Poly" + *"Things are not as they appear!"* = todo es un engaño de misdirección.

---

## 1. Triage
```
ELF64 AArch64 (ARM64), No-PIE (EXEC), stripped, freestanding (syscall wrappers propios)
Secciones: .text (32KB) · .flag (236KB, alta entropía) · .bss (4MB)
1 LOAD RWE (.text+.flag) + 1 LOAD RW (.bss)
```
- **Sin `time` importado** → cualquier PRNG/seed es determinista.
- Sin qemu ni sudo → herramientas: **capstone** (disasm ARM64) + **Unicorn** (emulación) — ambos vienen con `angr` (pip).

**Ejecutando** (Unicorn full-emulation, hookeando syscalls read/write):
```
Things are not as they appear!
p011y>            <- REPL, lee una línea
```

---

## 2. El camino DECOY (la trampa) 🪤

Reversando el REPL (`0x4d0` banner → `read` → `0x764` handler):
1. **`MD5(input)`** (init constants `0x67452301…` = firma inconfundible de MD5).
2. Se convierte a **hex string** + se le appendea `\x13\x37` ("1337").
3. **`MD5( hex(MD5(input)) + "\x13\x37" )`** → se compara (`memcmp`, `0xcd4`) con un target de 16 bytes.
4. Si matchea → **XOR-descifra** un buffer de 1392 bytes con `MD5(input)` (key repetida de 16), valida magic `0x1337`, y **ejecuta el buffer como shellcode** (`blr`, `0xf24`) con `x0=0x8cf`, `x1=CRC32(input)`.

**Rompiéndolo sin el input:** el buffer es XOR-repetido de 16 bytes. Bruteforce de `rockyou` contra el double-MD5 target →
- **`il0vep0lly`** (="I love polly", `MD5=11ebc29a…`). ✅ matchea.

Descifrás y ejecutás el shellcode (Unicorn, con `x0=0x8cf`, `x1=CRC32`)… y el binario te escupe:
```
Brr, nice try md5 cracker!
Alas, there is no flag here ;( Go back to the start!
 -- Poly wants a cracker
```
**El autor plantó un password crackeable para castigar a los crackers de fuerza bruta.** `il0vep0lly` es un señuelo. La sección `.flag` de 236KB: **ruido random** (Hamming ~3.9, ningún keysize da texto) — otra distracción.

---

## 3. DECOY #2 — el banner de "coffee lake" 🪤

El **banner buffer** (`0x40004d48`, 327 bytes) se descifra con XOR de 2 bytes (key `0x8cf`) y solo imprime `"Things are not as they appear!"`. Bruteforceando las 65536 keys sobre el resto del buffer aparece, en el offset 82 con key `0x05/0xd2`:
**`HTB{"I have no arms, but I make do with my coffee lake!"}`** (chiste ARM="no arms" + Coffee Lake=Intel x86).
→ **También decoy** ("Incorrect flag"). Formato sospechoso (comillas + espacios, atípico de HTB). jb0 plantó DOS flags falsos.

---

## 4. El camino REAL — el flag va a `/dev/null` 🎯

Emulando el binario completo con **Unicorn** y capturando los `write` **por file descriptor**, se ve el truco: con CUALQUIER input incorrecto, el binario escribe a **dos fds simultáneamente**, intercalando fragmentos:

| fd | destino | contenido (fragmentos concatenados) |
|---|---|---|
| **1** | stdout (visible) | `\nCRI`+`TI`+`CAL`+`: `+`Sys`+`te`+`m `+`err`+`or!\n` = **"CRITICAL: System error!"** |
| **3** | **`/dev/null`** (oculto) | `HTB{`+`i'm`+`-A`+`~pr`+`ET`+`TY_`+`B!`+`r6`+`}` = **el FLAG** |

El binario hace `open("/dev/null")` (→ fd 3) al arrancar, y escribe el flag ahí carácter por carácter, **intercalado** con el error de fd 1. Por eso "**Things are not as they appear!**": lo que ves (fd 1) es un error; el flag está en un fd que va a la basura.

**Captura en el binario real:** `./poly 3>flag.txt` / `strace -e write` / `ltrace`. En la emulación: hookear el `write` syscall y filtrar por `x0==3`.

**`HTB{i'm-A~prETTY_B!r6}`** — estable con cualquier input (independiente del password).

---

## 5. Herramientas / método (sin qemu, sin sudo)
- **capstone** para desensamblar ARM64 (`Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)`), reconstruir la VM/lógica.
- **Unicorn** para **emular el binario completo** hookeando syscalls (`UC_HOOK_INTR`: read=inyectar input, write=capturar stdout, exit=stop). Corre self-modifying nativo, rapidísimo, computa el CRC/MD5 reales. La forma correcta de "correr" un ARM64 cuando no podés instalar qemu.
- **Reconocer primitivas cripto por sus constantes:** MD5 (`0x67452301/0xefcdab89/0x98badcfe/0x10325476`), CRC32 (loop `lsl 8 / lsr 24 / eor tabla`).

---

## 5. Q&A de entrevista

**P: ¿Cómo emulás/corrés un binario de otra arquitectura sin qemu?**
R: Unicorn Engine (motor de qemu como librería). Mapeás los segmentos LOAD, seteás SP, y hookeás las interrupciones de syscall (`svc`) para implementar read/write/exit vos mismo. No necesita el binfmt del sistema ni root. Ideal cuando el entorno no te deja instalar qemu-user.

**P: Identificaste MD5 sin símbolos. ¿Cómo?**
R: Por las **constantes de inicialización** en el código: `0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476` son los IV de MD5 (A,B,C,D). Igual SHA1/SHA256 tienen IVs característicos, y CRC32 se reconoce por el shift-8/xor-tabla. Reconocer constantes cripto es más rápido que reversar el algoritmo entero.

**P: ¿Por qué un password estaba en rockyou si era "seguro"?**
R: Era una **trampa deliberada** (defensa por engaño / canary). El autor plantó un password débil que pasa el check pero lleva a un mensaje burlón, para detectar y frustrar a quien ataca por fuerza bruta en vez de reversar. Lección: cuando un camino se resuelve "demasiado fácil" en un Insane, sospechá que es un decoy (ver PLAYBOOK: *camino fácil/imposible = probablemente NO es el intended*).

**P: ¿Cómo rompés un XOR de key repetida corta sin conocer el plaintext?**
R: (a) Estimar la longitud de key con **distancia de Hamming normalizada** (Kasiski). (b) Romper cada columna independiente por análisis de frecuencia (byte más común ≈ espacio en texto). Con key de 2 bytes y buscando un marcador conocido (`HTB{`), fuerza bruta directa de 65536 keys es trivial.

**P: ¿Qué era el "poly" del título?**
R: El flag es un chiste sobre **poly**glot de arquitecturas: el binario es ARM ("no arms") pero el flag menciona "coffee lake" (Intel x86). "Things are not as they appear" — parece una cosa (ARM crackme con MD5) y es otra (flag escondido en el banner). El prompt `p011y>` es un guiño a "Polly the parrot" ("Poly wants a cracker").

---
*Método: [PLAYBOOK.md](PLAYBOOK.md) · toolkit: [ARSENAL.md](ARSENAL.md) · previo: [Callfuscated.md](Callfuscated.md)*

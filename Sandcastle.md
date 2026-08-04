# Sandcastle — HackTheBox (Pwn · Insane · clubby789) ✅ RESUELTO

> **Flag:** `HTB{S0rry_M4r10_y0ur_pr1nc3ss_1s_1n_4n0th3r_(54nd)c457l3!}`
> **Categoría:** pwn / sandbox-escape. **Target:** IP:PORT directo (sin VPN). Files: `Dockerfile` + `sandcastle` (ELF64, No-PIE, canary, NX, seccomp).
> Exploit: `~/ctf/sandcastle/solve.py`. Disasm: `scratchpad/sandcastle/disasm.txt`.

---

## 1. Overview

Te dan un intérprete de "lenguaje custom" (una **VM tipo Brainfuck**) que corre tu programa (≤800 bytes) con ops de I/O, **FILESYSTEM** y **EXEC**, todas "locked down". El escape sale de combinar **dos** bugs.

**Arquitectura (broker + workers seccomp):** `main` mmapea 4 regiones FIJAS (No-PIE) — programa `0x3fd000`, **slots de datos `0x3fc000`** (slot0=+0, slot1=+0xff, slot2=+0x1fe, slot3=+0x2fd), la **tape de la VM `0x3fe000`**, y la **región de fds de pipe `0x3ff000`** (MAP_SHARED). Crea 6 pipes y **forkea 3 servicios seccomp'd** (VM, FILESYSTEM, EXEC) + el **padre = broker** sin seccomp. Los workers piden ops al broker por pipes.

- **VM (fork1):** seccomp = **solo read/write/exit**. Corre tu programa.
- **EXEC (fork3):** hace `popen`. Seccomp laxo.
- **Broker (padre):** ejecuta las ops privilegiadas.

**ISA relevante:** `0x0c b3 b1` = request al broker `{op, arg}` (op0=OUTPUT slot0→stdout, op1=INPUT stdin→slot0, op5=EXEC). `0x0b A B` = `memcpy(slotB, slotA, 0xff)`. `0x01/0x02` = P±=byte (**operando SIGNED**). `0x03/0x04` = P±=255·byte (unsigned). `0x05/0x06` = `mem[base+P] ±= byte`.

---

## 2. Bug #1 — el "candado" del EXEC: open() vs popen() + MD5

El opcode EXEC (broker op5) corre un **gate** (`402221`) antes de ejecutar:
1. `memcmp(cmd, "date", 4)` — prefijo.
2. **`open("../"+cmd)`** — abre el comando como PATH → `mmap` → **`MD5(contenido)` == hash pinneado de `date`**.

Si el MD5 no matchea → aborta. El gate trata `cmd` como **archivo** (`open`+MD5), pero el servicio EXEC lo corre como **comando de shell** (`popen`). Esa discrepancia es el bug — pero explotarlo por creación de archivo se traba por un **sanitizador** (`402dca`, borra `.` y `/`) y un **desajuste de directorio** (FS escribe en `sandcastle/`, el gate lee en `../`). Callejón.

**El insight ganador:** el **servicio EXEC en sí SOLO chequea `memcmp("date",4)` — el MD5 gate vive ÚNICAMENTE en el broker.** Si disparo el servicio EXEC **directo**, salteando el broker, el único chequeo es el prefijo → cualquier `date;<inyección>` corre. (Y el servicio EXEC tampoco pasa el sanitizador → puedo usar `/` literal.)

## 3. Bug #2 — puntero de VM sin bounds-check = arbitrary write

La VM usa `mem[base+P]` con `base=0x3fe000`, `P=0x800` inicial. Los opcodes de mover-P **no validan límites** → `P` arbitrario → **write arbitrario** en el espacio de fork1 (incluida la .data en direcciones fijas por No-PIE).

**Explotación — redirigir los fds de pipe:** el opcode `0x0c` escribe al fd en `mem[[0x406138]+4]` y lee de `mem[[0x406130]]` (los pipes VM↔broker). Los punteros `[0x406138]=0x3ff000`, `[0x406130]=0x3ff008`. Cambiando **un solo byte bajo** de cada uno:
- `[0x406138]` 0x00→0x28 ⇒ `0x3ff028` ⇒ `+4` = `0x3ff02c` = **write end del pipe-trigger del EXEC**.
- `[0x406130]` 0x08→0x20 ⇒ `0x3ff020` = **read end del pipe-respuesta del EXEC**.

Ahora `0x0c` **dispara el servicio EXEC directamente** (fork1 nunca cerró ese fd) → `popen("../"+slot1)` con solo el check de prefijo. La salida cae en slot2 → la leo con `copy slot2→slot0` + OUTPUT.

**Gotcha clave:** los operandos de `0x01/0x02` son **sign-extended** (`movsx`) → valores ≥128 se vuelven negativos. Hay que mover P con `0x04 122` (=+31110) y `0x01 78` (=−78) para llegar a `0x8138`, no `0x02 177`.

---

## 4. Cadena del exploit (programa de la VM, ~31 bytes)

```
0c 01 30   INPUT 0x30 → slot0            (mando "date>/dev/null;/flag-reader")
0b 00 01   copy slot0 → slot1
04 7a 01 4e  P: 0x800→0x8138  (&0x406138)   [0x04=122, 0x01=78]
06 28      [0x406138]lo += 0x28  → pipe-trigger EXEC
01 08      P → 0x8130  (&0x406130)
06 18      [0x406130]lo += 0x18  → pipe-respuesta EXEC
0c 00 00   TRIGGER: dispara EXEC directo (bypass del gate MD5)
05 18 / 02 08 / 05 28   restaurar los punteros
0b 02 00   copy slot2 → slot0   (salida del popen = flag)
0c 00 ff   OUTPUT slot0         → imprime la flag
```
Comando: `date>/dev/null 2>&1;/flag-reader` (prefijo "date" ✓, inyección `;` corre `/flag-reader`).

---

## 5. 🛡️ Defensa de entrevista (Q&A)

**P: ¿Cuál fue el bug de diseño principal?**
Separación de privilegios incompleta: el chequeo fuerte (MD5 del binario) estaba en el broker, pero el **worker EXEC confiaba** y solo revalidaba el prefijo. Al alcanzar el worker directamente (via el arbitrary-write del intérprete), el chequeo fuerte se saltea. Lección: **cada componente debe validar sus propias entradas**, no asumir que otro ya lo hizo (defense in depth).

**P: ¿Cómo conseguiste el arbitrary write?**
El puntero de datos de la VM no tenía bounds-check. Con base fija (No-PIE) y `P` libre, `mem[base+P]` alcanza cualquier dirección → cambié un byte de dos punteros de fd en `.data` para redirigir el canal IPC del intérprete hacia el pipe del servicio EXEC.

**P: ¿Por qué no hizo falta ROP ni leak de canary?**
Aunque había arbitrary R/W + canary + seccomp (read/write/exit en el intérprete), no necesité control de flujo: bastó **redirigir un pipe** para hablarle al servicio EXEC (que sí puede `execve`) directo. Mucho más simple que un ROP.

**P: ¿La trampa de implementación?**
Los operandos de mover-puntero eran **signed** — un valor `177` se volvía `-79`. Detectar la semántica exacta de cada opcode (movzx vs movsx) del disasm fue clave.

---

## 6. Mitigaciones (blue-team)

- **Validar en el punto de uso:** el worker EXEC debe re-verificar el MD5/allow-list, no confiar en el broker.
- **Bounds-check** en el puntero del intérprete (toda VM/sandbox).
- **No mezclar `open` y `popen`** sobre el mismo string; usar `execve` con argv fijo, sin shell.
- **Aislar fds:** cada worker con solo los pipes que necesita; no dejar el trigger del EXEC accesible al intérprete.

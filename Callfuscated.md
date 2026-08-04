# 🧩 Callfuscated — HTB Insane (Reversing)

> **Flag:** `HTB{Sliced_Up_the_Function_4_Ya}`
> **Autor:** ReAdventures · **Rating:** 4.9 · Escenario: *"VM, MBA, OP, JI (Junk Instructions), what are these terms. Well, now you're going to defeat them."*

Un crackme que apila **cuatro capas de anti-reversing** sobre un check trivial. El chiste del nombre: **Callfuscated = call-obfuscation**. La gracia del reto es que ninguna capa resiste el **análisis dinámico** si atacás la abstracción correcta (la VM), en vez de pelear con el asm ofuscado.

---

## 1. Triage

```
ELF64 x86-64, No-PIE (EXEC), stripped, .text ~46 KB
Imports: __libc_start_main, puts, printf, srand, scanf, rand   (¡NO time!)
```

- **No-PIE** → direcciones fijas (`main`=0x409002, buffer input=0x40f080). Enorme para instrumentar.
- **`time` no importado** → `srand()` usa seed **constante** ⇒ la secuencia `rand()` es determinista y reproducible.
- `.rodata`: `scanf("%63s")`, y en éxito `printf("Correct. Validate the challenge using the flag: %s")`. El password **es** la flag.

Comportamiento: pide password → wrong = "Incorrect flag. Try again".

---

## 2. Las 4 capas de ofuscación (y por qué no importan)

| Sigla | Qué es | Cómo la neutralicé |
|---|---|---|
| **Call-obfuscation** | Cada instrucción real envuelta en `call gadget` + `pop r8`, con `push rax;pop r8` y `call $+5` como junk. El disasm lineal es basura. | **No leer asm estático.** Single-step dinámico en **orden de ejecución** desenreda el flujo. |
| **VM** | El check corre en un intérprete de bytecode (stack machine, 8 opcodes). | **Devirtualizar dinámicamente**: tracear a nivel de opcode, no de instrucción x86. |
| **MBA** (Mixed Boolean Arithmetic) | Cada op aritmética (XOR/SUB/MUL…) implementada como polinomio lineal con constantes mágicas (`imul 0x9cbe4440`, `not`/`and`…). | **Black-box**: no simplifiqué la MBA a mano; observé `operandos → resultado` en la VM. |
| **OP + JI** (opaque predicates + junk) | Ramas siempre-tomadas y cálculos muertos con valores de `rand()`, para inflar y despistar. | **Transparentes al trace dinámico**: el flujo real es único e input-independiente. |

**Insight central:** el control-flow es **input-independiente** (192 `rand()` + 32 lecturas SIEMPRE, sin early-exit). El keystream depende solo del seed, no del input ⇒ todo lo que no sea el input es una **constante capturable**.

---

## 3. Ataque paso a paso (todo dinámico, con gdb + Python API)

### 3.1 Seed y buffer (breakpoint en `srand`/`scanf`)
```
[SRAND] edi=1337        # seed FIJO
[SCANF] buf=0x40f080    # input en .bss, %63s
```
`rand()` se llama 0 veces antes de scanf → el keystream se genera durante el check. Reproduje glibc `rand(1337)` en Python (algoritmo TYPE_3) y **matchea exacto** con los valores en runtime.

### 3.2 Longitud del password
Contando lecturas del buffer: **32 bytes siempre** (input corto se rellena con `\0`). Password = 32 chars.

### 3.3 Devirtualización — el paso clave
Localizada la **cabeza del loop VM** (`cmp pc, proglen` @ 0x40c2da) y las estructuras en el stack frame:

| Var | Rol |
|---|---|
| `[rbp-0x18]` | **PC** (índice en bytecode) |
| `[rbp-0x1c]` | longitud del programa (**586** celdas) |
| `[rbp-0x14]` | **SP** (stack de datos) |
| `[rbp-0x950]` | **bytecode** (`MEM[pc]` = opcode) |
| `[rbp-0x18f0]` | **stack de datos** (operandos) |

Trazando un hit por instrucción VM y mirando el **delta del stack**, identifiqué los 8 opcodes por su efecto (sin tocar la MBA):

| Op | Semántica | Evidencia (stack antes→después) |
|---|---|---|
| **0** | `PUSH imm` (pc+=2) | mete `MEM[pc+1]` |
| **10** | `LOAD8 [addr]` | `0x40f080 → 0x41` (lee input) |
| **5** | `MUL` | `0x41 · 0x100 = 0x4100` |
| **7** | `OR` | `0x41414100 | 0x41 = 0x41414141` |
| **8** | `XOR` | `0x41414141 ^ K1 = …` |
| **3** | `SUB` | `X - K2 = …` |
| 1, 2 | ADD/aritmética de direcciones (OP/JI) | cálculo de `&input[i]` + junk |

### 3.4 La lógica del check, desnuda
Cada **4 bytes** del password se ensamblan big-endian en un word de 32 bits, y por word `j=0..7`:

```
W_j = b[4j]<<24 | b[4j+1]<<16 | b[4j+2]<<8 | b[4j+3]     # via MUL 0x100 + OR
D_j = (W_j XOR K1_j) - K2_j                              # XOR keystream, SUB constante
FAIL |= D_j                                              # OR acumulado
```
**Éxito ⟺ FAIL == 0 ⟺ para todo j: `W_j == K1_j XOR K2_j`.**

### 3.5 Extracción de las llaves y despeje
Capturando los operandos de cada `XOR`(op8) y `SUB`(op3):

| j | K1 (keystream, rand) | K2 (constante) | W = K1⊕K2 | ASCII |
|---|---|---|---|---|
| 0 | 0915033a | 41414141 | 4854427b | `HTB{` |
| 1 | 427d7872 | 11111111 | 536c6963 | `Slic` |
| 2 | 30310a00 | 55555555 | 65645f55 | `ed_U` |
| 3 | 2a052e32 | 5a5a5a5a | 705f7468 | `p_th` |
| 4 | cff5ecdf | aaaaaaaa | 655f4675 | `e_Fu` |
| 5 | 1914031e | 77777777 | 6e637469 | `ncti` |
| 6 | f6f7c6ad | 99999999 | 6f6e5f34 | `on_4` |
| 7 | 6c6a524e | 33333333 | 5f59617d | `_Ya}` |

Concatenado: **`HTB{Sliced_Up_the_Function_4_Ya}`** ✓ (verificado corriendo el binario → imprime "Correct").

---

## 4. Por qué angr NO fue la vía
Probé `angr` (rand hookeado a la secuencia concreta). El path es **único** (no explota), pero cada op MBA genera expresiones simbólicas gigantes ⇒ **timeout** aunque sea single-path. Lección: contra MBA pesada, **devirtualizar dinámicamente > symbolic execution ciego**. angr habría servido si hookeaba las funciones MBA a su op simple — pero para eso ya necesitás haber devirtualizado, así que el trace directo cierra solo.

---

## 5. Defensa (lado azul)
- La ofuscación **no agrega seguridad real**: un XOR-SUB con constantes en un bytecode se recupera 100% en runtime. Sirve para *slow down*, no para *stop*. Contra piratería usá secretos server-side + attestation, no "esconder la clave en el cliente".
- El seed `srand()` **fijo** convierte cualquier "keystream" en constante. Nunca uses `rand()`/PRNG no-cripto para material secreto.

---

## 6. Q&A de entrevista

**P: ¿Qué es la ofuscación por MBA y cómo la atacás?**
R: *Mixed Boolean Arithmetic* reescribe una op simple (ej. `a^b`) como una combinación lineal de términos aritméticos+bit-a-bit (`a+b`, `~(a&b)`, `a|b`…) con coeficientes elegidos para que colapse al original. Ataques: simplificación algebraica (SiMBA, msynth, Z3), o **black-box** — tratás la función como caja negra, le das operandos conocidos y observás la salida para inferir la op. En un crackme no necesitás simplificarla si podés instrumentar.

**P: ¿Cómo se devirtualiza un bytecode VM sin símbolos?**
R: Ubicás el **dispatch loop** (fetch `opcode = code[pc]`, típicamente `cmp`/jump-table), y las estructuras de estado (PC, SP, arrays de código y datos) en el frame. Trazás UN hit por instrucción VM y deducís cada opcode por su **efecto en el stack**. Con eso reconstruís el programa a un IR que entendés.

**P: ¿Por qué la call-obfuscation rompe el disasm estático pero no el dinámico?**
R: Estático (linear sweep / recursive) asume flujo por caídas y saltos directos; la call-obfuscation esconde el flujo real en cadenas de `call`/`ret` + instrucciones solapadas, así que el desensamblado se desincroniza. El dinámico ejecuta el flujo REAL en orden, inmune al solapamiento.

**P: Tenías seed fijo. ¿Por qué es fatal?**
R: `rand()` sin entropía real (sin `time`/`/dev/urandom`) es 100% reproducible. Reimplementás el PRNG (glibc TYPE_3), generás el mismo keystream, y toda la "protección" cae. Regla: PRNG no-cripto **jamás** para secretos.

**P: ¿Cuándo symbolic execution (angr) y cuándo no?**
R: Brilla en checks con lógica compleja y pocos paths. Sufre con **explosión de estados** (loops/interpretes) y con **expresiones enormes** (MBA). Acá el path era único pero las expresiones MBA lo mataban → devirtualizar a mano fue más rápido. Regla práctica: si hay una VM/MBA, primero reducí la abstracción, después (si hace falta) tirás angr sobre el IR limpio.

---
*Método: ver [PLAYBOOK.md](PLAYBOOK.md) · toolkit: [ARSENAL.md](ARSENAL.md)*

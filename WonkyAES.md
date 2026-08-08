# Wonky AES — HTB (Crypto)

> **Flag:** `HTB{55fda399fc85149bdca4134b76280960}`
> **Técnica:** Differential Fault Analysis (DFA) sobre AES-128 — ataque de *fault injection* clásico (Piret-Quisquater / Dusart-Letourneux-Vivolo).
> **Resumen en una línea:** el servicio te regala, por cada plaintext, la cifra **correcta** y una **con 1 byte corrompido** a mitad del cifrado; esa diferencia filtra la última round-key → se invierte el key schedule → se recupera la key maestra → se desencripta el flag.

Escrito para estudio / prep de entrevista. Payloads/valores son ilustrativos.

---

## 1. El reto

Un binario `enc_fault` (servidor `nc`) + su fuente (tiny-AES-c estándar). Por sesión genera una **key AES-128 aleatoria** y ofrece un loop:

- **`y`** → toma un plaintext aleatorio y te imprime:
  - `Correct encryption:` = `AES-128(plain, key)`.
  - `Faulty encryption:`  = el **mismo** plaintext cifrado pero con un **fault de 1 byte** inyectado en una posición y valor aleatorios.
- **`n`** → cifra `flag.txt` (2 bloques de 16 bytes) con la misma key y te da `Flag encrypted:`.

El AES es **estándar** (S-box, Rcon, KeyExpansion, MixColumns idénticos a tiny-AES; verificado contra el test-vector NIST). Lo "wonky" es **solo el fault**.

**Dónde se inyecta el fault** (de `aes.c`, `CipherFault`):

```c
for (round = 1; ; ++round) {
    SubBytes(state); ShiftRows(state);
    if (round == Nr) break;                 // Nr=10: última ronda, sin MixColumns
    if (is_fault && round == Nr - 1)        // ronda 9
        (*state)[pos%4][pos/4] ^= fault;    // 1 byte, DESPUÉS de ShiftRows, ANTES de MixColumns
    MixColumns(state); AddRoundKey(round, state, RoundKey);
}
AddRoundKey(Nr, state, RoundKey);
```

Fault en **ronda 9, post-ShiftRows / pre-MixColumns** = exactamente el modelo del ataque DFA clásico de "1 sola MixColumns entre el fault y la salida".

---

## 2. Por qué funciona (la matemática, sin dolor)

Un fault de **1 byte** justo antes de la MixColumns de la ronda 9:

1. **MixColumns lo esparce a 1 columna** (4 bytes) con una relación fija: la diferencia de la columna es `(2·δ, δ, δ, 3·δ)` (rotada según la fila del byte faulteado), donde `δ` es el valor del fault. La matriz MDS de AES garantiza esa proporción.
2. La ronda 10 (SubBytes byte-a-byte + ShiftRows + AddRoundKey) **permuta** esos 4 bytes: terminan como una **"diagonal"** de 4 posiciones en el ciphertext.
3. Por eso, en cada par correcto/faulty, **exactamente 4 bytes difieren** y su patrón te dice **qué columna** se faulteó.

**Recuperación de 4 bytes de la última round-key (K10) por columna:**
Para cada byte de la diagonal se plantea:

```
InvSBox(C_i ⊕ K_i) ⊕ InvSBox(C*_i ⊕ K_i) = (coef · δ)
```

Se prueban las 4 posibles filas del fault × 255 valores de `δ` y, por byte, los 256 candidatos de `K_i`. Cada par deja esos 4 bytes de K10 en ~2⁸ candidatos; **≈2 pares de la misma columna → único**. Con las 4 columnas → **K10 completa**.

**De K10 a la key maestra:** el key schedule de AES es **invertible**. Dada la round-key 10 (`w[40..43]`) se recorre para atrás (`w[i-4] = w[i] ⊕ temp(w[i-1])`) hasta `w[0..3]` = **key original**.

**Del key a la flag:** desencriptar los 2 bloques `Flag encrypted` con AES-128-ECB y la key recuperada.

---

## 3. Ejecución

1. Conectar al server, mandar `y` ~60 veces, parsear cada `Correct`/`Faulty`.
2. Agrupar los pares por columna faulteada (los 4 bytes que difieren).
3. Por columna: intersectar candidatos de K10 hasta 1 → 4 bytes.
4. K10 → invertir key schedule → key maestra.
5. `n` → obtener `Flag encrypted` → desencriptar → flag.

Colecté 60 pares (sobra; con ~2 por columna alcanza) para garantizar unicidad. Resultado:

```
K10:         802391a196abb31ac55d585d3cb9c220
Master key:  7d92597cd8dbca231c665eafc156e283
FLAG:        HTB{55fda399fc85149bdca4134b76280960}
```

**Metodología** (igual que en los otros retos): **implementar y validar el solver localmente** primero — AES propio con hook de fault + un self-test que genera pares con una key random y comprueba que el DFA la recupera (y que el AES coincide con el vector NIST). Recién con el self-test en verde, apuntar al target. La tool (`solve.py`) es self-contained (AES + DFA + decrypt propios, sockets) y muestra la cadena en vivo.

---

## 4. Q&A de entrevista

**¿Qué es un fault attack / DFA?**
Inducir un error controlado durante un cómputo criptográfico (por glitch de voltaje, clock, láser, etc.) y comparar la salida correcta vs la errónea. La diferencia filtra información del secreto. DFA aplica esto a cifras de bloque: un fault bien ubicado en las últimas rondas de AES permite recuperar la round-key final con **muy pocos pares** (2-4).

**¿Por qué un solo byte de fault rompe algo "irrompible" como AES?**
AES es fuerte contra criptoanálisis de caja negra, pero DFA **no ataca el algoritmo, ataca la implementación física**. La difusión de AES (MixColumns) que normalmente lo hace seguro, acá **juega en contra**: propaga el fault con una estructura conocida que reduce el espacio de la key.

**¿Por qué la posición exacta del fault no importa acá?**
El valor y la posición son aleatorios, pero se **detectan** del par: los 4 bytes que difieren identifican la columna, y el patrón de diferencias identifica la fila/δ. No hace falta saberlos de antemano.

**¿Cómo se recupera la key maestra desde la round-key 10?**
El key schedule de AES es determinístico e **invertible**: conocida cualquier round-key completa se reconstruyen todas, incluida la original.

**¿Cómo se defiende?**
Contramedidas anti-fault: **redundancia** (cifrar dos veces y comparar, o cifrar+descifrar y verificar), **detección de sensores** (voltaje/clock/luz), checks de integridad del estado, y **no exponer jamás** salidas faulty al atacante (acá el bug de diseño es literalmente entregar el par correcto/faulty).

---

## 5. Mitigaciones (resumen)

| Problema | Fix |
|---|---|
| Se entrega la cifra faulty al usuario | nunca exponer resultados de cómputos con fallo |
| Sin detección de faults | doble cómputo + comparación; verify-after-sign/encrypt |
| Hardware sin protección | sensores de glitch, shielding, redundancia temporal/espacial |
| Key derivable de 1 round-key | (propiedad de AES) — la defensa es impedir el fault/leak, no el schedule |

> Ataque de libro, pero el detalle didáctico del reto: el binario **te regala** los pares correcto+faulty, que en un ataque real habría que **provocar** con fault injection de hardware.

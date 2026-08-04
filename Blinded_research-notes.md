# HTB — Blinded  🔴 Insane · Pwn (heap) · ⏸️ PARKED (research notes)

> Honesto: **no lo cerramos.** Estas son notas de investigación — sirven igual para el CV (demuestran análisis de un pwn brutal) y para retomarlo con las herramientas correctas.

**Stack:** binario `blinded` (PIE, Full RELRO, NX, sin canary) · **glibc 2.35** · servido por `socat`+`server.py`.

## La vuln
```c
scanf("%zu %d %hhd", &size, &i, &c);
if (... || !(0 <= i < size)) _exit(1);   // 0<=i<size  ==  (0<=i)<size  -> i NO está acotado
char* ptr = malloc(size); ptr[i] = c; free(ptr);
```
`i` es `int` → **escritura de 1 byte en offset arbitrario** (±2GB) desde un `malloc`, repetible ~2048 veces (budget 4096).

## Por qué es Insane (el muro)
- El server corre tu payload **32 veces, cada una con ASLR nuevo** (confirmado: 3 bases de libc distintas). El "leak" de `/proc/maps` es de OTRO proceso → inútil. **Exploit tiene que ser 100% determinista.**
- Escrituras solo llegan al **heap** (heap↔libc a decenas de TB, `i` solo ±2GB).
- Único puntero a libc sembrable sin leak = `main_arena` (via unsorted bin) → pero para redirigirlo, **solo el byte 0 del puntero es determinista** (los bits 12-15 son ASLR random y comparten byte). Cruzar página = 1/16 → con 32/32, `(1/16)³²` ≈ 0. **Muerto el brute force.**

## Hasta dónde llegamos (primitivo VERIFICADO)
1. ✅ Escritura arbitraria de heap (determinista, vía `i = diff de offsets`).
2. ✅ Control total del `tcache_perthread_struct` (counts @ `heap+0x10`, entries @ `heap+0x90`).
3. ✅ **Sembrado de `main_arena` en el heap** (House of Water): counts[idx]=8 + guard chunk → `free` va a unsorted → `fd/bk = main_arena` en offset conocido del heap.
4. ✅ Ordenado unsorted → **smallbin** (paso previo al stashing).

## Lo que falta (y por qué se trabó)
- El **stashing** para meter el puntero libc en `entries` necesita 2 chunks en smallbin; con el primitivo (malloc→free de a uno) hay que forjar metadata (House of Water real).
- **El endgame determinista:** aun con escritura arbitraria en libc, meter la dirección de `system`/one_gadget en un puntero que se llame requiere partial-overwrite de un puntero existente en la MISMA ventana de 256 bytes → **hace falta `one_gadget` + gdb** para encontrar ese gadget en esta libc. La técnica canónica (House of Water) usa 1/16, que acá no sirve.

## Para la revancha (checklist)
- [ ] Instalar `gdb` + `gef`/`pwndbg` + `one_gadget` (necesita root en la WSL).
- [ ] Completar el tcache-stashing → allocación en libc → escritura arbitraria de libc.
- [ ] Encontrar cadena FSOP **fully-deterministic** (stdin vtable → `system("cat password")`).
- Entorno local ya montado en `scratchpad/blindwork/` (binario + libc 2.35 + `dbg.c` = clon instrumentado rayos-X del heap).

## Rematch con tooling completo (gdb + one_gadget + pwntools) — HALLAZGO DURO
Con las herramientas instaladas, el chequeo decisivo:
- one_gadgets: `0xebcf5, 0xebcf8, 0xebd52, 0xebda8, 0xebdaf, 0xebdb3`.
- **Escaneé las 1197 relocations RELATIVE de la libc: 0 punteros de datos dentro de la ventana de 256 bytes (ni misma página 4KB) de `system`(0x50d60) o de cualquier one_gadget.**
- Conclusión: **no hay fuente determinista para el último `call`.** Aunque logres un vtable-switch determinista (`_IO_file_jumps`→`_IO_wfile_jumps`), el `__doallocate`/slot final igual exige una dirección de código de libc, que no se puede escribir sin leak ni partial-overwrite en-window (no existe).
- Por eso la solución del autor es una **técnica exótica** (data-only FSOP / "nibble spray" que cubra los 16 valores de ASLR en una sola corrida, o algo equivalente). Eso es research de frontera, no adaptación de técnica conocida.

**Veredicto honesto:** con tooling completo, el heap primitive está resuelto pero el endgame determinista sigue sin caer. No es un problema de herramientas ni de esfuerzo — es que este reto vive en el techo de una sub-especialidad.

## Aprendizaje para el CV
Distinguir **CTF vs vida real**: un heap pwn ciego determinista 32/32 es nicho de *exploit-dev* (Project Zero / APT), no pentest diario. Saber analizarlo y explicar por qué es duro ya vale — pero para empleabilidad rinden más **web y AD**.

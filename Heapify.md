# Heapify — HTB (Pwn, Insane)

> **Flag:** `HTB{dd148d2b41d538fa950eee1f6a1fa9ce}`
> **Técnica:** explotación de heap en glibc 2.35 sin primitiva de lectura — leak de heap por *safe-linking* + oráculo de orden de pop, leak de libc por `malloc_consolidate`, OOB en un min-heap mal programado → *free* arbitrario → tcache poisoning → **FSOP House of Apple 2**.
> **Resumen en una línea:** una priority-queue de "comandos" vive sobre el heap; `downheap` no chequea el límite del array y, al hundir un elemento a un índice profundo, lee/escribe **fuera** del struct sobre el chunk vecino → con eso se fabrica un *free* de un puntero elegido, se envenena el tcache y se apunta `_IO_list_all` a un `FILE` falso que en `exit()` dispara `system("/bin/sh")`.

Escrito para estudio / prep de entrevista. Los payloads son mínimos e ilustrativos; el foco es el *porqué* de cada paso. Exploit completo validado 12/12 en local; corrió al **primer intento** en el remoto.

---

## 1. El reto

Un binario `heapify` (glibc **2.35**, provisto con su `ld` y `libc.so.6`). Protecciones **completas**: PIE + **Full RELRO** + NX + Canary, y glibc 2.35 → **sin `__malloc_hook`/`__free_hook`**. El menú:

```
1. Send a command      2. Execute a command
```

Estructura global `heap = calloc(1, 0x200)` (un array **en el heap** — de ahí "heap on the heap"):

```
heap[0x000] = count (int)
heap[0x008 + i*8] = slots[i]   ->  punteros a chunks   (63 slots, i = 0..62)
```

- **Send** (`send_cmd`): `size ∈ [1, 0x70]`, `malloc(size+8)`; el chunk es `[prio : 8 bytes][data : size]`. La **prioridad** se lee con `scanf("%zu")` (entero 64-bit **totalmente controlado**), la data con `fgets`. Luego `add_cmd` + `upheap`.
- **Execute** (`exec_cmd`): `remove_min` (saca la raíz, el de menor prioridad) → `do_cmd(chunk+8)` → **`free(chunk)`**.

`do_cmd` es un intérprete troll: `strcmp("flag")` imprime una **flag falsa** ("Congratulations, here's the flag: HTB{fo0L_m3...}"), y comandos como `id`, `realflag`, `ratio`, `sudo rm -rf /` devuelven strings fijas. **No hay ninguna primitiva de lectura de memoria** (ni `view`, ni `%s` sobre algo controlado). Todo el leak hay que sacarlo de **canales laterales**.

---

## 2. El bug: `downheap` no chequea el límite del array

Un min-heap binario clásico. Al sacar la raíz, `downheap` "hunde" el último elemento comparándolo con sus hijos:

```c
void downheap(heap *h){
  int i = 0;
  while (i < h->count){
    int left = 2*i+1, right = 2*i+2;
    if (h->slots[left] == 0) break;          // <-- detecta "hoja" por el zero-fill del calloc
    ... elige el hijo menor, swap, i = hijo ...
  }
}
```

El corte de "llegué a una hoja" se hace mirando **`slots[left] == 0`** (confía en que `calloc` dejó ceros), pero **nunca chequea `left < count`**. El array tiene 63 slots (`0..62`). Cuando un elemento se hunde hasta el **índice 32**:

```
left = 2*32 + 1 = 65   ->  slots[65]  está FUERA de los 512 bytes del struct
```

`slots[65]` cae sobre el **chunk físicamente adyacente** al struct del heap. Es decir: **OOB read/write controlable**. (En `i=31`, `left=63` = `*(heap+0x200)` = el `prev_size` del chunk vecino = 0 → se detecta hoja OK, sin daño. `i=32` es el primer índice tóxico.)

El layout OOB (chunks de 0x20): `slots[63]`=prev_size(0), `slots[64]`=size(0x21), **`slots[65]`=prio del 1er chunk físico**, `slots[66]`=su data, etc.

**La sutileza que traba a mucha gente:** `downheap` **derefiere** `slots[65]` como puntero (lee `*slots[65]` para comparar prioridades). Con una prioridad normal ahí, crashea; y sin un leak previo no hay dirección válida que poner → dependencia circular. La salida es no depender del deref: se leakea **antes**, por canal lateral, y recién con `heap_base` conocido se apunta ese slot a memoria mapeada.

---

## 3. Los primitivos (y por qué funcionan)

### 3.1 Heap leak sin lectura — `scanf`-fail + safe-linking + oráculo de orden de pop

glibc 2.35 protege el `fd` del tcache con **safe-linking**: el primer chunk liberado en un bin guarda `fd = (dirección_del_chunk) >> 12` (por `PROTECT_PTR(&fd, NULL)`). O sea: en cuanto liberás un chunk a un tcache vacío, en su primer qword queda **`heap_base >> 12`** — ¡un leak del heap listo para usar!

¿Cómo sacarlo sin poder leer memoria? Dos trucos combinados:

1. **`scanf("%zu")` que falla NO escribe el destino.** Si a la prioridad le mandás algo no numérico (`"z"`), el `scanf` falla y **deja intacto** el qword. Al **reusar** un chunk recién liberado (que ya tiene `fd = heap>>12` en su primer qword), su prioridad queda siendo **`heap>>12`**.
2. **Oráculo por orden de pop.** No podés leer el valor, pero podés *comparar* prioridades: el min-heap saca primero al de menor prioridad, y `do_cmd` **imprime distinto** según la data (`"flag"`→"Congratulations" vs otra cosa→"Invalid command!"). Metés el chunk-objetivo con data `"flag"` (prio = `heap>>12`, desconocida) y una **sonda** con prioridad `P` conocida; ejecutás y mirás cuál salió primero → **1 bit**: `heap>>12 < P` o no.

En vez de binary-search de 1 bit/query, uso un **oráculo de rango**: meto *k=15 sondas* por ronda que parten el intervalo en 16 → **~4 bits por ronda**. La última ronda desempata con **una sola** sonda (tie-free: `upheap` no intercambia en empate, así que el objetivo —insertado primero— queda en la raíz, y `r==0 ⇔ objetivo == sonda`). Resultado: `heap_base` **exacto, 12/12**, buscando en `[0, 2³⁶)` sin asumir nada del ASLR.

### 3.2 Libc leak sin OOB — `malloc_consolidate` + dispensador del `last_remainder`

Para libc necesitamos un puntero a `main_arena` (que vive en libc). El truco elegante evita el OOB por completo:

1. Se llenan **29 chunks de 0x80** contiguos: 7 van al **tcache** (lo llenan) y 22 al **fastbin**, quedando **físicamente adyacentes**.
2. Se dispara **`malloc_consolidate`** con un truco de bordes: mandar el `size` con **~70.000 dígitos** hace que el `scanf` interno pida un `malloc` gigante (>0x400), lo que **fusiona los fastbins** en un único chunk grande que va al **unsorted bin**. Su `fd`/`bk` = `&main_arena.bins[0]` = **`libc_base + 0x219ce0`**.
3. Cada `malloc(0x60)` siguiente sale del **split del `last_remainder`**: el usuario recibe un chunk cuyo `user[0]` es justo ese puntero a libc. Se leakea con el **mismo oráculo** de la sección 3.1 (rango de 47 bits) → `libc_base`.

### 3.3 De la OOB a un *free* arbitrario

Con `heap_base` conocido ya podemos usar la OOB sin crashear:

- Se prepara un chunk falso `Ff` en una dirección conocida (dentro de la data de un chunk controlado), con un `size` forjado (`0x41`) y `*Ff = 0`.
- Se hace que el elemento que se hunde a `i=32` deje en `slots[32]` el valor **`Ff`** (el swap de `downheap` escribe ahí el qword que elegimos = la prioridad del 1er chunk físico, que apuntamos a `Ff`).
- Como `*Ff = 0` (prioridad mínima), `Ff` **burbujea hasta la raíz** y, unos `execute` después, el programa hace **`free(Ff)`** → tcache poisoning listo.

**Detalle clave de este reto:** el groom se hace con **34 elementos, no 63**. Con 34, tras el pop quedan 33 y el único nodo de nivel-5 alcanzable es el índice 32 (todas las demás ramas terminan en un slot 0). Con 63 elementos el hundimiento llega a hojas 38-61 = memoria no controlada → crash. Reducir el árbol es lo que hace el OOB *dirigible*.

### 3.4 Tcache poisoning → `_IO_list_all`

Con `free(Ff)` hecho, el tcache 0x40 tiene a `Ff`. Se sobreescribe su `fd` con el target **manglado** por safe-linking:

```
fd = (Ff >> 12) ^ (LIBC + _IO_list_all)
```

Dos `malloc(0x30)` más: el primero saca a `Ff`, el segundo devuelve **`&_IO_list_all`** como chunk → escribimos ahí el puntero a nuestro **`FILE` falso**.

### 3.5 El endgame: FSOP House of Apple 2

glibc 2.35 no tiene hooks, así que el clásico es **falsificar un `FILE`** y engancharlo en la cadena de flush que corre en `exit()`. La técnica **House of Apple 2** usa la **vtable ancha** (`_wide_data->_wide_vtable`), que —a diferencia de la vtable normal— **no** pasa por `IO_validate_vtable`:

- `FILE.vtable = _IO_wfile_jumps` (esta sí válida, pasa el check) → su `__overflow` = `_IO_wfile_overflow`.
- `FILE._wide_data = W` (falso), `W->_wide_vtable = VT` (falso), `VT->__doallocate = system`.
- `FILE._flags` (los primeros 8 bytes del `FILE`) = **`"AA;/bin/sh"`** → como `rdi` de `system` apunta al `FILE`, `system(FILE)` = `system("AA;/bin/sh")`.

En `exit(1)` (que se dispara mandando una opción de menú inválida, `3`), `_IO_flush_all` recorre `_IO_list_all`, ve nuestro `FILE` con `_IO_write_ptr > _IO_write_base` y llama `_IO_OVERFLOW` → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `_wide_vtable->__doallocate(FILE)` = **`system("AA;/bin/sh")`** → **shell**.

---

## 4. El bug que casi me come vivo (y la lección)

Con **toda** la cadena montada y cada campo del `FILE` verificado byte-a-byte en memoria, `exit()` salía **limpio, sin shell**. El trace con gdb mostró que `_IO_wfile_overflow` **se ejecutaba** sobre nuestro `FILE`… pero **saltaba** `_IO_wdoallocbuf`.

El motivo está en el disassembly:

```asm
_IO_wfile_overflow:
  mov eax, [rdi]          ; eax = _flags
  test al, 0x8            ; _IO_NO_WRITES  (byte 0, bit 3)
  jne  return_WEOF
  test ah, 0x8            ; _IO_CURRENTLY_PUTTING = 0x800  (byte 1, bit 3)
  jne  skip_alloc         ; <-- si está puesto, SALTEA _IO_wdoallocbuf
```

Mi `_flags` era **`" /bin/sh"`**. El **segundo byte** es `'/'` = `0x2f`, y `0x2f & 0x08 = 0x08` → el bit `0x800` (`_IO_CURRENTLY_PUTTING`) quedaba **puesto** → la función creía que ya estaba "escribiendo" y no allocaba buffer → **nunca llamaba a `system`**.

`_flags` cumple **doble rol**: es el argumento de `system` **y** controla el flujo de `_IO_wfile_overflow`. Los dos primeros bytes deben tener **limpios** los bits:

| bit | flag | dónde se chequea |
|---|---|---|
| `0x2` (byte 0) | `_IO_UNBUFFERED` | `_IO_wdoallocbuf` saltea `__doallocate` si está puesto |
| `0x8` (byte 0) | `_IO_NO_WRITES` | `_IO_wfile_overflow` retorna temprano |
| `0x800` (byte 1) | `_IO_CURRENTLY_PUTTING` | saltea el `_IO_wdoallocbuf` |

`'A' = 0x41` cumple los tres. Solución: **`_flags = "AA;/bin/sh"`** — `sh -c "AA;/bin/sh"` ejecuta `AA` (comando inexistente, error a stderr) y luego `/bin/sh` interactiva. Con eso + `_chain = NULL` (para que el loop de flush corte tras nuestro `FILE`), salió el shell.

**Lección:** en FSOP, el `_flags` no es "relleno": cada bit puede desviar el flujo. Cuando el `FILE` está perfecto pero no dispara, sospechar de los **bits bajos de `_flags`** antes que de cualquier otra cosa.

---

## 5. Ejecución (de punta a punta)

```
P0  reservar 2 chunks de dirección fija (anchor = slots[65], K = portador del chunk falso)
P1  heap leak   : scanf-fail + safe-linking + oráculo de rango           -> heap_base
P2  libc leak   : consolidate + dispensador del last_remainder + oráculo  -> libc_base
P3  escribir el payload FSOP en 6 chunks 0x80 reciclados del tcache (contiguos, dir conocida)
P4  groom de 34 elementos que hunde un elemento al índice 32
P5  OOB de downheap: slots[32] = Ff  -> Ff burbujea -> free(Ff)
P6  tcache poison: Ff.fd = (Ff>>12) ^ (&_IO_list_all)
P7  malloc x2 -> _IO_list_all = FILE falso
P8  menu "3" -> exit(1) -> _IO_flush_all -> House of Apple 2 -> system("AA;/bin/sh")
```

Metodología (como en los otros retos): **modelo local primero**. El harness (`hx.py`) incluye un **simulador fiel del min-heap** (espejo exacto de `upheap`/`downheap`) y un **modelo de conteos del allocator** (tcache/fastbin/top/dispensador) que **predice la dirección de cada chunk** — sin eso, ubicar el payload en direcciones conocidas es imposible. Todo se valida contra `/proc/pid/maps` y `/proc/pid/mem` en local (assertions que abortan si un leak difiere del real) antes de apuntar al remoto. Resultado local: **12/12** exacto. Remoto: **1er intento**.

```
[+] SHELL abierta
HTB{dd148d2b41d538fa950eee1f6a1fa9ce}
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
```

---

## 6. Q&A de entrevista

**¿Qué es "un heap sobre el heap" y por qué complica el exploit?**
La estructura de control de la priority-queue (el array `slots[]`) vive **dentro** del heap de glibc, pegada a los chunks de datos. Eso convierte un overflow del array (por el bug de límite) en un **overlap** directo con metadatos/datos de chunks vecinos — pero también significa que no hay direcciones "estáticas" que leakear: todo se randomiza junto y hay que derivar cada dirección del `heap_base`.

**No hay función de lectura. ¿Cómo se leakea una dirección?**
Por **canal lateral**. El único observable es el *orden* en que salen los elementos (y el string que imprime `do_cmd`). Una comparación de prioridades = 1 bit de información sobre un valor secreto. Con safe-linking, el `fd` del tcache **es** `heap>>12`; metiéndolo como prioridad (vía `scanf`-fail) y comparándolo contra sondas conocidas, se reconstruye bit a bit. Es un **oráculo de comparación**, igual que un ataque de padding oracle pero sobre el heap.

**¿Por qué `scanf("%zu")` que falla ayuda?**
Porque el estándar C dice que un `scanf` que no matchea **no toca** el destino. Entonces, si el destino ya contenía un valor útil (el `fd = heap>>12` que safe-linking plantó al liberar el chunk), ese valor **sobrevive** y se convierte en la prioridad del chunk reusado. Es un "leak sin leer": escribo el secreto en un campo comparable.

**¿Qué es safe-linking y cómo lo derrotás?**
Mitigación de glibc ≥2.32: el `fd` de tcache/fastbin se guarda como `(dirección) >> 12 XOR fd_real`. El **primer** free a un bin vacío deja `fd = &chunk >> 12` (XOR con 0). Eso *es* un leak del heap (los 12 bits bajos se conocen: son 0 por alineación de página). Para el poison, se re-manglea: `fd_a_escribir = (chunk_actual >> 12) ^ target`.

**¿Por qué `malloc_consolidate` da un leak de libc "gratis"?**
Al consolidar fastbins adyacentes en un chunk grande, ese chunk va al **unsorted bin**, cuyo `fd`/`bk` apuntan a `main_arena` (en libc). Los `malloc` siguientes parten ese chunk (`last_remainder`) y devuelven pedazos cuyo primer qword todavía tiene el puntero a `main_arena`. Es el leak de libc clásico del unsorted bin, pero disparado sin necesidad de forjar tamaños con la OOB.

**¿Por qué House of Apple 2 y no un one-gadget o `__free_hook`?**
glibc 2.35 **eliminó** `__malloc_hook`/`__free_hook`. Un one-gadget necesita que se cumplan sus constraints de registros en el momento del call, lo que acá no controlamos. House of Apple 2 es robusto: falsifica un `FILE` y usa la **vtable ancha**, que **no** valida (a diferencia de la vtable normal, protegida por `IO_validate_vtable` desde 2.28), para redirigir `__doallocate` a `system` con `rdi` = el propio `FILE` (que empieza con la string del comando).

**¿Cómo se dispara la cadena FSOP?**
`exit()` corre `_IO_cleanup` → `_IO_flush_all`, que recorre la lista `_IO_list_all` y hace `_IO_OVERFLOW` en cada `FILE` con salida pendiente. Envenenando `_IO_list_all` para que apunte a nuestro `FILE` falso, controlamos ese flush. Acá el `exit(1)` se consigue gratis mandando una opción de menú inválida.

**El detalle más fino que casi te cuesta el reto:**
`_flags` de un `FILE` no es relleno: sus bits bajos deciden ramas dentro de `_IO_wfile_overflow`/`_IO_wdoallocbuf`. Como `_flags` es *también* el string que recibe `system`, hay que elegir una cadena que (a) spawnee un shell y (b) tenga limpios `0x2`/`0x8`/`0x800` en los dos primeros bytes. `" /bin/sh"` falla por el `/` (0x2f); `"AA;/bin/sh"` funciona.

**¿Cómo fue el proceso de debug del "todo perfecto pero no dispara"?**
Grabé el stream de entrada, saqué un corefile (`io.corefile`), identifiqué que el crash pasaba *después* de nuestro `FILE` (siguiendo un `_chain` basura), lo corté con `_chain=NULL`, y cuando aun sin crash tampoco había shell, tracé `_IO_wfile_overflow` con breakpoints por dirección absoluta (base leakeada) y vi el `test ah,0x8; jne` que salteaba el allocate. El bit malo estaba en `_flags`.

---

## 7. Mitigaciones (resumen)

| Problema | Fix |
|---|---|
| `downheap` no chequea `left < count` | validar índice de hijo contra `count` antes de indexar `slots[]` (el bug raíz) |
| Estructura de control (array) mezclada con datos en el heap | separar metadatos de datos; no poner el array de punteros en un chunk de heap contiguo a datos del usuario |
| `scanf` que falla deja el buffer intacto y reusable | inicializar el destino antes del `scanf`; chequear el valor de retorno |
| Prioridad = 64-bit crudo controlado por el usuario | acotar/validar el rango de prioridades; no derivar comportamiento observable del orden exacto |
| Sin ASLR de heap efectivo frente al oráculo | (defensa de diseño) no exponer un oráculo de comparación observable |
| `_IO_list_all` / vtable ancha explotables | glibc endurece la vtable normal, pero la ancha sigue siendo vector → CFI/`_FORTIFY`, y no dejar escrituras arbitrarias que alcancen punteros de FILE |

> Reto de manual de heap moderno: **un solo `<` faltante** en un chequeo de límite, apalancado con oráculos de canal lateral (porque no hay lectura) y rematado con FSOP porque glibc 2.35 ya no regala hooks. La parte más didáctica es que **no hay ningún leak "directo"**: cada dirección se reconstruye observando el *comportamiento* del programa, no su memoria.

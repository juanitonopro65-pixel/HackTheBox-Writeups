# 🎮 OverTheWire — Bandit (0→12) · material de comunidad / Semana Cero

> **Para qué sirve:** Bandit es el ladder canónico de **fundamentos de Linux + línea de comandos** para quien arranca. No es "hacking" avanzado: es la base que TODO pentester necesita antes de tocar AD, web o pwn. Ideal para la Semana Cero del grupo.
> **Cómo se juega:** cada nivel guarda el password del siguiente en algún lado de la máquina. Entrás por SSH como `banditN` con el password que encontraste, y buscás el de `banditN+1`.
> **Entorno:** `ssh banditN@bandit.labs.overthewire.org -p 2220`. Sin VPN, sin instalar nada, legal por diseño. Password de arranque: usuario `bandit0`, pass `bandit0`.

Resuelto de forma **autónoma** con un harness (paramiko) que encadena los niveles — pero acá va explicado **a mano**, que es como el estudiante debe hacerlo la primera vez.

---

## Los niveles y el concepto que enseña cada uno

| Nivel | Dónde está el password | Comando | Concepto que enseña |
|---|---|---|---|
| **0→1** | archivo `readme` en el home | `cat readme` | leer archivos, `ls -la`, el home |
| **1→2** | archivo llamado `-` | `cat ./-` | un `-` se confunde con "stdin/flag" → prefijá `./` para tratarlo como ruta |
| **2→3** | archivo `spaces in this filename` | `cat "spaces in this filename"` | espacios en nombres → comillas o `\ ` |
| **3→4** | archivo **oculto** en `inhere/` | `ls -a inhere; cat inhere/...Hiding-From-You` | archivos ocultos (`.` al inicio), `ls -a` |
| **4→5** | el único archivo **de texto** entre 10 | `file inhere/-file0*` → `cat` el ASCII | `file` identifica tipo real por *magic bytes*, no por extensión |
| **5→6** | archivo de **1033 bytes**, legible, no ejecutable, en `inhere/` | `find inhere -type f -size 1033c ! -executable` | `find` por tamaño/permisos = superpoder de recon |
| **6→7** | en **todo el server**: user `bandit7`, group `bandit6`, 33 bytes | `find / -user bandit7 -group bandit6 -size 33c 2>/dev/null` | `find` global por dueño/grupo; `2>/dev/null` para silenciar ruido |
| **7→8** | en `data.txt`, junto a la palabra `millionth` | `grep millionth data.txt` | `grep` = buscar texto dentro de archivos |
| **8→9** | la **única línea** que aparece una sola vez | `sort data.txt \| uniq -u` | `sort`+`uniq` (uniq necesita input ordenado); `-u` = líneas únicas |
| **9→10** | strings legibles precedidas de varios `=` | `strings data.txt \| grep '==='` | `strings` extrae texto de binarios |
| **10→11** | `data.txt` en **base64** | `base64 -d data.txt` | encoding ≠ cifrado; base64 se decodifica trivial |
| **11→12** | `data.txt` en **ROT13** | `cat data.txt \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` | `tr` para sustitución de caracteres; ROT13 |

**Passwords (para verificación del instructor — no spoilear al alumno):** cadena válida obtenida en vivo, bandit1=`6y2kwn…`, …, bandit12=`GROozWPO8QyN0mGrjUkID0WCYkZiQxrN`.

---

## Lo que sigue (13+) — se pone interesante

Del 13 en adelante ya no es solo "buscar un archivo"; son técnicas reales que transfieren a pentest:

- **13:** te dan una **clave SSH privada** → `ssh -i sshkey.private` (autenticación por clave, no password).
- **14:** mandar el password al **puerto 30000** de localhost → `nc localhost 30000` (interacción con servicios).
- **15/16:** el servicio habla **SSL/TLS** → `openssl s_client -connect ...`; luego `nmap` para descubrir puertos + servicios SSL.
- **17:** `diff` entre dos archivos.
- **18:** `.bashrc` malicioso que te patea → `ssh ... 'comando'` (ejecutar sin shell interactiva).
- **19→20:** **binario setuid** → concepto base de **privesc en Linux** (correr como otro usuario).
- **21→23:** **cron jobs** (tareas programadas) y scripts writable corridos por otro usuario = privesc clásico.
- **24:** brute-force de un **PIN de 4 dígitos** contra un daemon → scripting de fuerza bruta.
- **25/26/32:** **escapes de shell restringida** (vim `:!`, `more`, `sh`) = romper una jaula.

Estos (setuid, cron, shell-escape) son exactamente los vectores de **privesc Linux** del [ARSENAL.md](ARSENAL.md) §6.

---

## Ruta de práctica autónoma (dónde probarse, sin VPN)

| Entorno | Qué entrena | Acceso |
|---|---|---|
| **OTW Bandit** | fundamentos Linux/CLI | SSH :2220 (hecho 0→12) |
| **OTW Natas** | **web** (LFI, SQLi, cookies, código fuente) | HTTP, navegador/curl |
| **OTW Leviathan / Behemoth** | privesc, binarios simples | SSH |
| **OTW Krypton** | **crypto** clásica | SSH |
| **OTW Narnia** | **pwn** (buffer overflow básico) | SSH |
| **HTB Challenges** | web/rev/crypto/pwn más duros | descarga offline, sin VPN |
| **HTB Machines / GOAD** | **AD** y cadenas completas | requieren VPN o lab virtualizado |

> Método: [PLAYBOOK.md](PLAYBOOK.md) · toolkit: [ARSENAL.md](ARSENAL.md). Regla de la casa: solo objetivos autorizados (OTW/HTB/lab propio lo son por diseño).

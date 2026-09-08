# 💉 OS Command Injection

> **La idea:** cuando una app arma un comando del sistema pegando texto que vos controlás, podés colar tus propios comandos y hacer que el servidor los ejecute por vos.

---

> ⚠️ **Marco de trabajo.** Esta técnica solo se practica contra objetivos que tenés autorización explícita para probar. Todo lo de esta clase corre en el **lab local `vulnlab.py`** de la comunidad, en tu propia máquina (`http://127.0.0.1:5000`). Lanzar esto contra un sistema ajeno sin permiso escrito es un delito. No hay excepciones.

---

## 1. Qué es y por qué importa

Muchas aplicaciones necesitan pedirle algo al sistema operativo: hacer un `ping`, convertir una imagen, comprimir un archivo. Para eso arman una **línea de comando** como texto y se la pasan a un shell (bash, sh) para que la ejecute.

El problema aparece cuando parte de esa línea es **input del usuario** y se pega tal cual, sin filtrar. El shell no distingue "dato" de "comando": para él, ciertos caracteres (`;`, `|`, `&`, `` ` ``, `$()`) significan *"acá termina un comando y empieza otro"*. Si vos podés meter uno de esos caracteres, dejás de mandar un dato y empezás a mandar **órdenes**.

**Impacto:** ejecución de comandos arbitrarios con los privilegios del proceso web. En la práctica eso suele ser:
- Leer archivos sensibles (`/etc/passwd`, claves, configs, tokens).
- Robar credenciales y variables de entorno.
- Abrir una **reverse shell** y tomar control total del servidor.
- Usar la máquina como pivote para moverse dentro de la red interna.

Es una de las vulnerabilidades más críticas que existen: pasa directo de "una URL rara" a "soy dueño del servidor".

---

## 2. Montar el lab

La comunidad usa un único laboratorio vulnerable, `vulnlab.py`. Instalá las dependencias y levantalo:

```bash
pip install flask requests lxml pyjwt && python3 vulnlab.py
```

Queda escuchando en `http://127.0.0.1:5000`.

**Endpoint de esta clase:**

```
GET /ping?host=<valor>
```

La idea legítima del endpoint es simple: le pasás una IP o un host y te devuelve el resultado de hacerle `ping`. Esa es exactamente la funcionalidad que vamos a abusar.

---

## 3. El ataque, paso a paso

### Paso 1 — Uso normal (baseline)

Primero vemos cómo se comporta con un valor esperado:

```bash
curl "http://127.0.0.1:5000/ping?host=127.0.0.1"
```

Devuelve algo como:

```
64 bytes from 127.0.0.1...
```

Todo normal: le pasamos una IP, nos hace el ping.

### Paso 2 — Inyectar un segundo comando

Ahora, en vez de solo una IP, encadenamos un comando extra con `;`:

```bash
curl "http://127.0.0.1:5000/ping?host=127.0.0.1;id"
```

**Output real:**

```
64 bytes from 127.0.0.1...
uid=1000(Meowju) gid=1000(Meowju) groups=1000(Meowju)
```

El servidor primero hizo el `ping` **y después ejecutó `id`**, un comando que nosotros nunca deberíamos haber podido correr. La segunda línea de salida (`uid=1000(Meowju)...`) es la prueba: acabamos de ejecutar código en el servidor.

### Por qué funciona

El código detrás del endpoint hace esto:

```python
# VULNERABLE
subprocess.run("ping -c 1 " + host, shell=True)
```

Dos decisiones lo rompen:

1. **Concatenación de string:** el `host` que mandamos se pega directo a la línea `ping -c 1 `.
2. **`shell=True`:** en vez de ejecutar `ping` como programa con argumentos, Python le entrega toda la línea a `/bin/sh -c "..."`. Y el shell **interpreta los metacaracteres**.

Cuando mandamos `127.0.0.1;id`, el shell recibe:

```sh
ping -c 1 127.0.0.1;id
```

Para el shell, el `;` separa dos comandos independientes: ejecuta `ping -c 1 127.0.0.1`, y después ejecuta `id`.

**El concepto reusable:** *cualquier* input que termine dentro de un shell puede inyectar comandos usando metacaracteres. No es solo el `;`. Sirven todos estos:

| Metacaracter | Qué hace |
|---|---|
| `;` | Ejecuta el siguiente comando después del primero |
| `|` | Pasa la salida del primero como entrada del segundo (o encadena) |
| `&` / `&&` | Ejecuta en segundo plano / si el anterior tuvo éxito |
| `` `cmd` `` | Sustitución de comando (ejecuta `cmd` y mete su salida) |
| `$(cmd)` | Sustitución de comando (forma moderna) |

Si podés meter uno de estos en un parámetro que llega a un shell, tenés command injection.

---

## 4. Blue Team

### Firma de detección

La señal clásica: **metacaracteres de shell apareciendo dentro de parámetros HTTP** que normalmente contienen datos simples (un host, un nombre de archivo, un ID). Ver `;`, `|`, `&`, `` ` `` o `$(` en un parámetro como `host=` es altamente sospechoso — un host legítimo nunca los lleva.

### Regla Sigma

```yaml
title: Posible OS Command Injection en parametro HTTP
id: 7f3c1a94-2b6e-4d81-9a4f-0c5e8b2d1f63
status: experimental
description: Detecta metacaracteres de shell en parametros de peticiones web, indicio de intento de inyeccion de comandos del SO.
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - ';'
      - '|'
      - '&&'
      - '`'
      - '$('
      - '%3B'   # ; url-encoded
      - '%7C'   # | url-encoded
  condition: selection
fields:
  - c-ip
  - cs-uri-stem
  - cs-uri-query
falsepositives:
  - Parametros que legitimamente contienen estos caracteres (raro; requiere allow-list previa)
level: high
```

> Nota: incluí las variantes URL-encoded (`%3B`, `%7C`) porque un atacante suele codificar los metacaracteres para pasar filtros ingenuos.

### Mapeo MITRE ATT&CK

| Técnica | ID | Relación |
|---|---|---|
| Command and Scripting Interpreter | **T1059** | El servidor ejecuta comandos arbitrarios vía shell |
| Command and Scripting Interpreter: Unix Shell | **T1059.004** | El intérprete concreto abusado es `/bin/sh` |
| Exploit Public-Facing Application | **T1190** | El vector de entrada es la app web expuesta |

### Mitigación (el fix correcto)

La causa raíz es entregar input a un shell. El fix es **no usar un shell** y pasar los argumentos como **lista**, para que el input nunca se interprete como sintaxis:

| ❌ Vulnerable | ✅ Correcto |
|---|---|
| `subprocess.run("ping -c 1 " + host, shell=True)` | `subprocess.run(["ping", "-c", "1", host])` |

```python
# FIX correcto
import subprocess, re

# 1) Validar PRIMERO (allow-list estricta): aceptar solo lo esperado.
#    Si el valor trae un metacaracter (p.ej. "127.0.0.1;id" tiene ';'),
#    se rechaza ANTES de tocar el sistema. La validacion debe ir antes
#    de ejecutar, no despues.
if not re.fullmatch(r"[A-Za-z0-9.\-]+", host):
    raise ValueError("host invalido")

# 2) Sin shell + lista de argumentos: cada elemento es un argumento
#    literal, no sintaxis. Aunque algo se colara, "127.0.0.1;id" seria
#    UN host invalido para ping, nunca dos comandos.
subprocess.run(["ping", "-c", "1", host])
```

**Las dos capas:**
1. **`shell=False` + lista de argumentos** (default de `subprocess`): elimina la interpretación de metacaracteres. Es el arreglo estructural principal.
2. **Allow-list / validación estricta, aplicada ANTES de ejecutar:** aceptá solo lo que esperás (letras, dígitos, puntos, guiones para un hostname) y rechazá todo lo demás. Nunca uses una "black-list" de caracteres prohibidos: siempre se te escapa uno.

---

## 5. Q&A de entrevista

**1. ¿Cuál es la causa raíz de un command injection, y por qué "escapar el `;`" no alcanza como fix?**
La causa raíz es pasar input del usuario a un intérprete de shell (`shell=True`), donde ciertos caracteres tienen significado sintáctico. Filtrar el `;` no alcanza porque hay muchos otros metacaracteres (`|`, `&`, `` ` ``, `$()`, saltos de línea…) y variantes de codificación; una black-list siempre deja huecos. El fix real es eliminar el shell y pasar argumentos como lista, para que el input nunca se interprete como sintaxis.

**2. ¿Cuál es la diferencia entre `subprocess.run("cmd " + x, shell=True)` y `subprocess.run(["cmd", x])`?**
Con `shell=True` Python arma una sola string y la entrega a `/bin/sh -c`, que interpreta metacaracteres: el input puede inyectar comandos. Con la forma de lista, `cmd` se ejecuta directamente y `x` llega como un único argumento literal — el shell no interviene, así que `127.0.0.1;id` se trata como un nombre de host (inválido), no como dos comandos.

**3. Sos un pentester y solo ves la salida del `ping`, no la de tu comando inyectado. ¿Está a salvo la app?**
No necesariamente. Puede ser **blind command injection**: el comando se ejecuta pero su salida no vuelve en la respuesta. Se confirma con técnicas out-of-band (por ejemplo forzar una petición DNS/HTTP a un servidor tuyo con `$(...)`) o con inyección basada en tiempo (un `sleep` que retrase la respuesta). Ausencia de output no es ausencia de vulnerabilidad.

**4. Desde el lado defensivo, ¿qué buscarías en los logs para cazar esto, y qué técnica MITRE mapea?**
Buscaría metacaracteres de shell (`;`, `|`, `&`, `` ` ``, `$(`) y sus formas URL-encoded (`%3B`, `%7C`) dentro de parámetros que normalmente llevan datos simples, correlacionando con procesos hijos inesperados del proceso web (un servidor web no debería estar lanzando `id`, `whoami` o `curl`). Mapea a **T1059** (Command and Scripting Interpreter) — sub-técnica **T1059.004** para el shell Unix — y el vector de entrada a **T1190** (Exploit Public-Facing Application).
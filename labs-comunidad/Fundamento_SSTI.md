## 🧬 Server-Side Template Injection (SSTI) → RCE

> **La idea:** cuando el input del usuario se mezcla *dentro del codigo* de una plantilla en vez de pasarse como *dato*, el motor de plantillas lo ejecuta. En Jinja2 (Flask) eso significa evaluar expresiones de Python... y desde una expresion se llega a `os` = ejecucion de comandos en el servidor.

---

### ⚖️ Marco de la clase

Esto se practica **solo contra objetivos que te autorizaron por escrito** o contra tu propio laboratorio. Todo lo de abajo esta verificado contra el lab local de la comunidad, **`vulnlab.py`**, que escucha en `http://127.0.0.1:5000`. No apuntes ni un solo payload a un sistema que no sea tuyo o que no tengas permiso explicito de tocar.

---

### 1) Que es y por que importa

Un **motor de plantillas** (Jinja2, Twig, Freemarker, ERB...) sirve para armar HTML mezclando una plantilla fija con datos variables. La forma correcta es:

- La **plantilla** es codigo confiable escrito por el desarrollador.
- Los **datos** (nombre del usuario, etc.) entran como *variables de contexto*, y el motor los escapa.

El **SSTI** aparece cuando el desarrollador construye la plantilla *concatenando* el input del usuario. Entonces el input deja de ser un dato y pasa a ser parte del **codigo** que el motor evalua. El usuario ya no rellena un hueco: escribe programa.

**Por que importa (impacto):** no es un XSS que corre en el navegador de la victima. Esto corre en el **servidor**. Segun el motor, la escalada tipica es:

- Leer variables internas, configuracion, secretos de la app.
- Navegar el modelo de objetos de Python hasta `os` / `subprocess`.
- **RCE**: ejecutar comandos del sistema operativo → normalmente el paso previo a tomar el servidor entero.

Es de las vulnerabilidades web mas criticas justamente porque el salto de "evaluo `7*7`" a "ejecuto `id`" suele ser corto.

---

### 2) Montar el lab

Instala dependencias y levanta el laboratorio de la comunidad:

```bash
pip install flask requests lxml pyjwt && python3 vulnlab.py
```

Queda escuchando en `http://127.0.0.1:5000`.

**Endpoint de esta clase:** `/greet?name=`

Codigo vulnerable (asi se ve por dentro):

```python
# vulnlab.py — endpoint /greet  (VULNERABLE)
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # ⚠️ el input del usuario se CONCATENA dentro del codigo de la plantilla
    return render_template_string("<p>Hola, " + name + "!</p>")
```

La clave esta en `render_template_string(... + name + ...)`: `name` termina siendo parte del **source de la plantilla**, no una variable. Todo lo que escribas entre `{{ }}` lo evalua Jinja2.

---

### 3) El ataque, paso a paso

#### Paso A — Deteccion: ¿evalua expresiones?

La sonda universal de SSTI es una operacion matematica. Si el servidor te devuelve el *resultado* en vez del texto literal, hay evaluacion del lado servidor.

```bash
curl --get 'http://127.0.0.1:5000/greet' --data-urlencode 'name={{7*7}}'
```

**Output real:**

```html
<p>Hola, 49!</p>
```

Mandaste `{{7*7}}` y te contestaron `49`. El servidor **no** devolvio el texto `{{7*7}}`: lo *calculo*. Eso es SSTI confirmado.

> Tip de metodo: `{{7*7}}` da `49` en Jinja2/Twig; `${7*7}` o `#{7*7}` prueban otros motores. Con el `49` ya sabes que estas ante Jinja2 y que puedes escribir expresiones Python.

**Por que funciona:** el `name={{7*7}}` se concatena dentro de `"<p>Hola, " + name + "!</p>"`, quedando el source `"<p>Hola, {{7*7}}!</p>"`. Jinja2 ve `{{ ... }}`, evalua la expresion y la reemplaza por su resultado. Concepto reusable: **si tu dato reaparece transformado, esta siendo interpretado, no mostrado.**

#### Paso B — Escalar a RCE

Desde una expresion Python se navega el modelo de objetos hasta llegar a `os`. Un *gadget* clasico parte de un builtin de Jinja (`cycler`) y sube por sus atributos internos hasta `__globals__`, donde vive `os`:

```bash
curl --get 'http://127.0.0.1:5000/greet' \
  --data-urlencode "name={{cycler.__init__.__globals__.os.popen('id').read()}}"
```

**Output real:**

```
uid=1000(Meowju) ...
```

Ejecutaste `id` **en el servidor**. Ya no es matematica: es una shell a traves de una URL.

**Por que funciona (el concepto reusable):**

- `cycler` es un objeto que Jinja2 expone por defecto en el contexto.
- `.__init__` es su metodo constructor (una funcion Python).
- `.__globals__` es el diccionario de globales del *modulo* donde esa funcion vive → ahi esta importado `os`.
- `.os.popen('id').read()` ejecuta el comando y lee su salida.

Es la tecnica de **attribute navigation**: en Python casi todo objeto te deja subir a `__class__`, `__init__`, `__globals__`, `__builtins__`... y desde esas globales alcanzar `os`/`subprocess`. Por eso "puedo evaluar una expresion" degenera tan rapido en "ejecuto comandos".

**El fragmento que lo causa** es el mismo de la seccion 2 (Montar el lab): concatenar `name` dentro de `render_template_string`. No hay ningun filtro entre tu input y el evaluador de Jinja2.

---

### 4) Blue Team

#### Firma de deteccion

Los delimitadores de plantilla en parametros HTTP son la senal barata y de alto valor: **`{{`**, **`}}`**, **`{%`** (y variantes URL-encodeadas `%7B%7B`, `%7D%7D`, `%7B%25`) apareciendo en query strings, campos de formulario o cabeceras. Ojo: si el cliente encodea la URL (como hace `curl --data-urlencode`), en el log veras la forma `%7B%7B` y no `{{`, por eso la regla incluye ambas. En un servicio normal, un usuario no manda `{{` en su nombre. Sumale palabras de gadget: `__globals__`, `__class__`, `__init__`, `popen`, `subprocess`, `cycler`.

#### Regla Sigma

```yaml
title: Posible Server-Side Template Injection (Jinja2) en parametros HTTP
id: 7a3f9c2e-1b4d-4e6a-9f8c-2d5e7a1b3c4f
status: experimental
description: Detecta delimitadores de plantilla y gadgets de Jinja2 en la URI/query, indicativos de sondas o explotacion de SSTI.
logsource:
  category: webserver
detection:
  delimitadores:
    c-uri|contains:
      - '{{'
      - '}}'
      - '{%'
      - '%7B%7B'
      - '%7D%7D'
      - '%7B%25'
  gadgets:
    c-uri|contains:
      - '__globals__'
      - '__class__'
      - '__init__'
      - 'cycler'
      - 'popen'
      - 'subprocess'
  condition: delimitadores or gadgets
falsepositives:
  - Documentacion o playgrounds que muestran sintaxis de plantillas
  - Frameworks que usan {{ }} legitimamente en el frontend (revisar contexto)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - attack.execution
  - attack.t1059
```

#### Mapeo MITRE ATT&CK

| Fase | Tecnica | ID | En este ataque |
|------|---------|----|----------------|
| Initial Access | Exploit Public-Facing Application | **T1190** | Se explota el endpoint web `/greet` expuesto |
| Execution | Command and Scripting Interpreter | **T1059** | El gadget `os.popen('id')` ejecuta comandos del SO (sub-tecnica aplicable: T1059.006 — Python) |

#### Mitigacion (el fix correcto)

| Mal (vulnerable) | Bien (fix) |
|------------------|-----------|
| `render_template_string("<p>Hola, " + name + "!</p>")` | Nunca construir la plantilla con input del usuario. |
| Input dentro del **codigo** de la plantilla | Input como **variable de contexto**, no como source. |

Fix en codigo — el input viaja como dato, no como plantilla:

```python
from flask import render_template_string

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # La plantilla es FIJA; el input entra como VARIABLE de contexto.
    # Al no ser parte del source, el motor NUNCA lo evalua -> se corta el RCE.
    # Ademas, con autoescape activo (default en Flask >= 2.2 para strings),
    # Jinja2 escapa el valor y previene el XSS reflejado.
    return render_template_string("<p>Hola, {{ name }}!</p>", name=name)
```

Principios del fix:

1. **Plantilla constante, datos por contexto.** El source de la plantilla nunca debe contener input del usuario. Pasa los valores como argumentos (`name=name`) y deja que el motor los escape. Esto es lo que corta el SSTI/RCE: el valor se trata como dato, no como codigo. (El autoescape es una capa aparte: previene el XSS, no el SSTI.)
2. **Preferí `render_template`** (archivos `.html`) sobre `render_template_string`; y mantené **autoescape activado** (default en Flask >= 2.2; en versiones anteriores `render_template_string` no autoescapaba, conviene verificarlo).
3. **Si de verdad necesitas templating dinamico** definido por el usuario, usa el **sandbox de Jinja2** (`jinja2.sandbox.SandboxedEnvironment`), que bloquea el acceso a atributos peligrosos — pero es una defensa en profundidad, no el reemplazo de no concatenar input.

---

### 5) Q&A de entrevista

**1. ¿Cual es la diferencia de fondo entre XSS y SSTI?**
XSS ejecuta en el *cliente* (el navegador de la victima interpreta HTML/JS inyectado). SSTI ejecuta en el *servidor* (el motor de plantillas evalua el input). Por eso SSTI escala a RCE y compromete la infraestructura, mientras XSS compromete sesiones de usuario. Ambos nacen de mezclar datos y codigo, pero el interprete y el blast radius son distintos.

**2. Detectaste `{{7*7}} → 49`. ¿Como decides que motor es y cual es tu siguiente paso?**
`{{7*7}}=49` apunta a Jinja2 o Twig (usan `{{ }}`). Para desambiguar mando pruebas especificas de cada motor (p. ej. `{{7*'7'}}` da `7777777` en Jinja2 —multiplicacion de string en Python— mientras Twig castea el string a numero y devuelve `49`). Confirmado Jinja2, el siguiente paso es enumerar gadgets para llegar a las globales del modulo (`__globals__`) donde suele estar `os`, y de ahi `popen`/`subprocess` para RCE.

**3. ¿Por que `cycler.__init__.__globals__.os` llega a ejecucion de comandos?**
Porque en Python los objetos exponen su cadena de atributos internos: desde un objeto del contexto (`cycler`) subo a su constructor (`__init__`, una funcion), y toda funcion tiene `__globals__`, el diccionario de globales del modulo donde fue definida. Si ese modulo importo `os`, ya tengo `os.popen(...)`. Es *attribute navigation*: no explotas un bug de memoria, abusas de la introspeccion legitima del lenguaje.

**4. Un dev te dice "le agrego un filtro que bloquea `os` y `popen` y listo". ¿Que le respondes?**
Que las blocklists de SSTI se evaden trivialmente: `os` se alcanza por muchos caminos (`__builtins__`, `subprocess`, `request.application`), se puede concatenar strings (`'o'+'s'`), usar `attr()`, o codificaciones. El fix real no es filtrar payloads sino **no meter input del usuario en el codigo de la plantilla**: datos por contexto con autoescape, y sandbox de Jinja2 si el templating dinamico es un requisito ineludible. Filtrar es parchear el sintoma; el diseño es la cura.
# 🕷️ Cross-Site Scripting (XSS) Reflejado

> **Cuando la web te devuelve tu propio código y el navegador lo ejecuta.** Aprendé cómo un simple parámetro de búsqueda puede convertirse en JavaScript corriendo en el navegador de una víctima.

---

> ⚠️ **Marco de trabajo:** Todo lo que sigue se practica **únicamente en el lab local `vulnlab.py`** de la comunidad, en tu propia máquina. Solo se atacan **objetivos autorizados**. Usar estas técnicas contra sistemas de terceros sin permiso escrito es un delito. Este módulo es para aprender a **encontrar y arreglar** el fallo, no para hacer daño.

---

## 1. Qué es y por qué importa

**Cross-Site Scripting (XSS)** es una vulnerabilidad en la que una aplicación web toma datos que vienen del usuario y los mete dentro del HTML de la página **sin limpiarlos**. El resultado: el atacante logra que el navegador de la víctima ejecute **JavaScript que no escribió el desarrollador**.

La clave para entenderlo: el navegador no distingue "texto que quería mostrar el sitio" de "texto que inyectó un atacante". Si el `<script>` llega dentro del HTML, el navegador lo ejecuta. Punto.

Hay tres sabores de XSS:

| Tipo | Dónde vive el payload | Ejemplo |
|------|----------------------|---------|
| **Reflejado** (esta clase) | En la **respuesta inmediata** a una petición (típicamente un parámetro de la URL) | Un link malicioso que la víctima clickea |
| **Almacenado** | **Guardado** en el servidor y servido a todos los que visitan | Un comentario con `<script>` en un foro |
| **DOM** | En el **JavaScript del cliente** que manipula el DOM inseguramente | `document.write(location.hash)` |

**Por qué importa (impacto real):**

- **Robo de sesión:** leer `document.cookie` y mandar el token de sesión al atacante → suplantación de la víctima.
- **Keylogging y phishing:** inyectar un formulario falso de login sobre la página real.
- **Acciones en nombre de la víctima:** ejecutar peticiones autenticadas (cambiar el email de la cuenta, transferir, etc.).
- **Pivote:** en paneles de administración, un XSS reflejado enviado al admin puede escalar a control total de la aplicación.

El XSS reflejado es especialmente traicionero porque **no deja nada en el servidor**: el payload viaja en la URL. Basta con que la víctima haga click en un enlace preparado.

---

## 2. Montar el lab

Instalá las dependencias y levantá el laboratorio de la comunidad:

```bash
pip install flask requests lxml pyjwt && python3 vulnlab.py
```

El servidor queda escuchando en:

```
http://127.0.0.1:5000
```

El **endpoint vulnerable de esta clase** es el buscador:

```
/search?q=<lo que escribas>
```

Es una función de búsqueda que devuelve un mensaje del estilo *"Resultados para: ..."* repitiendo lo que pusiste en `q`. Ese "repetir lo que pusiste" es exactamente el problema.

---

## 3. El ataque, paso a paso

### Paso 1 — Confirmar que el parámetro se refleja

Primero probamos con texto normal para ver que `q` aparece en la respuesta. Después mandamos un payload de prueba clásico: `<script>alert(1)</script>`.

```bash
curl "http://127.0.0.1:5000/search?q=<script>alert(1)</script>"
```

**Output real:**

```html
<p>Resultados para: <script>alert(1)</script></p>
```

### Paso 2 — Leer lo que pasó

Fijate bien en el output. Los caracteres `<`, `>` de nuestro `<script>` **llegaron crudos** a la respuesta. No se convirtieron en `<script>` (que sería texto inofensivo mostrado en pantalla). Llegaron como **etiqueta HTML real**.

Cuando un navegador reciba ese HTML (Flask sirve la respuesta como `text/html` por defecto), va a interpretar `<script>alert(1)</script>` como una etiqueta de script legítima y **va a ejecutar `alert(1)`**. Con `curl` no vemos el popup porque `curl` no es un navegador y no ejecuta JavaScript — pero la prueba está en que el payload volvió **sin escapar**. Esa reflexión cruda es la confirmación del XSS reflejado.

### Por qué funciona

**El concepto reusable:** una aplicación es vulnerable a XSS cuando **inserta input del usuario dentro de una página sin codificarlo según el contexto** donde cae (HTML, atributo, JavaScript, URL). El navegador confía en todo lo que le llega como parte del documento.

**El código vulnerable que lo causa:**

```python
# ❌ VULNERABLE
@app.route("/search")
def search():
    q = request.args.get("q", "")
    return "<p>Resultados para: " + q + "</p>"   # q entra al HTML sin escapar
```

El problema está en esa concatenación: `q` es una cadena controlada por el atacante y se pega directamente al HTML. No hay ninguna función que transforme los caracteres peligrosos (`<`, `>`, `"`, `'`, `&`) en sus equivalentes seguros (entidades HTML). El servidor está tratando datos como si fueran código de la plantilla.

---

## 4. Blue Team

### Firma de detección

En logs de acceso o en un WAF, buscá parámetros que contengan estructuras que solo tienen sentido como HTML/JS activo:

- `<script` — inyección de etiqueta de script.
- `onerror=`, `onload=` — manejadores de evento (payloads que no usan `<script>`, ej. `<img src=x onerror=...>`).
- `javascript:` — pseudo-protocolo en atributos `href`/`src`.

Ojo con los falsos positivos y con el **URL-encoding**: los atacantes mandan `%3Cscript%3E` para evadir filtros ingenuos. Normalizá (decodificá) el parámetro **antes** de aplicar la firma.

### Regla Sigma

```yaml
title: Posible XSS Reflejado en Parametro de URL
id: 6f2b1c84-9d3e-4a7f-b1c2-8e5a0f4d7c39
status: experimental
description: Detecta patrones tipicos de inyeccion XSS en parametros de peticiones HTTP GET.
author: Comunidad Sec
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - '<script'
      - 'onerror='
      - 'onload='
      - 'javascript:'
      - '%3Cscript'
  condition: selection
falsepositives:
  - Herramientas de escaneo de seguridad autorizadas (DAST)
  - Documentacion o foros tecnicos que citan payloads como texto
level: high
tags:
  - attack.execution
  - attack.t1059.007
```

### Mapeo MITRE ATT&CK

| Técnica | ID | Relación con XSS |
|---------|-----|-----------------|
| Command and Scripting Interpreter: **JavaScript** | **T1059.007** | El payload es JavaScript ejecutado por el navegador de la víctima. |

### Mitigación (el fix correcto en código)

| Medida | Qué hace | Ejemplo |
|--------|----------|---------|
| **Output-encoding por contexto** | Codificar la salida según dónde caiga (HTML, atributo, JS, URL). Es el fix principal. | Ver código abajo |
| **Content-Security-Policy (CSP)** | Cabecera que bloquea scripts inline / de orígenes no permitidos. Segunda capa de defensa. | `Content-Security-Policy: default-src 'self'` |
| **Cookies HttpOnly** | El JS del navegador no puede leer la cookie de sesión → mitiga el robo de token vía XSS. | `Set-Cookie: session=...; HttpOnly; Secure` |
| **Frameworks que auto-escapan** | Plantillas que escapan por defecto (Jinja2 con autoescape, React, etc.). Evita el error humano. | `render_template` en vez de concatenar |

**El código arreglado:**

```python
# ✅ SEGURO — output-encoding en contexto HTML
from flask import request
from markupsafe import escape

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return "<p>Resultados para: " + str(escape(q)) + "</p>"
    # escape() convierte < > " ' & en entidades: <script> -> <script>

# ✅ MEJOR AUN — dejar que el framework auto-escape
from flask import request, render_template_string

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string("<p>Resultados para: {{ q }}</p>", q=q)
    # Jinja2 escapa {{ q }} automaticamente. Ojo: q es una VARIABLE, no la
    # plantilla. Nunca pases input del usuario como el string de plantilla
    # (eso seria SSTI, otro bug distinto).
```

La regla de oro: **nunca concatenes input del usuario dentro del HTML a mano.** Codificalo según el contexto o dejá que el framework lo haga por vos.

---

## 5. Q&A de entrevista

**1. ¿Cuál es la diferencia entre XSS reflejado, almacenado y basado en DOM?**
El **reflejado** viaja en la petición y vuelve en la respuesta inmediata (requiere que la víctima haga click en un link preparado, no persiste). El **almacenado** se guarda en el servidor y se sirve a cualquiera que visite la página (más peligroso, dispara solo). El **DOM** ocurre enteramente en el navegador: JavaScript del cliente toma una fuente controlable (ej. `location.hash`) y la escribe insegura en el DOM, sin que el payload toque el servidor.

**2. Confirmaste un XSS reflejado con `curl` pero no viste ningún popup. ¿Por qué eso igual prueba la vulnerabilidad?**
Porque `curl` no ejecuta JavaScript, solo muestra el HTML crudo. La prueba no es el popup, es que el payload `<script>alert(1)</script>` **volvió sin escapar** dentro de la respuesta (`<p>Resultados para: <script>...`). Un navegador que reciba ese mismo HTML (servido como `text/html`) interpretará la etiqueta y ejecutará el script. El escape (o su ausencia) es lo que determina la vulnerabilidad, no el motor de JS del cliente.

**3. Si ponés una `Content-Security-Policy`, ¿ya no hace falta escapar la salida?**
No. CSP es una **defensa en profundidad**, no un reemplazo. Puede haber bypasses de CSP (dominios permitidos con gadgets, `unsafe-inline` mal configurado, JSONP), y no todo XSS necesita un `<script>` inline. El fix correcto y primario sigue siendo el **output-encoding por contexto**; CSP y las cookies HttpOnly reducen el impacto si algo se escapa.

**4. ¿Por qué se dice que el escape debe ser "según el contexto"?**
Porque el mismo dato es peligroso de formas distintas según dónde caiga. Escapar para **HTML** (`<` → `<`) no te protege si el dato entra dentro de un atributo entre comillas (donde alcanza con `"` para romper), o dentro de un bloque `<script>` (donde necesitás escape de JavaScript), o en una URL (donde importa `javascript:`). Aplicar el encoder equivocado deja huecos; por eso los frameworks modernos escapan sabiendo el contexto de cada punto de inserción.
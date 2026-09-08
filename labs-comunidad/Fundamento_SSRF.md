# 🎯 Server-Side Request Forgery (SSRF)

> **La idea:** hacés que el *servidor* haga una petición HTTP por vos — y así alcanzás cosas que vos, desde afuera, no podés ver.

---

> ⚠️ **Marco ético.** Todo lo que sigue se practica **solo sobre objetivos autorizados**. Los comandos de esta clase corren contra el lab local de la comunidad (`vulnlab.py`), que escucha en `http://127.0.0.1:5000`. No apuntes esto a infraestructura que no sea tuya o para la que no tengas permiso explícito por escrito.

---

## 1. Qué es y por qué importa

**SSRF (Server-Side Request Forgery)** ocurre cuando una aplicación toma una **URL que vos controlás** y el servidor la va a buscar por su cuenta. El atacante no hace la petición: **la hace el servidor, con la identidad y la posición de red del servidor.**

¿Por qué es tan grave? Porque el servidor casi siempre está en un lugar privilegiado de la red:

- **Alcanza servicios internos** que no están expuestos a Internet: bases de datos de administración, paneles internos, endpoints `/admin`, microservicios que confían entre sí.
- **En la nube (AWS/GCP/Azure)** puede llegar al **endpoint de metadatos** `http://169.254.169.254/` (IMDS), que devuelve **credenciales IAM temporales** de la instancia. Con esas credenciales el atacante actúa como el servidor dentro de la cuenta cloud. (Este es exactamente el pivote del caso **Nimbus** del ARSENAL.)
- Sirve para **escaneo de puertos interno**, saltar firewalls perimetrales y, encadenado, escalar a RCE.

La clave conceptual: **el perímetro no te protege si el atacante puede pedirle al servidor que golpee hacia adentro.**

---

## 2. Montar el lab

El lab de la comunidad es un único archivo Flask. Instalá dependencias y levantalo:

```bash
pip install flask requests lxml pyjwt && python3 vulnlab.py
```

Queda escuchando en `http://127.0.0.1:5000`.

**Endpoint de esta clase:** `/fetch?url=` — recibe una URL y el servidor la va a buscar y te devuelve el contenido.

Para simular "servicios internos", el mismo lab expone `/user?id=` (imaginá que es un microservicio interno que **no debería** ser accesible desde afuera).

---

## 3. El ataque, paso a paso

Le pedimos al endpoint público `/fetch` que, en lugar de traer una web externa, vaya a buscar un **endpoint interno** del propio servidor:

```bash
curl "http://127.0.0.1:5000/fetch?url=http://127.0.0.1:5000/user?id=99"
```

**Output real:**

```
(99, 'admin')
```

El servidor hizo la petición a `http://127.0.0.1:5000/user?id=99` **en su propio nombre** y nos devolvió la fila del usuario interno `99` → `admin`. Alcanzamos un endpoint interno usando al servidor como proxy.

> 📝 **Detalle de encoding.** Acá la URL interna va sin URL-encode y funciona porque **no contiene `&`**: Flask parsea `url=http://127.0.0.1:5000/user?id=99` como un único par y el `?id=99` queda dentro del valor. En cuanto el objetivo interno lleve más de un parámetro (p. ej. `?id=99&debug=1`), ese `&` **cortaría** el valor de `url=` y el ataque fallaría. En la práctica, encodeá el `?` interno como `%3F` y el `&` como `%26` para que la URL viaje entera dentro del parámetro.

### Por qué funciona

El código del endpoint es, en esencia:

```python
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    r = requests.get(url)      # <-- URL controlada por el usuario, sin validación
    return r.text
```

El problema es que `requests.get(url)` usa **directamente la URL del atacante**, sin **allow-list** de destinos ni de esquemas. El servidor confía en cualquier URL que le pasen.

**El concepto reusable:** cualquier función que "traiga una URL" (descargar avatar, previsualizar link, webhook, importar desde URL, generar PDF de una página, health-check) es un candidato a SSRF si la URL viene del usuario y no hay lista blanca. Lo que en el lab es `127.0.0.1:5000/user`, en producción cloud es:

```bash
# Mismo patrón, objetivo real en AWS: robar credenciales IAM
curl "http://VICTIMA/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

Mismo bug, impacto de toma de cuenta cloud.

---

## 4. Blue Team

### Firma de detección

Buscá parámetros que contengan `http://` o `https://` apuntando a **IPs internas o link-local**:

- Loopback: `127.0.0.1`, `localhost`, `::1`
- Metadata cloud (link-local): `169.254.169.254`
- Rangos privados: `10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`

Una petición desde el *front* público hacia esos destinos, originada por el servidor de aplicación, es la huella típica de SSRF.

### Regla Sigma

```yaml
title: Posible SSRF hacia IPs internas o metadata cloud
id: 5b1e0c74-3d2a-4f19-9c8e-7a6b4d2f1e03
status: experimental
description: Detecta parametros de URL apuntando a loopback, rangos privados o el endpoint de metadatos (IMDS)
logsource:
  category: webserver
detection:
  selection_param:
    cs-uri-query|contains:
      - 'url=http://127.0.0.1'
      - 'url=http://localhost'
      - 'url=http://169.254.169.254'
      - 'url=http://10.'
      - 'url=http://192.168.'
      - 'url=http://172.16.'
  condition: selection_param
falsepositives:
  - Health-checks internos legitimos que pasen por el mismo endpoint
level: high
tags:
  - attack.initial-access
  - attack.t1190
  - attack.credential-access
  - attack.t1552.005
```

> ⚠️ **Límites de esta regla (leélos antes de desplegarla).**
> - El patrón `url=http://172.16.` solo cubre `172.16.0.0/16`, **no** todo el rango privado `172.16.0.0/12` (`172.16.x` a `172.31.x`). Para cobertura real agregá `172.17.` … `172.31.`, o mejor, normalizá/resolvé la IP antes de evaluar.
> - En logs reales `cs-uri-query` suele venir **URL-encodeado** (`http%3A%2F%2F127.0.0.1`), así que sumá variantes encodeadas o decodificá el campo antes de aplicar la regla; si no, un simple `%3A%2F%2F` evade estos `contains`.
> - Faltan formas alternativas del mismo destino (`0.0.0.0`, `::1`, `2130706433`, `0x7f000001`) — ver Q&A 3. La detección por patrones es orientativa; la defensa dura va en el código (sección siguiente).

### Mapeo MITRE ATT&CK

| Técnica | ID | Relación con SSRF |
|---|---|---|
| Exploit Public-Facing Application | **T1190** | El atacante abusa de una app pública (`/fetch`) para alcanzar recursos internos. *(Táctica: Initial Access.)* |
| Unsecured Credentials: Cloud Instance Metadata API | **T1552.005** | El SSRF hacia `169.254.169.254` (IMDS) roba las **credenciales IAM temporales** de la instancia. *(Táctica: Credential Access.)* |

### Mitigación (el fix en código)

| Problema | Fix correcto |
|---|---|
| URL del usuario usada sin validar | **Allow-list de destinos**: solo permitir hosts explícitamente aprobados. |
| Cualquier esquema aceptado | Restringir a **`http`/`https`** (bloquear `file://`, `gopher://`, `dict://`, etc.). |
| Se puede apuntar a IPs internas | **Resolver el DNS y bloquear** IPs internas/link-local (`127.0.0.0/8`, `169.254.0.0/16`, `10/8`, `192.168/16`, `172.16/12`) *antes* de conectar. |
| Metadata cloud expuesta | Forzar **IMDSv2** (requiere token, mitiga SSRF ciego contra `169.254.169.254`). |

Ejemplo del fix:

```python
from urllib.parse import urlparse
import ipaddress, socket

ALLOWED_HOSTS = {"api.midominio.com", "cdn.midominio.com"}

def fetch_seguro(url):
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise ValueError("Esquema no permitido")
    if p.hostname not in ALLOWED_HOSTS:          # allow-list (default-deny)
        raise ValueError("Host no permitido")
    ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("Destino interno bloqueado")   # mata IMDS y loopback
    return requests.get(url, timeout=5)
```

> 🔒 **Caveat de este ejemplo (TOCTOU / DNS rebinding).** El código resuelve el DNS y valida la IP, pero después `requests.get(url)` **vuelve a resolver el DNS** al conectar. Entre las dos resoluciones el atacante puede cambiar el registro (DNS rebinding, ver Q&A 3): validás una IP segura y conectás a otra interna. La allow-list de hosts *propios* reduce mucho el riesgo, pero la versión robusta **conecta a la IP ya validada** (pinneándola con un adaptador de `requests`, o pasando la IP como host y el nombre en la cabecera `Host`), en vez de reusar la URL. Además, `socket.gethostbyname` devuelve **una sola IPv4**: para cobertura completa validá todas las A/AAAA con `socket.getaddrinfo`.

---

## 5. Q&A de entrevista

**1) ¿Cuál es la diferencia entre SSRF y un Open Redirect?**
En un *open redirect* el navegador de la víctima es el que termina en otra URL (afecta al cliente). En **SSRF es el servidor** quien hace la petición, con su propia posición de red y sus credenciales, por eso alcanza servicios internos que el cliente jamás vería.

**2) ¿Por qué el endpoint de metadatos `169.254.169.254` es el objetivo clásico de SSRF en cloud?**
Porque devuelve **credenciales IAM temporales** de la instancia sin autenticación adicional: cualquier proceso que corra en la máquina (o cualquiera que logre que la máquina haga la petición vía SSRF) obtiene tokens válidos para actuar dentro de la cuenta cloud. Es el pivote de acceso inicial a RCE/robo de datos (caso Nimbus). En ATT&CK esto es exactamente **T1552.005 — Unsecured Credentials: Cloud Instance Metadata API**.

**3) Bloqueé `127.0.0.1` en una lista negra. ¿Por qué sigue siendo insuficiente?**
Las **blacklists se evaden**: `localhost`, `0.0.0.0`, `2130706433` (decimal), `0x7f000001` (hex), IPv6 `[::1]`, redirects 302 hacia una IP interna, o DNS rebinding que resuelve distinto en la segunda consulta. La defensa robusta es **allow-list de hosts** + resolver la IP y validar que **no** sea interna antes de conectar (conectando a esa misma IP validada para cerrar la ventana de rebinding).

**4) ¿Por qué una allow-list de destinos es mejor que filtrar por patrones "peligrosos"?**
Porque una allow-list es *default-deny*: solo pasa lo que aprobaste explícitamente, así que cualquier truco de codificación o host nuevo cae automáticamente. Filtrar patrones es *default-allow*: siempre te vas a olvidar de una representación (decimal, hex, IPv6, redirect) y el atacante solo necesita una.
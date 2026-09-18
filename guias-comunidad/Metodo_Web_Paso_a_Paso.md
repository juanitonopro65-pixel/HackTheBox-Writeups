# 🧭 Cómo se ataca un reto web con código fuente — el paso a paso

> Guía para quien empieza. No es una lista de trucos: es el **orden** en que hay
> que hacer las cosas, que es lo que de verdad separa resolver un reto en una
> hora de estar tres días dando vueltas.
>
> Todos los ejemplos son reales, de retos resueltos: **Bobby's Bistro**
> (Medium, web), **Why Lambda** (Hard, web) y **QLotto** (Easy). Los errores
> también son reales, y son míos.

---

## Antes de nada: ¿de quién es la caja?

HTB, un CTF, tu propio laboratorio, o un programa con alcance escrito: adelante.
Cualquier otra cosa, no. No por miedo al castigo — porque eso es exactamente lo
que separa a un investigador de seguridad de un delincuente, y no es la técnica.

Si alguien te pregunta "¿cómo ataco esto?" sin decirte qué es "esto", la primera
respuesta es **"¿dónde está la caja?"**. No es vigilancia: es que nadie puede dar
una buena respuesta sobre un objetivo que no conoce.

---

## La idea que ordena todo lo demás

La mayoría de la gente que empieza ataca así:

> leo un poco → se me ocurre algo → lo disparo al objetivo → no pasa nada →
> se me ocurre otra cosa → lo disparo → no pasa nada → …

El problema no es que las ideas sean malas. Es que **cada disparo al objetivo no
te dice nada**. Recibís un 500, o un 401, o silencio, y no sabés en qué eslabón
se rompió la cadena. Tres intentos, cero información.

En *Why Lambda* disparé **tres veces a ciegas** contra el objetivo. Cuando por fin
reconstruí el reto en mi máquina, los registros del contenedor me dieron la
respuesta **al primer intento**.

> **Cuando no podés ver lo que pasa, el trabajo no es adivinar mejor.**
> **Es construir el sitio donde se pueda ver.**

Todo el método de abajo sale de ahí.

---

## Paso 0 — Inventario (cinco minutos, y no te los saltes)

Antes de leer una sola línea de lógica, mirá **qué tamaño tiene el problema**.

```bash
unzip -P hackthebox reto.zip -d ~/ctf/reto
cd ~/ctf/reto

# el arbol, sin la basura
find . -type f -not -path '*/node_modules/*' -not -path '*/.git/*' | sort

# los ficheros de codigo mas gordos, que es por donde se empieza
find . -type f -not -path '*/node_modules/*' -printf '%s\t%p\n' | sort -rn | head -12
```

Qué buscás en esta pantalla:

| Fichero | Qué te dice |
|---|---|
| `requirements.txt` / `package.json` | El lenguaje, el framework y **las versiones**. Una versión clavada a mano suele ser la pista del reto. |
| `Dockerfile` | Dónde está la bandera, qué usuario corre, qué puertos. `RUN mv flag.txt /flag.txt` te ahorra buscarla. |
| `supervisord.conf` / `docker-compose.yml` | **Cuántos procesos hay.** Si hay dos, uno suele ser un bot. |
| `bot.py` / `bot.js` | Lo más importante del reto, y casi nadie lo lee primero. Ver abajo. |
| Extensión de las plantillas | `.pt` → Chameleon. `.j2`/`.html` con `{{ }}` → Jinja2. `.ejs`, `.pug`, `.hbs`… Cada una tiene su propia forma de SSTI. |

**El Dockerfile de un reto es un mapa.** En *Why Lambda*, `google-chrome-stable`
instalado en la imagen significaba que había un bot con navegador, y eso decidió
la cadena entera.

---

## Paso 1 — Si hay bot, leelo AHORA

Esto es lo que más tiempo ahorra de toda la guía, y va antes que la lógica de la
aplicación.

La pregunta no es *"¿hay un bot?"*. Es **"¿qué motor usa ese bot?"**:

| El bot usa… | Entonces… |
|---|---|
| Selenium, Playwright, Puppeteer, `google-chrome` | Es un navegador de verdad. **El XSS es el camino**: ejecuta JS, tiene cookies, podés robarle la sesión. |
| `requests`, `axios`, `curl`, `fetch` a pelo | **No ejecuta JavaScript.** El XSS no existe en este reto. Buscá otra cosa. |

En **Bobby's Bistro** el enunciado dice que hay un bot vigilando, y dentro de la
app hay un anuncio que dice *"añadí una red de seguridad 😈, intentá algo raro y
te quedás fuera"*. Todo empuja al XSS. Y la primera línea del bot es:

```python
import requests
```

No hay navegador. No hay DOM. No hay dónde ejecutar una carga. La "red de
seguridad" ni siquiera existe en el código: es decorado para que pierdas la
tarde.

> Si no podés **robarle** la sesión al admin, la vas a tener que **fabricar**.
> Esa frase, sacada en el minuto cinco, fue el reto entero.

---

## Paso 2 — Montá el laboratorio antes de tocar el objetivo

Con el `Dockerfile` delante, esto son dos minutos:

```bash
docker build -t reto . && docker run -d --name r0 -p 13001:3000 reto
```

**Ponelo en un script y que el script no se coma los errores.** Este fallo me
costó un rato hoy mismo:

```bash
docker build -t reto . | tail -5        # ← MAL: el codigo de salida es el de tail
```

Con una tubería, `$?` es el de `tail`, que siempre da 0. El script sigue adelante
tan contento con la imagen sin construir. Lo correcto:

```bash
set -eo pipefail
if ! docker build -t reto . > /tmp/build.log 2>&1; then
  echo "FALLO:"; tail -25 /tmp/build.log; exit 1
fi
```

### Los dos controles, desde el primer minuto

Antes de atacar nada, comprobá que tu laboratorio **distingue el éxito del
fracaso**. Dos peticiones:

```bash
# CONTROL SANO: desde fuera, la app me tiene que rechazar
curl -s http://127.0.0.1:13001/flag

# CONTROL POSITIVO: desde dentro, me tiene que dar la bandera
docker exec r0 curl -s http://127.0.0.1:3000/flag
```

Si el de dentro no funciona, tu laboratorio está roto y todo lo que midas después
es basura. Si el de fuera funciona sin atacar nada, no estás midiendo el ataque.

> **Un control sano detecta falsos positivos. Un control que falla a propósito
> detecta un detector ciego.** Hacen falta los dos, y hay que ir intercalándolos,
> no ponerlos todos al principio.

### Lo que te da el laboratorio y el objetivo no

- **Los registros.** `docker logs r0`, `/var/log/app_error.log`. La traza completa
  de una excepción, que el objetivo te esconde tras un 500 genérico.
- **Poder mirar dentro.** `docker exec r0 ls /app/static`, `cat` de cualquier
  fichero. Sabés si tu escritura llegó, en vez de suponerlo.
- **Poder romperlo.** Reiniciás y volvés a empezar limpio. Contra el objetivo, no.
- **Velocidad.** Sin latencia, sin límites, sin gastar intentos.

### Trampa: el laboratorio se ensucia

Un experimento deja rastro y el siguiente falla **por eso**, no por tu exploit.
Hoy me pasó: había reemplazado el llavero de claves en una prueba, y la siguiente
fallaba porque los tokens legítimos ya no valían. El exploit estaba bien.

**Ante cualquier resultado raro, reiniciá el contenedor antes de investigar:**

```bash
docker rm -f r0 && docker run -d --name r0 -p 13001:3000 reto && sleep 8
```

---

## Paso 3 — El mapa de superficie

Ahora sí, el código. Pero no lo leas de arriba abajo: **hacé una tabla**. Una
fila por ruta, y estas cuatro columnas:

| Ruta | ¿Pide sesión? | ¿Pide ser admin? | Qué entra del usuario |
|---|---|---|---|
| `/register`, `/login` | no | no | usuario, contraseña |
| `/profile` POST | sí | no | `token` → **va a una consulta SQL** |
| `/api/chat-messages` POST | sí | no | mensaje + **fichero adjunto** |
| `/api/announcements` POST | sí | **sí** | título + texto → **va a una plantilla** |
| `/flag` o `/admin/...` | sí | sí | — |

Con esa tabla ves dos cosas de golpe:

1. **Dónde está la meta** y qué privilegio pide.
2. **Qué entradas hay antes de esa puerta**, que son tus materiales.

La pregunta que guía todo lo demás: *¿qué me falta para llegar a la meta, y qué
entrada me lo puede dar?*

---

## Paso 4 — Leer buscando sumideros, no leyendo todo

Un **sumidero** es el sitio donde un dato del usuario llega a algo peligroso. No
leas buscando "vulnerabilidades": leé buscando **estos patrones concretos**.

### SQL

```python
filter(text("token='{}'".format(token)))     # ← formato dentro de text()
cursor.execute(f"SELECT ... WHERE x='{v}'")  # ← f-string en SQL
```
Lo correcto sería un parámetro ligado. Si ves `format`, `%`, `+` o una f-string
construyendo SQL, hay inyección.

**Dónde mirar además:** ¿el resultado se muestra en pantalla? Si la plantilla
pinta las filas, la inyección **tiene ventana** y podés leer datos directamente en
vez de sacarlos a ciegas bit a bit.

### Subida de ficheros

```python
file.save(CARPETA + "/" + file.filename)     # ← el nombre lo pone el cliente
```
**Werkzeug y Flask NO limpian el nombre solos.** `secure_filename()` es una
función que hay que llamar. Si no está, `../` sale de la carpeta y tenés
**escritura de ficheros donde quieras**.

### Plantillas (SSTI)

```python
PageTemplate(contenido_del_usuario).render()   # Chameleon
Template(contenido_del_usuario).render()       # Jinja2
render_template_string(contenido_del_usuario)  # Flask
```
Contenido de usuario **compilado** como plantilla, no pintado como texto. Eso es
ejecución de código.

### Deserialización y formatos que ejecutan

`pickle.loads`, `yaml.load` sin `SafeLoader`, `marshal`, y —el de *Why Lambda*—
`keras.models.load_model()`, donde una capa `Lambda` es bytecode de Python que se
ejecuta **al cargar** el modelo.

### Autenticación

Éste es el que menos se mira y el que más regala:

```python
signing_key = jwks_client.get_signing_key_from_jwt(token)
jwt.decode(token, signing_key.key, algorithms=[signing_key.algorithm_name])
```

Dos preguntas siempre:

1. **¿Dónde vive la clave?** Si sale de un fichero en disco, ¿ese fichero está en
   una carpeta donde podés escribir? En Bobby's Bistro el llavero de claves
   públicas vivía dentro de `static/`, justo donde llegaba el `../` de la subida.
2. **¿Quién decide el algoritmo?** Si sale del propio token o de la propia clave
   (`algorithms=[signing_key.algorithm_name]`) en vez de estar fijo en el código,
   estás dejando que el dato te diga cómo validar el dato.

> **Un almacén de confianza que se puede escribir no es un almacén de confianza.**
> La escritura de ficheros parecía el fallo menor de los cuatro; era el que
> convertía "puedo subir un adjunto" en "soy quien yo diga".

---

## Las seis recetas — de sumidero a exploit

El paso anterior enseña a **reconocer**. Esto es lo que se hace con cada uno. Con
estas seis se resuelve la mayoría de los retos web que traen código fuente.

Cada receta tiene la misma forma: *cómo se reconoce*, *cómo se explota*, *cómo se
comprueba*. La tercera parte no es opcional: es la que convierte un intento en una
prueba.

### Receta 1 — Inyección SQL con ventana

**Se reconoce:** la consulta se arma con `format()`, una f-string o un `+`, **y el
resultado se pinta en la página**. Lo segundo importa tanto como lo primero: si hay
ventana, leés datos directamente en vez de sacarlos a ciegas.

**Se explota:** cerrás la comilla y forzás una condición verdadera. El `--` comenta
la comilla que sobra al final.

```
token=' OR 1=1--
```

Si necesitás datos de otra tabla, con `UNION`, igualando el número de columnas:

```sql
' UNION SELECT name,sql,null FROM sqlite_master--   -- SQLite
```

**Se comprueba:** tres peticiones. Valor válido → 1 fila. Valor inventado → 0
filas. Ataque → todas.

**Qué buscar:** el **id o uuid** del admin, tokens, roles. No pierdas tiempo con el
hash de la contraseña: en estos retos suele ser de 64 caracteres aleatorios y no se
rompe. **Te sirve la identidad, no la credencial.**

### Receta 2 — Subida sin sanear → escritura arbitraria

**Se reconoce:**

```python
file.save(CARPETA + "/" + file.filename)      # falta secure_filename()
```

**Se explota:** el nombre lo pone el cliente, así que lo ponés vos.

```bash
curl ... -F 'attachment=@/tmp/x;filename=../static/prueba.txt'
```

**Se comprueba:** subí dos ficheros iguales, uno con nombre normal y otro con
`../`. Si solo el segundo aparece donde no debería, la travesía es la causa.

**Qué escribir, en este orden:**

1. Un fichero cualquiera dentro de la carpeta servida por web, **solo para
   confirmar** que escribís.
2. El **llavero o las claves** que la app usa para validar sesiones.
3. Un fichero de configuración que la app **relea en cada petición**.
4. Código, al final: casi siempre necesita un reinicio, y el reinicio no lo
   controlás.

> **Una escritura vale lo que vale el fichero que pisás.** Antes de elegir, buscá
> qué ficheros lee la app *en cada petición* — ésos son los que dan algo inmediato.

### Receta 3 — SSTI, motor por motor

**Se reconoce:** contenido del usuario **compilado** como plantilla, no pintado
como texto.

**Se confirma siempre igual:** metés una operación y mirás si la hace. Si no sale
`49`, no hay SSTI y cualquier carga que pruebes después es tiempo perdido.

```
Jinja2 / Flask    {{7*7}}   ->  49
Chameleon         ${7*7}    ->  49
```

**Se explota** (Chameleon, el del ejemplo):

```html
<p tal:content='python: ...'>x</p>
```

Si hay filtro de caracteres, no pelees con él: **construí el texto en ejecución**
con `chr()` y `+`, que el filtro ya no puede ver. Y para leer un fichero sin
necesitar un punto, `list(open(...))` en vez de `.read()`.

**Se comprueba:** la operación primero, la carga después. Nunca al revés.

### Receta 4 — JWT: mirá quién decide

**Se reconoce:** tres preguntas, y cada una tiene su ataque.

- **¿Se comprueba el algoritmo?** Si el servidor acepta el `alg` del propio token →
  `alg: none`.
- **¿Verifica con la clave pública como secreto simétrico?** → confusión
  RS256 → HS256.
- **¿De dónde sale la clave pública?** Si sale de un fichero que podés escribir →
  reemplazalo.

**Se explota** (la tercera, que es la del ejemplo): generás tu propio par de
claves, publicás tu parte pública como llavero con un `kid` tuyo, la subís con la
receta 2, y a partir de ahí **firmás vos lo que quieras** — incluido el `user_id`
del admin que sacaste con la receta 1.

**Se comprueba:** pedí un endpoint que **solo** responda al admin. La señal es
`200` contra `302`/`401`, y el **control es tu token normal**: tiene que seguir
siendo rechazado ahí.

### Receta 5 — Formatos que ejecutan al cargarse

**Se reconoce:** `pickle.loads`, `yaml.load` sin `SafeLoader`, `marshal`, o un
modelo Keras con una capa `Lambda`.

**La marca que los distingue:** el objeto se ejecuta **al cargarse**, no al usarse.
Eso tiene una consecuencia que despista mucho: un error posterior —*"no se pudo
evaluar el modelo"*, un 422, un 500— puede llegar **después** de que tu código ya
corrió. En *Why Lambda* estuve leyendo un 422 como fracaso cuando era el éxito.

**Se comprueba:** que el efecto sea observable **por otro canal** —un fichero
creado, una ruta que cambia de respuesta— y no por lo que conteste el endpoint que
atacaste.

### Receta 6 — Prototype pollution (Node)

**Se reconoce:** `req.body` entero pasado a una función de mezcla o actualización,
sin elegir campos.

**Se explota:** se ensucia una propiedad que *otro* código lee sin comprobar que
sea suya. **La parte difícil no es ensuciar: es encontrar qué propiedad lee
alguien**, y eso se busca leyendo el código del framework, no el de la app.

**Se comprueba:** ensuciá algo inofensivo y comprobá que persiste entre peticiones.
**Aviso:** la contaminación no se deshace sola — reiniciá el laboratorio entre
pruebas o vas a estar midiendo la prueba anterior.

### Y cuando ya ejecutás: ¿dónde está la bandera?

- `/flag.txt` o `/flag` en la raíz — **miralo en el Dockerfile**, suele haber un
  `RUN mv flag.txt /flag.txt`.
- Una variable de entorno `FLAG`.
- Una tabla de la base de datos.

> La cadena del ejemplo es, literalmente, **receta 1 + receta 2 + receta 4 +
> receta 3**. Ninguna de las cuatro sirve sola: la SQLi te da un uuid que no podés
> usar, la escritura te deja tocar un fichero que no sabés cuál importa, y el SSTI
> está detrás de una puerta de admin. **El reto es el ensamblaje**, y por eso el
> paso 6 —traducir fallos a capacidades— es el que hay que aprender.

---

## Paso 5 — Probar UN fallo, con sus controles

Nunca pruebes dos cosas a la vez. **Si cambiás dos variables, no mediste
ninguna.**

Así se prueba una inyección SQL de verdad — tres peticiones, no una:

```bash
# CONTROL SANO: mi propio token -> tiene que salir 1 usuario, yo
# CONTROL NEGATIVO: un token inventado -> no tiene que salir nada
# PRUEBA: ' OR 1=1--  -> tienen que salir todos
```

```
CONTROL SANO     -> User ID: 5f4b... Username: juan482  Role: chatter
CONTROL NEGATIVO -> (vacio)
INYECCION        -> bobby_ddb7339545e6ffe88579 (admin) + juan482 (chatter)
```

El sano prueba que la consulta funciona. El negativo prueba que no devuelve filas
porque sí. **Sin los dos, un resultado positivo no significa nada.**

Lo mismo con la escritura de ficheros — subí dos, y que la única diferencia sea
el `../`:

```
nombre normal   -> cae en uploads/   GET /static/normal.txt   → 404
nombre con ../  -> cae en static/    GET /static/travesia.txt → 200
```

Mismo endpoint, mismo contenido, mismo todo. Lo único que cambia es la travesía,
así que la travesía es la causa. Eso es un experimento; lo otro es una anécdota.

> **Si todas las entradas te dan la misma respuesta, no estás midiendo nada.**

---

## Paso 6 — Encadenar: pensá en capacidades, no en fallos

Cuando tenés los fallos sueltos, no pienses "tengo una SQLi y una subida".
Traducilos a **capacidades**, y encajalas:

| Fallo | Capacidad |
|---|---|
| SQLi en `/profile` | *puedo leer cualquier fila de la base* → el UUID del admin |
| Subida sin sanear | *puedo escribir cualquier fichero* → … ¿qué fichero importa? |
| El JWKS vive en `static/` | *puedo reemplazar las claves de confianza* → **firmo yo los tokens** |
| SSTI, pero solo el admin llega | *ejecuto código* → la bandera |

La pregunta que une la cadena es siempre la misma: **"¿qué me falta, y cuál de
mis capacidades me lo da?"**

Me falta ser admin. No puedo robarle la sesión (el bot no es navegador) y no
puedo adivinar su contraseña (64 caracteres aleatorios). Pero puedo escribir
ficheros, y la verificación de sesión lee un fichero. Fin.

### Los filtros de caracteres casi nunca aguantan

En Bobby's Bistro el SSTI estaba "protegido" así:

```python
for i in '$#{}"_.':
    content = content.replace(i, "")
```

Adiós a `${...}`, a `__import__`, a `os.system` y a cualquier `.atributo`. Pero
quedan `'`, `(`, `)`, `+` y los dígitos, y con eso se fabrica texto en ejecución:

```html
<p tal:content='python: list(open(chr(47)+chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+chr(116)+chr(120)+chr(116)))'>x</p>
```

`chr(46)` es el punto. El filtro **ya miró el texto y se fue**; no puede ver la
cadena que el programa arma después. Y `list(open(...))` lee el fichero sin
necesitar `.read()`, así que tampoco hace falta un punto para eso.

> Un filtro de caracteres defiende contra una **forma de escribir**, no contra una
> **capacidad**. Mientras quede alguna manera de construir texto en tiempo de
> ejecución, la lista negra es decorativa.

**Probá el filtro contra la tubería exacta del servidor**, no contra tu idea de
ella. Si el servidor hace `markdown → filtro → plantilla`, tu prueba tiene que
hacer las tres, con las mismas versiones. Lo más fácil: correrla **dentro del
contenedor**.

```bash
docker cp prueba.py r0:/tmp/p.py && docker exec r0 python3 /tmp/p.py
```

---

## Paso 7 — Cuando todo comprueba bien y sigue fallando

Esto te va a pasar, y es el momento más caro del reto si no sabés qué hacer.

En Bobby's Bistro, con los cuatro fallos ya probados por separado, la cadena
fallaba. Comprobé cinco cosas:

- el fichero en disco dentro del contenedor era **byte a byte el que subí** ✓
- el token legítimo **había dejado de funcionar** → la app usaba mi llavero ✓
- ese mismo token verificaba **a mano** dentro del contenedor ✓
- solo había **un** `jwks.json`, y el directorio de trabajo era el correcto ✓
- la app había arrancado **una sola vez**: no se regeneraron claves ✓

Cinco comprobaciones, cinco síes, y el resultado seguía siendo 401.

> **Cuando todo lo que medís da bien y el resultado sigue mal, estás midiendo la
> cosa equivocada.** Dejá de comprobar y hacé hablar al código.

El código del reto tenía esto:

```python
except:
    return False        # cualquier fallo se convierte en un 401 identico
```

Un `except:` mudo. En **mi laboratorio** (nunca en el objetivo) lo parcheé para
que hablara:

```python
except Exception as e:
    import traceback; traceback.print_exc()
    return False
```

Reinicié el servicio, repetí el ataque, leí el registro, y salió al primer
intento:

```
PyJWKClientError('Unable to find a signing key that matches: "b41fe52e..."')
```

Ese `kid` era **el original de la aplicación**, no el mío. O sea: el servidor
nunca llegó a ver mi token. **El fallo estaba en mi herramienta, no en la
cadena.**

### La causa, que te va a morder a vos también

```python
S = requests.Session()
S.post(f"{B}/login", data=...)                      # deja auth_token en la sesion
S.get(f"{B}/api/x", cookies={"auth_token": forjado}) # ← manda LAS DOS cookies
```

`requests` **no sustituye** la cookie de la sesión por la que pasás en
`cookies=`: manda las dos (una con dominio, otra sin él) y el servidor se queda
con la primera. Tu exploit parece roto y está perfecto.

**Solución:** llamadas sueltas sin sesión compartida, con `cookies=` explícito en
cada una, o `S.cookies.clear()` después del login.

> Es el mismo error que un control positivo que rompe el depurador en vez del
> programa: **creés que medís el ataque y estás midiendo tu propia herramienta.**

---

## Paso 8 — Recién ahora, el objetivo

Cuando la cadena entera funciona en local de punta a punta y te devuelve la
bandera falsa del laboratorio, cambiás la URL y disparás **una vez**.

```bash
python3 solve.py http://127.0.0.1:13001        # laboratorio, bandera falsa
python3 solve.py http://<objetivo>:<puerto>    # objetivo, a la primera
```

Que tu script **imprima cada paso**, para que si algo falla sepas cuál:

```
  [1] sesion de usuario normal ... ok
  [2] admin por SQLi ............. bobby_605453fbbe88408b0a3b  11b4e751-...
  [3] llavero sustituido ......... ok
  [4] /admin responde ............ 200 (soy admin)
  [5] anuncio publicado .......... 120 caracteres, ni un punto literal
```

Un exploit que solo imprime "bandera" o "fallo" te deja igual de ciego que el
objetivo.

---

## Paso 9 — El writeup es el producto

El reto resuelto no vale nada dentro de tu cabeza. Escribí:

- la cadena, eslabón por eslabón, **con el código que la causa**
- **lo que fallaste** y por qué — es la parte que más enseña
- Q&A de entrevista: las preguntas que te harían sobre esa técnica
- **mitigaciones**: cómo se arregla cada fallo

Y **sin la bandera si el reto sigue activo.** La bandera es la única parte que no
enseña nada: es la respuesta del examen.

---

## La lista de comprobación

Imprimila mentalmente cada vez:

- [ ] ¿De quién es la caja?
- [ ] `find` del árbol, versiones, Dockerfile. ¿Dónde está la bandera?
- [ ] **Si hay bot: ¿navegador o cliente HTTP?**
- [ ] Laboratorio levantado, con control sano **y** control positivo
- [ ] Tabla de rutas: sesión / admin / qué entra
- [ ] Sumideros: SQL, ficheros, plantillas, deserialización, **de dónde sale la clave**
- [ ] Cada fallo probado por separado, con sus dos controles
- [ ] Fallos traducidos a capacidades, y encajados
- [ ] Cadena completa verde en local
- [ ] Un solo disparo al objetivo
- [ ] Writeup, sin bandera si está activo

---

## Los seis errores que más caros salen

1. **Disparar a ciegas al objetivo.** Tres intentos, cero información. Montá el
   laboratorio: son dos minutos y te devuelve horas.
2. **Leer el bot al final.** Es lo que decide si el XSS existe o no. Leelo el
   primero.
3. **Probar sin controles.** Un resultado sin control no distingue "funcionó" de
   "siempre sale eso".
4. **Cambiar dos cosas a la vez.** Si falla, no sabés cuál. Una variable por
   prueba, siempre.
5. **Culpar al objetivo cuando falla tu herramienta.** Cookies, codificación,
   comillas, versiones. Ante un resultado imposible, sospechá primero de tu lado.
6. **Tragarse los errores.** Ni en tu script (`| tail` se come el código de
   salida) ni en el objetivo (`except:` mudo). Un envoltorio que esconde los
   fallos es peor que ninguno.

---

## Apéndice — los comandos de siempre

```bash
# abrir y mapear
unzip -P hackthebox reto.zip -d ~/ctf/reto
find . -type f -not -path '*/node_modules/*' | sort

# laboratorio
docker build -t reto . && docker run -d --name r0 -p 13001:3000 reto
docker logs r0 | tail -30
docker exec r0 sh -c 'tail -40 /var/log/app_error.log'
docker exec r0 sh -c 'ls -la /app/static'
docker cp prueba.py r0:/tmp/p.py && docker exec r0 python3 /tmp/p.py
docker rm -f r0 && docker run -d --name r0 -p 13001:3000 reto   # limpiar estado

# peticiones
curl -s -i -X POST $B/login -d 'username=u&password=p'
curl -s -X POST $B/profile -b "auth_token=$C" --data-urlencode "token=' OR 1=1--"
curl -s -X POST $B/api/chat-messages -b "auth_token=$C" \
     -F 'message=x' -F 'attachment=@/tmp/f;filename=../static/prueba.txt'

# ver un JWT sin verificarlo
python3 -c "import sys,base64,json;[print(json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4)))) for p in sys.argv[1].split('.')[:2]]" "$TOKEN"
```

---

## Lo último

El método de arriba no es mío ni es especial. Es solo esto, repetido:

> **Construí dónde ver. Medí una cosa por vez. Poné siempre un control.**
> **Y cuando el resultado no cuadre, sospechá de tu instrumento antes que del
> mundo.**

Lo demás —las inyecciones, las travesías, los SSTI— se aprende leyendo writeups.
El orden, no.

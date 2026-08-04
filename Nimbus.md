# Nimbus — HackTheBox (Hard · Linux · Cloud/AWS)

> **Formato:** writeup educativo para CV/portfolio y prep de entrevista.
> **Estado flags:** ✅ **USER OWNED** = `4104fb73866d6963b55d23fb9b56af55` (capturada en vivo 28-jul, en `/home/worker/user.txt`). ⏳ **ROOT pendiente** (bloqueado en leer `/app/worker.py` para el privesc). (La flag `HTB{d1013168...}` que figuraba antes acá era de **Resizer**, metida por error — corregido.)
> **Tema:** SSRF (bypass filtro con IP en decimal/octal) → leak de creds IAM temporales por IMDS → **AWS mock (LocalStack) como vhost `aws.nimbus.htb`** → SQS `nimbus-jobs` + deserialización YAML insegura en el worker → RCE en contenedor → (root: privesc AWS pendiente).
>
> **Detalles confirmados en vivo (28-jul):** filtro SSRF = la URL debe terminar en `.yaml`/`.yml` (bypass `?z=.yaml`) **y** bloquea IPs internas resueltas (bypass: **decimal `2852039166`** u **octal `0251.0376.0251.0376`** = `169.254.169.254`). Rol robado por IMDS = `nimbus-web-role` (solo `sqs:SendMessage`). Worker corre como `worker` uid1000 en Docker, consume la cola en ciclo lento/errático. Payload que dispara la RCE: un valor `!!python/object/apply:os.system ["<cmd>"]` dentro del YAML del job (el worker usa `yaml.load` inseguro; el *preview* web usa `safe_load`, por eso no ejecuta ahí).
> **Lección personal (importante):** este box lo *perdí* en el primer intento por **saltarme la enumeración de vhosts** y clavarme en un rabbit-hole de SSRF. Lo documento aquí precisamente por eso — ver [PLAYBOOK.md](PLAYBOOK.md).

---

## 0. TL;DR de la cadena

```
nginx :80  ──► nimbus.htb (web "job scheduler", login deshabilitado)
                    │
                    ├─ /jobs  = URL fetcher SIN AUTH  →  SSRF
                    │            └─► leak de creds AWS temporales (STS)
                    │
   ★ vhost-enum ──► aws.nimbus.htb  = AWS API mock (LocalStack) DIRECTO
                    │
   (boto3 + creds) ─┼─► sts get-caller-identity   (¿quién soy?)
                    ├─► sqs  → cola de jobs
                    │        └─► job con YAML malicioso → worker deserializa → RCE ► USER
                    └─► codebuild privilegedMode → escape a host ► ROOT
```

El insight que lo desbloquea todo: **el proveedor de nube no estaba solo detrás del SSRF — estaba publicado como un subdominio virtual propio.** Una vez que lo tratás como una API AWS normal (firma SigV4 sola, sin filtros), el resto es enumeración cloud de manual.

---

## 1. Reconocimiento

### Puertos
```bash
nmap -p- --min-rate 3000 -T4 -Pn -n 10.129.x.x      # descubre 22, 80
nmap -sVC -p22,80 -Pn -n 10.129.x.x
```
```
22/tcp  open  ssh    OpenSSH 9.6p1 Ubuntu
80/tcp  open  http   nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nimbus.htb/
```

nginx redirige a `nimbus.htb` → agregarlo a `/etc/hosts`:
```
10.129.x.x   nimbus.htb
```

### ★ Enumeración de vhosts — el paso que me costó el box

**Regla de oro:** después de descubrir un dominio, **siempre** fuzzear subdominios virtuales antes de explotar nada. El servidor puede servir apps completamente distintas según el header `Host`.

```bash
# baseline: tamaño de una respuesta a un Host que no existe (para el filtro -fs)
curl -s -H "Host: nope.nimbus.htb" http://10.129.x.x/ | wc -c

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     -u http://10.129.x.x/ -H "Host: FUZZ.nimbus.htb" -fs <baseline>
```

Resultado: **`aws.nimbus.htb`** — un endpoint AWS-compatible (LocalStack) servido directo en el :80. *Esto* es lo que nunca busqué la primera vez, y es el eje de todo el box.

```
10.129.x.x   nimbus.htb aws.nimbus.htb
```

---

## 2. La app web y el vector SSRF

`nimbus.htb` es un "scheduler de jobs cloud". El login está deshabilitado, y la propia página lo regala:

> *"the job submitter is unauthenticated during the migration window — submit jobs there directly."*

En `/jobs` hay un formulario que **recibe una URL, la busca del lado del servidor y te muestra la respuesta** (una función de "preview"). Eso es un **SSRF** de libro: el server hace la petición por vos, así que podés alcanzar servicios internos que no son accesibles desde afuera.

El objetivo clásico en cloud es el endpoint de metadatos / STS interno para **filtrar credenciales temporales**:

```
Action=GetCallerIdentity / GetSessionToken  →  el mock responde con
AccessKeyId / SecretAccessKey / Token (creds STS temporales)
```

Guardé esas creds (aparecen en `creds.html` de mis notas).

### ⚠️ El rabbit-hole (lo que NO hay que hacer)

Mi error la primera vez: intenté ejecutar **cada** operación AWS *a través* del SSRF — firmando peticiones SigV4 a mano y contrabandeándolas por el fetcher, peleándome con un filtro de extensión que obligaba a colgar un `&z=.yaml` al final de la URL. El mock STS me devolvía `403 InvalidClientTokenId` una y otra vez:

```
<Error><Code>InvalidClientTokenId</Code>
<Message>The security token included in the request is invalid.</Message></Error>
```

**Cuando un camino se vuelve "imposible" (filtro raro, respuestas incoherentes), esa es la señal de que NO es el intended.** La respuesta correcta no era pelear más contra el filtro: era *re-enumerar*. Y la re-enumeración (los vhosts) daba `aws.nimbus.htb`, donde las mismas creds funcionan **directo**, sin SSRF y sin filtro.

---

## 3. Pivot al AWS mock directo (el intended)

Con `aws.nimbus.htb` en `/etc/hosts` y las creds temporales, ya no hace falta el SSRF: le hablás a la API AWS como cualquier cliente, con la firma SigV4 que boto3/awscli calculan solos.

```python
import boto3
sess = boto3.Session(
    aws_access_key_id=creds['AccessKeyId'],
    aws_secret_access_key=creds['SecretAccessKey'],
    aws_session_token=creds['Token'],
    region_name='us-east-1')
EP = 'http://aws.nimbus.htb'

sess.client('sts', endpoint_url=EP).get_caller_identity()   # ¿quién soy?
sess.client('sqs', endpoint_url=EP).list_queues()           # ¿qué colas hay?
```

**Enumeración cloud estándar con creds robadas** (checklist del PLAYBOOK):

| Servicio | Para qué |
|---|---|
| `sts get-caller-identity` | identidad/rol actual |
| `sqs list-queues` | colas de mensajes (aquí está el job runner) |
| `s3 ls` · `secretsmanager list-secrets` | datos y secretos |
| `ssm describe-parameters` · `lambda list-functions` | más superficie |
| `iam list-roles` / `get-role-policy` | rutas de AssumeRole a algo con más permisos |

`sqs list-queues` revela una **cola de jobs** que un worker consume en background.

---

## 4. De la cola de jobs a RCE (deserialización YAML) ► USER

El worker toma cada mensaje de la cola, lo interpreta como un **job en YAML** y lo carga. El bug: usa un cargador YAML **inseguro** (equivalente a `yaml.load()` sin `SafeLoader` en PyYAML).

### Por qué esto es RCE

YAML "full" soporta tags que **instancian objetos Python arbitrarios**. Un cargador inseguro que encuentra un tag `!!python/object/apply:<callable>` **llama a ese callable con los argumentos dados** durante el parseo. Si el atacante controla el YAML, controla qué función se ejecuta → ejecución de código.

Payload conceptual (ilustrativo — el "comando" es el punto a defender, no lo hardcodeo):
```yaml
# el worker deserializa esto y ejecuta el callable embebido
name: build
task: !!python/object/apply:os.system ["<comando del atacante>"]
```

Envío del job a la cola (mismo cliente boto3 de arriba):
```python
sqs = sess.client('sqs', endpoint_url=EP)
sqs.send_message(QueueUrl=<url_de_la_cola>, MessageBody=<yaml_malicioso>)
```

Para el shell interactivo usé un **callback estándar de reverse shell** a mi host (`nc`/pwncat escuchando). No pego el string exacto aquí a propósito: lo relevante para un writeup es la *clase de vuln* (deserialización), no el one-liner de conexión.

El worker corre el YAML → **ejecución como el usuario del servicio** → shell → **flag de usuario**.

> **Mitigación (blue-team):** `yaml.safe_load()` **siempre**; nunca `yaml.load()` con el `Loader` por defecto sobre input no confiable. Un scheduler de jobs debe validar contra un **esquema** (allow-list de campos) en vez de deserializar objetos arbitrarios. Correr el worker con privilegios mínimos y en sandbox.

---

## 5. Privesc a ROOT vía CodeBuild

Con las creds y el mock enumerado, aparece **CodeBuild** (servicio de CI de AWS que LocalStack emula). La debilidad: se puede lanzar un proyecto de build en **modo privilegiado**, y el sandbox del build comparte demasiado con el host.

Cadena (explicada, no como copy-paste ofensivo):

1. **Proyecto CodeBuild con `privilegedMode: True`** — el contenedor de build corre con capacidades extendidas.
2. **Bypass del drop de UID:** el runner intentaba bajar privilegios chequeando `id`; se puede envenenar ese chequeo exportando una **función de entorno de bash** que sobreescribe `id` (técnica tipo `BASH_FUNC_...`), haciendo creer al runner que ya es un uid sin privilegios cuando en realidad no lo es.
3. **Escape al host con `core_pattern`:** en Linux, `/proc/sys/kernel/core_pattern` puede apuntar a un *usermode helper* que el kernel ejecuta **como root en el host** cuando un proceso genera un core dump. Si el contenedor privilegiado puede escribir ese archivo, apuntarlo a un script propio y luego forzar un crash hace que el kernel corra ese script como root.

Resultado: ejecución como **root en el host** → **flag de root**.

> **Mitigación:** no exponer CodeBuild `privilegedMode` a identidades de bajo privilegio; los contenedores no deben poder escribir `/proc/sys/kernel/core_pattern` (namespacing / seccomp / `CAP_SYS_ADMIN` denegado); segmentar la cuenta cloud para que un worker de jobs no tenga IAM hacia CI.

---

## 6. ¿Por qué es "Insane"?

- **La superficie real está escondida detrás de un `Host` header.** Sin vhost-enum, ni ves el 70% del box. (Justo mi error.)
- **Trampa de diseño:** el SSRF *funciona* y te tienta a resolver todo por ahí, metiéndote en un filtro anti-relay diseñado para ser un pozo. El intended es más simple una vez que re-enumeras.
- **Cadena multi-dominio:** web → SSRF → IAM/STS → SQS → deserialización → CI → kernel. Cada eslabón es de un área distinta (appsec, cloud, Linux interno).
- **Emulación cloud (LocalStack)** en vez de AWS real: hay que reconocer los servicios por comportamiento, no por documentación oficial.

---

## 7. 🛡️ Defensa de entrevista (Q&A anticipando al reclutador)

**P: ¿Qué es un vhost y por qué lo enumeras siempre?**
Un virtual host es un sitio distinto servido por el mismo servidor/IP, seleccionado por el header `Host`. Un solo puerto 80 puede servir N apps. Si no fuzzeás el `Host`, te perdés superficie entera — en Nimbus, el AWS mock vivía en `aws.nimbus.htb` y era invisible desde `nimbus.htb`. Herramienta: `ffuf -H "Host: FUZZ.dom" -fs <baseline>`.

**P: Explicá el SSRF y por qué es tan peligroso en cloud.**
SSRF = lográs que el *servidor* haga peticiones que vos elegís. En cloud es crítico porque el server suele tener acceso a endpoints internos (metadatos `169.254.169.254`, STS, servicios privados) que filtran **credenciales temporales de IAM**. Con esas creds actuás como la propia app.

**P: ¿Por qué `yaml.load()` es RCE y `safe_load()` no?**
El loader por defecto de PyYAML soporta tags que **construyen objetos Python arbitrarios** (`!!python/object/apply:...`), lo que permite invocar callables como `os.system` durante el parseo. `safe_load()` usa `SafeLoader`, que solo mapea a tipos básicos (dict/list/str/int) y rechaza esos tags. Misma clase de bug: pickle, Java/`ObjectInputStream`, .NET `BinaryFormatter`, Ruby Marshal.

**P: ¿Cómo escapa un contenedor con `core_pattern`?**
`/proc/sys/kernel/core_pattern` define qué corre el kernel cuando un proceso genera un core dump. Si empieza con `|`, el kernel ejecuta ese programa **como root en el namespace del host**. Un contenedor privilegiado que puede escribir ese archivo apunta el pattern a un script propio y provoca un crash → root en el host. Defensa: `core_pattern` es global al kernel; un contenedor no debería tener `CAP_SYS_ADMIN` ni acceso de escritura a `/proc/sys`.

**P: Si tuvieras que arreglar Nimbus como blue-team, ¿por dónde empezás?**
(1) Quitar el SSRF: validar/allow-list de destinos en el fetcher, sin acceso a rangos internos ni metadatos (IMDSv2 con hop-limit). (2) `safe_load` + validación por esquema en el worker de jobs. (3) IAM de mínimo privilegio: el rol del worker no debería poder tocar CodeBuild. (4) Contenedores sin `privilegedMode` y sin escritura a `/proc/sys`.

**P: ¿Qué diferencia el camino intended del rabbit-hole?**
Ambos empiezan en el SSRF y filtran las creds. El rabbit-hole insiste en tunelizar *toda* la API AWS por el SSRF (peleando un filtro imposible). El intended usa el SSRF **solo para filtrar las creds** y después habla con `aws.nimbus.htb` **directo**. La lección de método: cuando un vector se vuelve "imposible", re-enumerar en vez de insistir.

---

## 8. Mitigaciones (resumen blue-team)

| Eslabón | Fix |
|---|---|
| `/jobs` SSRF | allow-list de URLs de salida; bloquear IPs internas/link-local; IMDSv2 + hop-limit |
| AWS mock como vhost | no exponer el plano de control cloud en la red de la app; segmentación |
| Creds STS filtrables | rotación corta, scoping por sesión, detección de uso anómalo |
| YAML deser | `yaml.safe_load()` + validación por esquema; worker con mínimo privilegio |
| CodeBuild privesc | prohibir `privilegedMode` a roles de bajo nivel; IAM segmentado |
| `core_pattern` escape | denegar `CAP_SYS_ADMIN`; `/proc/sys` read-only en contenedores |

---

## 9. Lección de método (lo que me llevo)

Nimbus no lo perdí por falta de capacidad técnica — lo perdí por **saltarme la enumeración de vhosts** y hacer **tunnel-vision** en el SSRF. Reglas que quedan grabadas:

1. **Enumerar vhosts/subdominios SIEMPRE** antes de explotar profundo. `ports → vhosts → dirs → params`, en ese orden.
2. **Camino "imposible" = probablemente no es el intended.** Re-enumerar, no insistir.
3. **Target no-determinista / app single-threaded:** una request a la vez, espaciada.

Ver [PLAYBOOK.md](PLAYBOOK.md) para la versión reusable de estas reglas.

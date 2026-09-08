# 🎓 Currícula de la comunidad — Pentest web + Blue Team (hands-on)

> Ruta práctica para enseñar seguridad web a quien ya pasó la **Semana Cero** (fundamentos de Linux/CLI). Cada módulo es un ataque **real, reproducible y verificado**, con su **gemelo defensivo** al lado — porque enseñamos las dos mitades: romper y defender.
>
> **Regla de la casa:** todo se practica en **laboratorios locales** (tu propia máquina). Nunca contra sistemas ajenos o sin permiso escrito. Los objetivos de acá (vulnlab.py, vulhub) son autorizados por diseño.

---

## Cómo está organizada

Dos tracks. Se recomienda arrancar por el **Track A** (fundamentos, en un solo lab controlado) y después el **Track B** (CVEs reales famosos, para ver "esto pasó de verdad").

### 🅰️ Track A — Fundamentos (lab propio: `vulnlab.py`)

Un solo laboratorio, `vulnlab.py`, expone **una clase de vulnerabilidad por endpoint**. Es la forma más limpia de enseñar el concepto sin ruido. El alumno lo levanta en 30 segundos:

```bash
pip install flask requests lxml pyjwt
python3 vulnlab.py            # escucha en http://127.0.0.1:5000
```

Orden sugerido de enseñanza (de más intuitivo a más abstracto):

| # | Módulo | Clase | Qué enseña | Endpoint |
|---|--------|-------|-----------|----------|
| 1 | [SQL Injection](Fundamento_SQLi.md) | SQLi (UNION) | input → query; extraer datos de otras tablas | `/user?id=` |
| 2 | [Command Injection](Fundamento_CommandInjection.md) | OS cmd injection | input → shell; encadenar comandos | `/ping?host=` |
| 3 | [XSS reflejado](Fundamento_XSS.md) | Cross-Site Scripting | input → HTML sin escapar; JS en el navegador | `/search?q=` |
| 4 | [SSTI → RCE](Fundamento_SSTI.md) | Template injection | input → motor de plantillas; `{{7*7}}`→RCE | `/greet?name=` |
| 5 | [SSRF](Fundamento_SSRF.md) | Server-Side Request Forgery | el server pide TU URL; llegar a servicios internos / metadata cloud | `/fetch?url=` |
| 6 | [XXE](Fundamento_XXE.md) | XML External Entity | parser XML lee archivos / hace SSRF | `POST /xxe` |
| 7 | [JWT](Fundamento_JWT.md) | Tokens débiles | secreto débil → forjar `role=admin` | `/login`, `/admin` |
| 8 | [Deserialización insegura](Fundamento_Deserializacion.md) | Deserialization → RCE | `pickle.loads` sobre input; gadget `__reduce__`→RCE | `POST /load` |

### 🅱️ Track B — CVEs reales (vulhub + Docker)

Vulnerabilidades famosas que pasaron en producción. Se montan con [vulhub](https://github.com/vulhub/vulhub) (`docker compose up -d`). Enseñan que los conceptos del Track A **son los mismos** que tumban software real.

| # | Módulo | CVE | Clase | Impacto verificado |
|---|--------|-----|-------|--------------------|
| 8 | [Apache Path Traversal → RCE](CVE-2021-41773_Apache_PathTraversal_RCE.md) | CVE-2021-41773 | Path traversal + mod_cgi | RCE `uid=daemon` |
| 9 | [ThinkPHP 5.0.23 RCE](CVE-2018-20062_ThinkPHP_5.0.23_RCE.md) | CVE-2018-20062 | Framework method-injection | RCE `uid=www-data` |
| 10 | [Spring Cloud Gateway SpEL RCE](CVE-2022-22947_SpringCloudGateway_SpEL_RCE.md) | CVE-2022-22947 | Actuator + SpEL injection | RCE `uid=root` |
| 11 | [Log4Shell](CVE-2021-44228_Log4Shell_JNDI_RCE.md) | CVE-2021-44228 | Log4j2 JNDI injection | Callback JNDI/LDAP verificado (cadena RCE explicada) |

> **Nota sobre Log4Shell:** verificamos de forma **segura** el núcleo del bug (la inyección `${jndi:...}` que hace al servidor conectarse de vuelta al atacante). La última parte de la cadena (cargar una clase Java maliciosa) se explica como teoría, sin correr binarios de terceros — que es justo lo que enseñamos a *no* hacer.

---

## El molde de cada módulo (para que el instructor lo dé igual)

Todos siguen la misma estructura, pensada para pizarrear:

1. **Qué es y por qué importa** — el concepto en criollo + el impacto.
2. **Montar el lab** — comandos exactos, reproducible por el alumno.
3. **El ataque, paso a paso** — el comando verificado, su salida real, y **por qué funciona** (el mecanismo, no el payload de memoria).
4. **🛡️ Blue Team** — la firma en los logs, una **regla Sigma**, el mapeo **MITRE ATT&CK**, y el **fix en código**.
5. **Q&A de entrevista** — 3-4 preguntas como las de una entrevista de pentest/SOC.

## Por qué enseñamos las dos mitades

El diferencial de tu comunidad: no formamos "script kiddies" ni "analistas que nunca vieron un ataque". Cada alumno sale sabiendo **ejecutar** el ataque *y* **detectarlo/mitigarlo**. Eso es lo que pide el trabajo real (pentest *y* blue team/SOC), y es lo que hace que este material valga.

---

*Método general: [PLAYBOOK.md](../PLAYBOOK.md) · arsenal completo (incl. Active Directory + Blue Team): [ARSENAL.md](../ARSENAL.md).*

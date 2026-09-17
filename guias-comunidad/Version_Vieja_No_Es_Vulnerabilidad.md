# 🔍 Una versión vieja no es una vulnerabilidad

> Guía para quien arranca. Nace de una pregunta real del grupo:
> *"¿conocen algún exploit para Dropbear sshd 2015.69?"*
>
> La respuesta corta: **sí hay exploit público, y aun así no te sirve para
> entrar.** Entender por qué enseña bastante más que el exploit.

---

## La escena

Escaneás una máquina. Sale esto:

```
22/tcp open  ssh  Dropbear sshd 2015.69 (protocol 2.0)
```

Y el cerebro hace *clic*: **2015. Es viejo. Viejo significa vulnerable. Busco el
exploit y entro.**

Ese clic es el que hay que desarmar, porque manda a mucha gente a perder tres
horas delante de un puerto que nunca fue la puerta.

---

## Qué te dice de verdad un banner

Un número de versión **no es una vulnerabilidad**. Es una **huella**: te dice qué
es la caja, no cómo entrar.

Dropbear, en concreto, es un servidor SSH diminuto pensado para equipos con poca
memoria. Verlo te dice cosas útiles:

- probablemente sea un **router, una cámara, un NAS o algo empotrado**
- o una máquina montada a propósito para parecer antigua
- va a tener **poquísimas herramientas** dentro: ni `python`, ni `curl`, a veces
  ni `bash`. Eso cambia por completo cómo vas a moverte si entrás
- el sistema de ficheros puede ser de solo lectura

Todo eso es inteligencia valiosa. Nada de eso es una forma de entrar.

---

## El caso Dropbear, hasta el final

Vamos a hacer lo que hay que hacer siempre: buscar de verdad, y leer lo que sale.

Para Dropbear anterior a 2016.74 existe **CVE-2016-7406**. En la ficha:

```
Format string vulnerability in Dropbear SSH before 2016.74 allows remote
attackers to execute arbitrary code via format string specifiers in the
username or host argument.

CVSS: 9.8 CRITICAL
```

Ejecución remota de código. Sin autenticar. 9.8 sobre 10. Parece el premio gordo.

**Y no sirve.** Por qué:

- **no hay prueba de concepto pública**
- **no hay módulo de Metasploit**
- no hay constancia de que se haya explotado nunca en la práctica

Un fallo de cadena de formato es de los más difíciles de convertir en un exploit
fiable. Hay que conocer el binario exacto, cómo fue compilado y cómo está la
memoria. Y en un equipo empotrado, el resultado más probable de intentarlo es
que el servicio se caiga — que es ruido, no acceso.

> **Un 9.8 en una ficha de CVE no es un camino para entrar.** Es una medida de lo
> grave que *sería* si alguien lograra explotarlo.

---

## Pre-auth contra post-auth: la distinción que más ahorra

Es lo primero que hay que mirar en cualquier CVE. Los otros fallos de Dropbear de
esa época lo ilustran perfecto:

| CVE | qué hace | ¿hay exploit público? | qué necesita |
|---|---|---|---|
| **2016-7406** | cadena de formato, ejecución de código | **no** | nada — pero sin exploit no sirve |
| **2016-3116** | inyección de comandos vía xauth | **sí — Exploit-DB `EDB-40119`** | **credenciales válidas** y `X11Forwarding yes` |
| **2016-7407** | clave OpenSSH maliciosa al convertirla | sí | que *otro* convierta tu fichero |
| **2016-7408** | fallo en el cliente `dbclient` | sí | que la víctima sea el cliente, no el servidor |

Mirá la columna derecha. **Ninguno te mete desde fuera.**

El `2016-3116` **sí tiene exploit público y funciona** — pero *después* de tener
usuario y contraseña. Eso lo convierte en una herramienta de **escalada**, no de
entrada. Guardalo para cuando ya estés dentro.

> **Una corrección honesta, y la dejo escrita porque enseña más que la tabla.**
> La primera versión de esta guía decía que *no había exploit público* para
> Dropbear. Era falso: el `EDB-40119` existe y se encuentra en una búsqueda.
> El error no fue de conocimiento sino de método — **afirmé un negativo con una
> sola búsqueda**. Lo correcto era decir "no encontré", que es distinto de "no
> existe". Un negativo necesita tanta prueba como un positivo, y ésta es
> exactamente la trampa contra la que avisa el resto de la guía.

---

## Cómo leer un CVE en sesenta segundos

Tres preguntas, en este orden:

1. **¿Necesita autenticación?** Si sí, no es tu camino de entrada. Anotalo para
   después y seguí.
2. **¿Existe exploit público que funcione?** Buscá en Exploit-DB, en Metasploit y
   en GitHub. Si no hay nada y el fallo es de corrupción de memoria, asumí que no
   vas a escribirlo vos esta tarde.
3. **¿Necesita una posición que no tenés?** Muchos CVE piden ser local, ser el
   cliente, o que la víctima abra algo. Si pide algo que no podés dar, no cuenta.

Si las tres respuestas te dejan fuera, **cerrá esa pestaña y volvé a enumerar.**
No es rendirse: es dejar de gastar en la puerta equivocada.

---

## Entonces, ¿qué se hace con un puerto SSH?

Casi siempre, esto:

> **Las credenciales están en otra parte.**

El SSH rara vez es la puerta. Es la cerradura que abrís con lo que encontraste en
otro sitio:

- una web con una subida de ficheros, un panel, un `.git` expuesto
- un SMB o un FTP con lectura anónima
- un fichero de configuración con una contraseña dentro
- un usuario que reutiliza la contraseña de otro servicio
- un repositorio con una clave privada olvidada en el historial

Enumerá **toda** la superficie antes de enamorarte de nada. Después volvés al 22
con lo que encontraste, y ahí sí entra.

---

## El error que hay debajo, y me incluyo

Lo que falla en "versión vieja → busco exploit → entro" no es el conocimiento.
Es el método: **decidir la respuesta antes de mirar.**

Y no es cosa de principiantes. El mismo día que surgió esta pregunta, yo estaba
resolviendo un reto y disparé **tres veces contra el objetivo** esperando que
funcionara, sin forma de ver en qué paso se rompía la cadena. Tres intentos,
ninguna información. Cuando por fin reconstruí el reto en mi propia máquina para
poder mirar los registros, la respuesta apareció **al primer intento**.

El patrón es el mismo en los dos casos: insistir en una hipótesis en vez de
buscar una forma de comprobarla.

> Cuando no podés ver lo que pasa, el trabajo no es adivinar mejor.
> Es construir el sitio donde se pueda ver.

---

## Cómo saber si un exploit es falso

Poco después de esta pregunta, alguien trajo al grupo un script "para Dropbear
2015.69", generado por un modelo de IA. Tenía la cabecera, el número de CVE, los
`[+]` de rigor y hasta banner de uso. **No explotaba absolutamente nada.**

Es un caso real y enseña más que cualquier ejemplo inventado, así que vale la
pena desarmarlo.

### Lo que decía

```python
# Exploit for CVE-2016-7409 - Dropbear SSH Server Remote Code Execution
# Target: Dropbear SSHd 2015.69
```

### Lo que es CVE-2016-7409 de verdad

> *dbclient y el servidor de Dropbear, **compilados con DEBUG_TRACE**, permiten a
> **usuarios locales** leer memoria del proceso mediante el argumento `-v`.*

Fuga de información, **local**, y solo si el binario se compiló con la depuración
activada — que no es lo habitual. CVSS 5.5, medio. La cabecera decía *"Remote
Code Execution"*. Las tres palabras clave de la descripción real —*local*,
*leer memoria*, *DEBUG_TRACE*— no aparecen por ningún lado en el script.

### Lo que hacía el código

```python
client.connect(target, port, username=username, password=password)
chan.exec_command("echo 'VULNERABLE'; cat /etc/passwd")
```

Se conecta **con el usuario y la contraseña que vos le das**, y ejecuta un
comando. Eso es un cliente SSH corriente. Si "funciona", no explotó nada: es que
tenías la contraseña. Y el `VULNERABLE` que imprime en pantalla **lo escribió el
propio script**.

También abría diez canales comentando que eso provocaba una "condición de
carrera". No hay ninguna carrera en ese CVE. Los diez canales no hacen nada.

### Las cuatro preguntas

Ese script falla las cuatro. Hacéselas a cualquiera que te pasen:

**1. ¿El CVE dice lo que el script dice?**
Buscalo en NVD o cvedetails y leé la descripción de una línea. Tarda diez
segundos y descarta la mayoría.

**2. ¿Dónde está la parte que explota?**
Seguí el flujo y preguntá *qué línea concreta abusa del fallo*. Un exploit real
tiene un paquete malformado, un desplazamiento, una estructura rara. Si al quitar
el comentario que dice "aquí ocurre la explotación" no queda nada, no había nada.

**3. ¿Te pide credenciales?**
Si un script te pide usuario y contraseña para "explotar" un servicio,
normalmente está usando el servicio como fue diseñado. Eso no es explotar.

**4. ¿El resultado lo produce el objetivo o el script?**
Un exploit que imprime su propia prueba de éxito no prueba nada. Que la evidencia
venga del otro lado.

### Por qué pasa esto

Un modelo de lenguaje ha visto miles de exploits. Reproducir su **forma**
—cabecera, CVE, prefijos, estructura— le sale sin esfuerzo. Reproducir su
**función** no, porque eso exige el binario exacto, cómo se compiló y cómo está
la memoria en ejecución.

Por eso salen tantos scripts con la envoltura perfecta y el interior vacío. Y por
eso cambiar de modelo, o buscar uno "sin filtros", no resuelve nada: lo que falta
no es permiso, es la parte difícil.

---

## Y si te preguntan algo que suena dudoso

Va a pasar. Alguien va a preguntar por una versión concreta sin decir de dónde
salió.

La mejor respuesta no es negarse ni soltar la herramienta y mirar a otro lado.
Es la que deja a la persona **más capaz y más cuidadosa a la vez** — y casi
siempre existe.

Mirá lo que pasó con la pregunta que abre esta guía. Pidieron un exploit. Se
fueron con: por qué un CVSS 9.8 puede no servir de nada, la diferencia entre
pre-auth y post-auth, cómo leer un CVE en un minuto, y qué hacer de verdad con un
puerto SSH. Eso vale muchísimo más que el script que pedían, y de paso quien lo
entiende ya no tiene ganas de correr basura ajena contra una caja que no conoce.

Y sí: preguntá de quién es la máquina. No como control, sino porque es parte de
responder bien — nadie puede darte una buena respuesta sobre un objetivo que no
conoce.

---

## Lo último, y no es negociable

Antes de buscar exploits para una máquina, la pregunta es **de quién es**.

HTB, un CTF, tu propio laboratorio, o un programa con alcance escrito: adelante.
Cualquier otra cosa, no — y no por miedo al castigo, sino porque lo que separa a
un investigador de seguridad de un delincuente es exactamente eso, y no es la
técnica.

Si alguien del grupo pregunta por una versión concreta, **preguntale dónde está
la caja**. No para vigilarlo: porque responder "cómo ataco esto" sin saber qué es
"esto" te hace responsable de algo que no podés ver.

# QLotto — HTB (Easy, Misc/Quantum)

> **Bandera:** no la publico — el reto está **activo**. Es la única parte de un
> writeup que no enseña nada. Todo lo demás está entero.
>
> Resuelto **al primer disparo** contra el objetivo, después de verificarlo
> contra una copia local del propio servidor.
>
> **Técnica:** los índices negativos de Python esquivan una validación de
> rango → entrelazamiento con un qubit "protegido" → **anti-correlación** para
> esquivar la segunda defensa → inversión de la reducción módulo 42.

---

## 1. La mesa

Un servidor te deja construir un circuito cuántico de dos qubits. El qubit 0 es
**de la casa**: el servidor le aplica `H` y de ahí salen los seis números del
sorteo. El qubit 1 es tuyo.

Te enseña los números que salen de **tu** qubit. Tenés que adivinar los suyos.

```python
def generate_circuit(self, instructions):
    circuit = QuantumCircuit(2)
    circuit.h(0)                     # el qubit de la casa: 50/50
    ...
```

Tres defensas, y hay que romper las tres.

---

## 2. Primera defensa: "no toques la carta de la casa"

```python
if any(p == 0 for p in params):
    print("[Dealer] Hey, don't tamper with the house card — that's forbidden.")
    return None

if len(params) == 1:
    if any(n >= circuit.num_qubits for n in params):
        print(f"[Dealer] Card numbers must be less than {circuit.num_qubits}")
        return None
```

Leído rápido suena hermético: **el índice no puede ser 0 y no puede ser ≥ 2.**
Con dos qubits, eso deja solo el 1. El qubit de la casa, intocable.

El fallo es que las dos comprobaciones juntas **no describen un rango**:

```
con 2 qubits:  el indice -2 apunta al qubit 0   y  el -1 al qubit 1
la comprobacion p == 0  lo deja pasar:  False
la comprobacion p >= 2  lo deja pasar:  False
```

En Python, `lista[-2]` es el penúltimo elemento; Qiskit hereda esa semántica.
**`-2` y `0` son el mismo qubit.** La validación comprueba una *representación*,
no la *cosa*.

> Esta es la clase entera del reto: el fallo no está en la criptografía ni en la
> física cuántica. Está en una validación de índices que asumió que los números
> empiezan en cero y no bajan de ahí.

Es el mismo error que un `if (indice > maximo)` sin comprobar el negativo, que en
C te da una lectura fuera de límites. Cambia el lenguaje, no el error.

---

## 3. Segunda defensa: no podés copiar

Con el qubit 0 alcanzable, el primer impulso es entrelazarlos para que mi bit
sea **igual** al suyo. Pero:

```python
if lotto_numbers == testing_numbers:
    print("[Dealer] Trying to mirror the house's numbers, are we?")
    return
```

El espejo está prohibido. Hace falta un estado donde mis números **determinen**
los suyos sin **ser** los suyos.

La respuesta es la anti-correlación: el estado `(|01⟩ + |10⟩)/√2`. Mi bit es
siempre el contrario al suyo. Nunca son iguales, y conocer uno es conocer el otro.

Y hay una tercera comprobación que hay que respetar mientras tanto:

```python
def validate_entropy(self, base_circuit, shots = 100_000):
    circuit.measure(0, 0)                       # mide SOLO el qubit de la casa
    binomial_test = binomtest(counts.get('0', 0), n = shots, p = 0.5, ...)
    if binomial_test.pvalue < 0.01: return False
```

Comprueba que el qubit de la casa siga siendo una moneda justa, con cien mil
tiradas y un test binomial. La anti-correlación la pasa sin despeinarse: cada
qubit por separado sigue siendo 50/50. **Lo que cambia es la correlación entre
los dos, y eso no lo mide.**

> Medir un qubit por separado no puede detectar el entrelazamiento. La prueba de
> aleatoriedad está bien hecha y aun así no ve nada, porque mira una marginal
> cuando el ataque vive en la conjunta.

---

## 4. Construir el estado sin las puertas que querrías

El menú es corto: `H`, `S`, `T`, `Z` de un qubit, y `RXX` / `RYY` / `RZZ` de dos.
No hay CNOT.

Aquí hice algo que vale más que la secuencia: **en vez de derivarla a mano, la
busqué en el simulador.** Derivar qué produce cada combinación de puertas es
fácil de hacer mal, y equivocarse en silencio cuesta horas. El simulador es el
mismo que corre el servidor, así que lo que diga aquí es lo que va a pasar allá.

```python
for pre in ["", "H:1;"]:
    for g in ["RXX", "RYY", "RZZ"]:
        for a in [45, 90, 135, 180, 225, 270, -90, -45]:
            for post in ["", "H:1;", "H:1;Z:1;H:1;", "S:1;H:1;", "Z:1;H:1;"]:
                ...
# de 240 jugadas, 5 anti-correlacionan perfecto:
#   RYY:270,-2,-1;S:1;H:1     casa 0 = 0.496   coinciden = 0.000
```

240 combinaciones tardan menos que un solo intento de derivarlo a mano, y el
resultado viene comprobado en vez de supuesto.

El criterio de aceptación tenía que ser **doble**, y esto importa: `coinciden ≈ 0`
dice que la anti-correlación es perfecta, pero por sí solo también lo cumpliría
un estado degenerado. `casa 0 ≈ 0.5` confirma que el qubit de la casa sigue vivo
y que `validate_entropy` no va a cortar. Una sola condición no distingue "ataque
correcto" de "circuito roto".

---

## 5. Tercera defensa: el módulo que borra información

Falta invertir lo que ves para obtener lo que no ves:

```python
lotto_number   = int(lotto_number,   2) % 42 + 1
testing_number = int(testing_number, 2) % 42 + 1
```

Seis bits dan 0–63, pero te muestran el resultado **módulo 42**. Eso pierde
información: un 5 en pantalla pudo salir de un 4 o de un 46. Con seis números,
2⁶ = 64 combinaciones posibles: fuerza bruta viable, pero sucia.

No hace falta. La ambigüedad **se cancela sola**:

- si veo `n`, mi crudo es `n-1` o `n-1+42`
- la casa es el complemento: `63 - crudo`
- los dos candidatos dan `64-n` y `22-n`, que **difieren exactamente en 42**
- y `% 42` los colapsa al mismo número

```
numeros con salida ambigua: 0 de 42
la formula queda:  casa = (64 - n) % 42 + 1
```

De regalo, la misma aritmética prueba que la jugada nunca dispara la defensa del
espejo: `(64-n) % 42 + 1 == n` exige `2n ≡ 23 (mod 42)`, y el lado izquierdo es
par mientras el derecho siempre es impar. **Sin solución, para ningún `n`.** No
es que tuviera suerte: es imposible que coincidan.

---

## 6. El exploit entero

```python
JUGADA = "RYY:270,-2,-1;S:1;H:1"
casa = lambda n: (64 - n) % 42 + 1

io.sendlineafter(b"moves : ", JUGADA.encode())
mios  = [int(n) for n in re.findall(r"\d+", io.recvline_contains(b"draws are").decode())]
io.sendlineafter(b"table : ", ",".join(str(casa(n)) for n in mios).encode())
```

```
  me muestra : [39, 12, 6, 36, 14, 22]
  deduzco    : [26, 11, 17, 29, 9, 1]
  The table erupts in chaos — you've cracked the QLotto!
```

Determinista. No hay 1/42⁶ de suerte: los números de la casa estaban escritos en
los míos desde que se midió el circuito.

---

## 7. El método, que es lo que se repite

Antes de tocar el objetivo, monté el servidor **real** en local con un
`secret.py` falso y le disparé ahí. Salió a la primera, y solo entonces fui al
objetivo — donde también salió a la primera.

Es la misma lección que me costó tres disparos a ciegas en *WhyLambda*:

> Cuando no podés ver lo que pasa, el trabajo no es adivinar mejor.
> Es construir el sitio donde se pueda ver.

Con un reto de red es casi gratis: el código está delante tuyo, montarlo son dos
minutos, y a cambio cada hipótesis se prueba en segundos en vez de por turnos
contra un servidor que solo te dice sí o no.

---

## 8. Q&A de entrevista

**¿Por qué `-2` pasa una validación que prohíbe el 0 y todo lo ≥ 2?**
Porque las dos comprobaciones juntas no acotan un rango: dejan abierto todo lo
negativo. Python indexa desde el final con índices negativos, así que `-2` en un
registro de 2 qubits **es** el qubit 0. La validación comprueba cómo se escribe
el índice, no a qué apunta. El arreglo es validar contra el rango completo
(`0 <= n < num_qubits`) y después excluir el qubit protegido.

**¿Por qué la prueba de aleatoriedad no detecta el ataque?**
Porque mide un solo qubit, cien mil veces. El qubit de la casa sigue siendo
exactamente 50/50 en un estado anti-correlacionado — la marginal no cambia. Lo
que cambia es la correlación **entre** los dos qubits, que ninguna medición de
uno solo puede ver. Detectarlo pediría medir ambos y comprobar la independencia,
o rechazar cualquier circuito que toque el qubit de la casa.

**¿Por qué anti-correlacionar y no copiar?**
Porque el servidor rechaza explícitamente que tus números salgan iguales a los
suyos. La anti-correlación da la misma información —conocer uno determina el
otro— sin producir la igualdad que se comprueba. La defensa buscaba una
*coincidencia*, no una *dependencia*.

**El módulo 42 pierde información. ¿Por qué no hace falta fuerza bruta?**
Porque los dos preimágenes de un valor mostrado difieren en 42, y al complementar
a 63 la diferencia se conserva; el `% 42` final los vuelve a juntar. La
ambigüedad se propaga y se cancela. Vale la pena comprobarlo con los 42 casos en
vez de confiar en el argumento.

**¿Por qué buscar la secuencia de puertas en vez de derivarla?**
Porque el simulador local es el mismo que corre el servidor, 240 combinaciones
tardan menos que una derivación a mano, y el resultado viene verificado. Derivar
está bien para entender **por qué** funciona — no para averiguar **si** funciona.

**¿Con qué doble criterio se acepta una jugada candidata?**
Coincidencias ≈ 0 (la anti-correlación es perfecta) **y** P(casa=0) ≈ 0.5 (el
qubit de la casa sigue siendo aleatorio y la validación de entropía va a pasar).
Con una sola condición no se distingue un ataque correcto de un circuito roto.

---

## 9. Mitigaciones

| defensa | por qué falla | arreglo |
|---|---|---|
| **Índices** | `p == 0` y `p >= num_qubits` no cierran el lado negativo | Validar el rango completo: `0 <= n < num_qubits`, y *después* excluir los qubits protegidos. Es el mismo bug de un `if (i > max)` sin comprobar `i < 0`. |
| **Aleatoriedad** | Mide una marginal; el ataque vive en la conjunta | Medir los dos qubits y comprobar independencia, o directamente prohibir que el circuito del jugador toque el qubit de la casa (aislarlo en otro registro, no protegerlo con una comprobación). |
| **Anti-espejo** | Comprueba igualdad, no dependencia | La igualdad es un caso particular de correlación. Si la propiedad que importa es "no puede deducirlos", hay que comprobar eso — o hacerlo imposible por construcción. |
| **Diseño** | El qubit de la casa vive en el mismo circuito que el del jugador | Separar lo sorteado de lo controlado por el usuario. Ninguna validación de entrada habría sido necesaria si el jugador no pudiera nombrar ese qubit. |

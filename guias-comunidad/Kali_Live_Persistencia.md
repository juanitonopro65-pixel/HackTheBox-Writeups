# 💾 Cómo hacer persistente Kali Live (USB)

> Guía para quien arranca. Objetivo: que tu Kali booteado desde USB **conserve** archivos, herramientas y configuración entre reinicios — en vez de empezar de cero cada vez.

---

## 1. ¿Por qué Kali Live pierde todo?

Cuando booteás Kali en modo **Live** (desde el USB, sin instalarlo en el disco), el sistema corre **en la memoria RAM**. La RAM se borra al apagar → todo lo que hiciste (guardar un archivo, instalar una tool, cambiar una config) **desaparece** al reiniciar.

La **persistencia** resuelve esto: se crea un espacio de guardado *en el mismo USB* donde Kali escribe los cambios, y los vuelve a cargar en el próximo arranque.

> ⚠️ Persistencia **no es lo mismo** que instalar Kali. Es "Live con memoria". Si querés un sistema completo y rápido, lo mejor a la larga es **instalarlo** (en el disco o en una VM). La persistencia es ideal para llevar tu Kali en el bolsillo.

---

## 2. Qué necesitás (antes de empezar)

- Un **USB de 16 GB o más** (cuanto más grande, más espacio de guardado).
- La **ISO de Kali Live** grabada al USB con una herramienta en **modo imagen/DD** (para que quede espacio libre para la persistencia):
  - **Windows:** [Rufus](https://rufus.ie) → al grabar, elegí **"DD Image mode"**; o **balenaEtcher**.
  - **Linux/Mac:** `dd` (ver abajo) o balenaEtcher.
- Podés hacer los pasos **desde otra Linux** o **desde la misma Kali Live ya booteada**.

> Grabar la ISO (si aún no lo hiciste), ejemplo en Linux — **verificá el device primero** (sección 4):
> ```bash
> sudo dd if=kali-linux-live.iso of=/dev/sdX bs=4M status=progress && sync
> ```

---

## 3. La idea, en 3 piezas

La persistencia son solo **tres cosas**:

1. Una **partición extra** en el USB (en el espacio libre), formateada en **ext4**.
2. Esa partición **etiquetada con el nombre exacto `persistence`**.
3. Adentro, un archivo llamado **`persistence.conf`** que contiene una sola línea: **`/ union`**.

Y al arrancar, elegir la opción de persistencia en el menú de boot. Nada más.

---

## 4. ⚠️ Paso 0 — Identificar el USB (crítico)

**El error más caro es apuntar al disco equivocado y borrarlo.** Antes de tocar nada:

```bash
sudo lsblk
```

Fijate cuál es tu USB por su **tamaño** (ej: 32G) y su nombre (ej: `sdb`). La ISO ya le creó dos particiones (`sdb1`, `sdb2`); vas a crear la tercera (`sdb3`) en el espacio libre.

> En esta guía uso **`/dev/sdb`** como ejemplo. **Cambiá `sdb` por el tuyo.** Si te confundís de disco, perdés datos — mirá `lsblk` dos veces.

---

## 5. Método A — Persistencia normal (sin cifrar)

**5.1. Crear la partición** en el espacio libre:

```bash
sudo parted /dev/sdb
```
Dentro de `parted`:
```
print                          # ver las particiones actuales y dónde termina la última
mkpart primary ext4 <fin> 100% # <fin> = donde terminó la última partición (ej: 3.9GB)
quit
```

**5.2. Formatear y etiquetar** (la etiqueta **tiene** que ser `persistence`):

```bash
sudo mkfs.ext4 -L persistence /dev/sdb3
```

**5.3. Crear el `persistence.conf`:**

```bash
sudo mkdir -p /mnt/persist
sudo mount /dev/sdb3 /mnt/persist
echo "/ union" | sudo tee /mnt/persist/persistence.conf
sudo umount /mnt/persist
```

Listo. Saltá a la **sección 7 (arrancar)**.

---

## 6. Método B — Persistencia **cifrada** (recomendada 🔒)

Kali es una distro de seguridad: si perdés o te roban el USB, **cualquiera vería tus archivos** con persistencia normal. Con cifrado LUKS, no.

Igual que el Método A pero cifrando la partición:

```bash
# 6.1. Cifrar la partición (te pide crear una passphrase — anotala, no hay recuperación)
sudo cryptsetup --verbose --verify-passphrase luksFormat /dev/sdb3

# 6.2. Abrirla (te pide la passphrase)
sudo cryptsetup luksOpen /dev/sdb3 my_usb

# 6.3. Formatear + etiquetar el volumen ya descifrado
sudo mkfs.ext4 -L persistence /dev/mapper/my_usb

# 6.4. Crear el persistence.conf
sudo mkdir -p /mnt/persist
sudo mount /dev/mapper/my_usb /mnt/persist
echo "/ union" | sudo tee /mnt/persist/persistence.conf
sudo umount /mnt/persist

# 6.5. Cerrar
sudo cryptsetup luksClose my_usb
```

Al arrancar con la opción **Encrypted Persistence**, Kali te va a pedir la passphrase.

---

## 7. Arrancar CON persistencia

Reiniciá y booteá desde el USB. En el menú de arranque (GRUB/isolinux), en vez de "Live system", elegí:

- **"Live system (persistence)"** → Método A.
- **"Live system (encrypted persistence)"** → Método B (te pide la passphrase).

> 🔑 Si booteás con la opción **"Live system"** normal, **NO** usa la persistencia y los cambios se pierden igual. Tenés que elegir la opción de persistencia **cada vez**.

---

## 8. Verificar que funciona

1. Booteá con la opción de persistencia.
2. Creá un archivo de prueba: `touch ~/Desktop/prueba_persistencia.txt`
3. Reiniciá (volviendo a elegir la opción de persistencia).
4. Si el archivo **sigue ahí**, funciona. ✅

---

## 9. Problemas comunes (FAQ)

| Síntoma | Causa / solución |
|---|---|
| "Reinicié y se borró todo" | Booteaste con "Live system" normal. Elegí la opción **(persistence)** en el menú. |
| No aparece la partición nueva | El grabador no dejó espacio libre. Regrabá la ISO en **modo DD/imagen** (Rufus DD, dd, Etcher). |
| "No toma los cambios" aunque elijo persistence | La etiqueta no es exactamente `persistence`, o el archivo no es `persistence.conf`, o su contenido no es `/ union`. Revisá los tres. |
| No sé cuál es mi USB | `sudo lsblk` — identificá por tamaño. **Nunca** uses el disco del sistema. |
| Quiero cifrarlo pero ya lo hice normal | Repetí el Método B sobre `/dev/sdb3` (se reformatea; perdés lo que hubiera). |

---

## 10. Alternativas (para saber que existen)

- **Ventoy**: gestor de arranque multi-ISO que **también** soporta persistencia (se configura distinto, con un archivo de mapeo). Cómodo si llevás varias ISOs.
- **Instalación completa** en el USB (no Live): más rápido y flexible, pero ocupa el USB entero como un disco.
- **Máquina virtual** (VirtualBox/VMware): lo más cómodo para practicar en casa; snapshots y sin riesgo para tu hardware.

---

> 📎 Guía oficial (referencia): **kali.org/docs/usb/usb-persistence**
> Material de la comunidad · dudas → al canal de soporte.

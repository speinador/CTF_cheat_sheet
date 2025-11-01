# Ayuda-Memoria de CTF para Principiantes  
_Vulnerabilidades Básicas · Herramientas · Enfoque Práctico_  
**Autor:** Sebastián Peinador  
**Versión:** 1.0  
**Fecha:** [___]

---

## Índice  
1. [Introducción](#introducción)  
2. [Flujo de trabajo / Cómo encarar un reto](#flujo-de-trabajo--cómo-encarar-un-reto)  
3. [Herramientas clave y comandos frecuentes](#herramientas-clave-y-comandos-frecuentes)  
4. [Vulnerabilidades comunes con escenarios y ejemplos](#vulnerabilidades-comunes-con-escenarios-y-ejemplos)  
5. [Tips rápidos / «¿Sabías que…?»](#tips-rápidos--¿sabías-que…)  
6. [Checklist de comprobación final](#checklist-de-comprobación-final)  
7. [Glosario de términos](#glosario-de-términos)  
8. [Referencias / recursos recomendados](#referencias--recursos-recomendados)  
9. [Plantilla de Write-Up para Alumnos](#plantilla-de-write-up-para-alumnos)  
10. [Tabla de CVE comunes y fáciles](#tabla-de-cve-comunes-y-fáciles)  
11. [Sección Avanzada: Enfoque estructurado según tipo de reto](#sección-avanzada-enfoque-estructurado-según-tipo-de-reto)  
12. [Plantillas visuales y estilo sugerido](#plantillas-visuales-y-estilo-sugerido)

---

## 1. Introducción  
En los retos de captura de banderas (CTF), nuestro objetivo es **encontrar la “flag”**, que normalmente es un texto oculto o protegido que demuestra que hemos conseguido acceso o vulnerabilidad.  
Pero más allá de “resolver el reto”, lo que realmente importa es **aprender la metodología**, entender los fallos y cómo se corrigen, de modo que podamos aplicar ese conocimiento en entornos reales de ciberseguridad.  
Este documento pretende servir como una “ayuda-memoria” para los alumnos del curso, como un compañero de bolsillo que guía cuando realizan ejercicios, laboratorios o máquinas vulnerables.  
El enfoque es **metodológico y práctico**, no únicamente “hackear por diversión”, sino aprender, documentar y enseñar.

---

## 2. Flujo de trabajo recomendado para un reto de CTF  
### Fase A – Reconocimiento / Enumeración  
- Identificar la máquina/entorno: dirección IP, puertos abiertos, servicios, sistema operativo.  
- Herramientas típicas:  
  ```
  nmap -sC -sV -oA initial <IP>
  gobuster dir -u http://<IP>/ -w /usr/share/wordlists/dirb/common.txt
  whatweb http://<IP>/
  ```  
- Crear un listado de servicios, versiones, hipótesis de funcionamiento.

### Fase B – Identificación de la vulnerabilidad  
- Con los datos del reconocimiento, pensar: ¿qué vulnerabilidad podría existir?  
- Ejemplo: servidor web versión antigua → inyección SQL, LFI/RFI; FTP anónimo → archivos sueltos.

### Fase C – Explotación  
- Aplicar la técnica adecuada: por ejemplo `sqlmap` para SQLi, `burpsuite` para manipulación web, `hydra` para fuerza bruta.  
- Documentar comandos usados, salidas, qué funcionó y qué no.

### Fase D – Post-explotación / Escalada de privilegios / Recolección de flags  
- Una vez que se tiene acceso de bajo nivel, buscar cómo escalar privilegios, moverse lateralmente, extraer información útil.  
- Verificar rutas como `/etc/passwd`, `/home/usuario/Desktop`, o en Windows `C:\Users\…`.  
- Usar herramientas de enumeración automática: `linpeas.sh`, `winPEAS.bat`, `enum4linux`.

### Fase E – Limpieza / Documentación / Reflexión  
- Documentar todos los pasos con capturas de pantalla o comandos y resultados.  
- Reflexionar: ¿qué permitió la vulnerabilidad? ¿cómo se mitigaría?  
- Guardar el write-up (por ejemplo en GitHub).  
- Limpiar: cerrar sesiones, eliminar archivos temporales si corresponde.

---

## 3. Herramientas clave y comandos frecuentes  
### 3.1 Reconocimiento / Enumeración  
**Comandos de Nmap (y variantes):**  
- `nmap <IP>` — escaneo básico.  
- `nmap -sS <IP>` — escaneo SYN (“half-open”).  
- `nmap -sT <IP>` — escaneo TCP connect.  
- `nmap -sU <IP>` — escaneo UDP.  
- `nmap -sV <IP>` — detección de versiones.  
- `nmap -O <IP>` — detección de sistema operativo.  
- `nmap -p- <IP>` — todos los puertos TCP (1-65535).  
- `nmap --top-ports 100 <IP>` — los 100 puertos más comunes.  
- `nmap -A -T4 <IP>` — escaneo agresivo.  
- `nmap -oA initial <IP>` — guardar resultados.  
- `nmap --script vuln <IP>` — ejecutar scripts de vulnerabilidad.

**Otras herramientas de enumeración:**  
- `gobuster dir -u http://<IP>/ -w /usr/share/wordlists/dirb/common.txt` — enumerar directorios web.  
- `whatweb <URL>` — identificar tecnologías web.  
- `dirsearch -u http://<IP>/ -e php,html,js` — enumeración de directorios con extensiones.  
- `enum4linux -a <IP>` — enumeración de SMB en entornos Windows/Linux.

### 3.2 Explotación  
**Para web:**  
```bash
sqlmap -u "http://<IP>/vuln.php?id=1" --batch
```  
- `burpsuite` — proxy web + manipulación de solicitudes/respuestas.  
- `hydra -l user -P rockyou.txt ftp://<IP>` — fuerza bruta contra FTP.  
- `steghide extract -sf hidden.jpg` — extraer datos de imagen (esteganografía).

**Para binarios:**  
- `file binary` — ver el tipo de binario.  
- `gdb ./binary` — iniciar GDB.  
- `ROPgadget --binary ./binary | grep "pop rdi"` — buscar gadgets para ROP chain.  
- `strings binary | grep flag` — buscar cadenas “flag” en binario.

**Para forense / archivos:**  
- `binwalk -e firmware.bin` — extraer contenido de firmware.  
- `strings image.dd | grep "flag{"` — buscar flags en imagen de disco.

### 3.3 Post-explotación / Privilege Escalation  
- `linpeas.sh` — script de Linux para enumeración post-explotación.  
- `winPEAS.bat` — script para Windows.  
- `sudo -l` — ver comandos que puede ejecutar un usuario con sudo.  
- `find / -perm -u=s -type f 2>/dev/null` — encontrar binarios con SUID en Linux.  
- `netstat -an` / `ipconfig /all` / `whoami /priv` — comandos útiles en Windows shell.  
- `hashcat -m 1000 hash.txt rockyou.txt` — crackear hash de contraseña.

---

## 4. Vulnerabilidades comunes con escenarios y ejemplos  
### 4.1 Inyección SQL (SQLi)  
- **Qué es:** cuando una entrada de usuario mal controlada permite ejecutar código SQL malicioso.  
- **Detección:** formularios de login o búsqueda, errores de base de datos, servicio MySQL/MSSQL visible.  
- **Ejemplo de explotación:**  
  ```sql
  ’ OR 1=1-- -
  ```  
  o  
  ```bash
  sqlmap -u "http://<IP>/login.php?user=admin&pass=123" --batch
  ```  
- **Mitigación:** usar consultas preparadas, sanitizar/escapar inputs, aplicar mínimo privilegio en la DB.

### 4.2 Cross-Site Scripting (XSS)  
- **Qué es:** cuando código malicioso es inyectado y ejecutado por el navegador a través de inputs no filtrados.  
- **Detección:** campos que aparecen reflejados sin escape; pruebas con `<script>alert(1)</script>`.  
- **Ejemplo de explotación:**  
  ```html
  <img src=x onerror=alert('XSS')>
  ```  
- **Mitigación:** escapar salidas, usar Content-Security Policy (CSP), validar input tanto en cliente como servidor.

### 4.3 Local/Remote File Inclusion (LFI / RFI)  
- **Qué es:** permitir que se incluyan archivos locales o remotos en la ejecución de una aplicación web.  
- **Detección:** parámetros tipo `?page=` o `?file=../../etc/passwd`; servicio web antiguo.  
- **Ejemplo de explotación:**  
  ```
  ?file=../../../../etc/passwd
  ```  
  o  
  ```
  ?file=php://filter/convert.base64-encode/resource=index.php
  ```  
- **Mitigación:** usar lista blanca de archivos permitidos, validar/sanitizar nombre del archivo, rutas absolutas seguras.

### 4.4 Escalada de Privilegios  
- **Qué es:** tras obtener acceso limitado, encontrar rutas para subir a root/administrador.  
- **Detección:** revisar `sudo -l`, buscar binarios con SUID, servicios mal configurados.  
- **Ejemplo de comandos:**  
  ```bash
  sudo -l
  find / -perm -u=s -type f 2>/dev/null
  ```  
- **Mitigación:** aplicar mínimo privilegio, revisar servicios/configuraciones, mantener sistemas actualizados.

### 4.5 Directorios o Archivos Expuestos / Credenciales por Defecto  
- **Qué es:** servicios o aplicaciones que exponen archivos sensibles o usan credenciales por defecto.  
- **Detección:** usar `gobuster dir` o `dirsearch`; Nmap detecta FTP anónimo.  
- **Ejemplo de comando de enumeración:**  
  ```bash
  gobuster dir -u http://<IP>/ -w /usr/share/wordlists/dirb/common.txt
  ```  
- **Mitigación:** deshabilitar listados de directorios, proteger backups, eliminar repositorios públicos no autorizados, cambiar credenciales por defecto.

### 4.6 Servicios Antiguos / Vulnerabilidades con CVE Públicas  
- **Qué es:** servicios desactualizados con vulnerabilidades conocidas.  
- **Detección:** Nmap detecta versión antigua del servicio; buscar CVE asociadas.  
- **Ejemplo:** escanear con Nmap luego buscar “CVE Apache 2.2.8 exploit”.  
- **Mitigación:** actualizar software, eliminar servicios obsoletos, deshabilitar protocolos inseguros como SMBv1.

### 4.7 Inyección de Comandos (Command Injection)  
- **Qué es:** cuando una aplicación acepta entradas que son enviadas al sistema sin sanitizar, permitiendo ejecución arbitraria.  
- **Detección:** campos que ejecutan comandos del sistema (`ping`, `download file`); probar `; ls /`, `| whoami`.  
- **Ejemplo de explotación:**  
  ```bash
  ; cat /etc/passwd
  ```  
- **Mitigación:** validar/sanitizar input, evitar pasar directamente a shell, usar funciones seguras.

### 4.8 Criptografía y Esteganografía  
- **Qué es:** retos que implican ocultar o cifrar datos dentro de otros archivos.  
- **Detección:** archivo “raro” (imagen, audio, binario) que acompaña el reto; revisar con `strings`, `binwalk`, `steghide`.  
- **Ejemplo de comandos:**  
  ```bash
  steghide extract -sf image.jpg
  binwalk -e firmware.bin
  strings suspect.bin | grep flag
  ```  
- **Mitigación:** en entorno real: validar lo que los usuarios suben, evitar almacenar datos sensibles sin protección.

---

## 5. Tips rápidos / «¿Sabías que…?»  
- ¿Sabías que muchos retos usan flags con formato `flag{…}` o `CTF{…}`? Esto ayuda a reconocer la señal del éxito.  
- Muchas máquinas vulnerables olvidan proteger el directorio `.git/`, permitiendo acceder al repositorio y obtener credenciales o código fuente.  
- Si tras un escaneo no encontrás nada, recuerda que también puede haber **UDP**, **puertos no estándar**, **aplicaciones web en otros puertos** distintos al 80/443.  
- Cuando se obtiene una shell en Windows, revisar `C:\Users\<usuario>\Desktop\` suele dar buenos resultados para encontrar documentos útiles.  
- Si un formulario no devuelve error pero el tiempo de respuesta cambia al enviar un inyección, puede tratarse de una inyección SQL “time-based”.  
- En Linux, si ves un binario con SUID activo y versión antigua, puede indicar una vulnerabilidad de escalación de privilegios.  
- En cualquier laboratorio: documenta **todo** — fecha/hora, IP, comandos, salidas. Esto no sólo demuestra que lo hiciste, sino que refuerza tu aprendizaje.

---

## 6. Checklist de comprobación final  
Antes de “entregar” o pasar al siguiente reto, revisá lo siguiente:  
- [ ] He identificado correctamente la IP / máquina objetivo  
- [ ] He realizado un escaneo completo de puertos y servicios  
- [ ] He anotado todas las versiones detectadas  
- [ ] He enumerado directorios web, ficheros ocultos y backups  
- [ ] He probado credenciales comunes y configuraciones por defecto  
- [ ] He identificado alguna vulnerabilidad (o al menos una hipótesis sólida)  
- [ ] He explotado la vulnerabilidad con éxito o documentado por qué falló  
- [ ] Si obtuve shell: he hecho enumeración de post-explotación  
- [ ] He documentado todos los pasos con comandos/salidas/capturas  
- [ ] He escrito lo que aprendí: qué permitió la vulnerabilidad, cómo se mitigaría  
- [ ] He revisado limpieza: cerrar sesiones, eliminar artefactos temporales  
- [ ] He guardado mi write-up o repositorio GitHub con los resultados

---

## 7. Glosario de términos  
- **Reconocimiento / Enumeration**: fase de descubrir la máquina/servicios antes de atacar.  
- **Shell**: interfaz para interactuar con el sistema (puede ser reversa o local).  
- **Privilege Escalation**: subir de acceso limitado a administrador/root.  
- **Flag**: cadena de texto que representa que se ha completado parte del reto.  
- **Payload**: código o comando malicioso usado para explotar una vulnerabilidad.  
- **Pivoting**: moverse lateralmente en una red desde un sistema comprometido hacia otro.  
- **CVE**: Identificador público de vulnerabilidad (“Common Vulnerabilities and Exposures”).  
- **WAF**: Web Application Firewall (Firewall de Aplicaciones Web).  
- **SUID**: En Linux, permiso especial que permite ejecutar un binario con los privilegios del propietario.  
- **NSE**: Nmap Scripting Engine — motor de scripts de Nmap para detección de vulnerabilidades.  
- **Esteganografía**: ocultación de datos dentro de otros datos (por ejemplo una imagen o audio).  
- **OSINT**: Inteligencia de fuente abierta (Open-Source Intelligence) — a veces aparece en retos CTF de tipo investigación.

---

## 8. Referencias / recursos recomendados  
- Repositorio “CTF CheatSheet” en GitHub — muchas técnicas comunes de CTF.  
- “Nmap Cheat Sheet (2025)” – completa referencia de Nmap.  
- “Capture-the-Flag CheatSheet” por SaiKiran Uppu — ejemplos contextuales.  
- “Ciberseguridad Web – Web Exploitation 101” (CTF101) — buena base para retos de aplicaciones web.  
- Blogs de cheat-sheets: Twin Security, Parrot CTFs, etc.

---

## 9. Plantilla de Write-Up para Alumnos  
**Título del reto / VM:**  
**IP / Identificador:**  
**Fecha de inicio / Fecha de conclusión:**  
**Versión del entorno:**  
**Objetivo (flag(s))**:

### 9.1 Reconocimiento  
- Comandos utilizados:  
  ```bash
  nmap -sC -sV -oA initial <IP>
  gobuster dir -u http://<IP>/ -w /usr/share/wordlists/dirb/common.txt
  whatweb http://<IP>/
  ```  
- Servicios & versiones detectadas:  
  | Puerto | Servicio | Versión | Observaciones |
  |--------|----------|---------|--------------|
  |        |          |         |              |

### 9.2 Identificación de la vulnerabilidad  
- Hipótesis planteada: (por ejemplo: “versión de Apache antigua → posible CVE X.YZ”)  
- Evidencias que apoyan la hipótesis: (log, captura de pantalla, salida de comando)

### 9.3 Explotación  
- Paso a paso (comandos, opciones, salidas)  
- Herramienta usada (ej: `sqlmap`, `burpsuite`, `hydra`, etc)  
- Resultado obtenido (shell, credenciales, flag)

### 9.4 Post-Explotación & Escalada  
- Usuario obtenido, niveles de privilegio  
- Comandos de enumeración utilizados:  
  ```bash
  linpeas.sh
  find / -perm -u=s -type f 2>/dev/null
  ```  
- Privilegios escalados, movimiento lateral, flags adicionales

### 9.5 Limpieza / Reflexión  
- ¿Qué permitió la vulnerabilidad?  
- ¿Cómo se podría mitigar en entorno real?  
- ¿Qué aprendí y qué haría distinto la próxima vez?  
- Documentación final: capturas de pantalla, salidas, resumen breve.

---

## 10. Tabla de CVE comunes y fáciles (nivel CTF)  
| Producto / Servicio        | Versión típica vulnerable     | Tipo de vulnerabilidad | Acción a tomar                                       |
|---------------------------|------------------------------|------------------------|----------------------------------------------------|
| Apache HTTP Server        | 2.2.x, 2.4.7                 | RCE, LFI               | Buscar exploit público, actualizar versión         |
| SMB (Windows)             | SMBv1 habilitado             | RCE, info/leak         | Revisar puertos 139/445, enumerar shares           |
| PHP + file upload         | versiones anteriores 7.x     | RCE, LFI               | Verificar directorios, extensiones permitidas      |
| MySQL / MSSQL             | versiones antiguas           | SQLi, credenciales     | Enumerar base de datos, buscar tablas/usuarios     |

---

## 11. Sección Avanzada: Enfoque estructurado según tipo de reto  
### 11.1 Web Application  
**Flujo recomendado:** Reconocimiento → Enumeración de tecnología → Directorios ocultos → Formularios/input → Pruebas de vulnerabilidad → Explotación → Shell → Escalada.  
**Comandos típicos:**  
- `dirsearch -u http://<IP>/ -e php,html,js -x 403,404`  
- `sqlmap -r request.txt --batch`  
- `burpsuite` interceptando/modificando parámetros  
**Vulnerabilidades frecuentes:** SQLi, XSS, LFI/RFI, file upload mal controlado.

### 11.2 Binario / Pwn  
**Flujo recomendado:** Descargar binario → analizar con `file`, `strings`, `gdb` → fuzzing → encontrar offset → construir exploit (ROP, buffer overflow) → obtener shell.  
**Comandos típicos:**  
- `file binary`  
- `gdb ./binary`  
- `ROPgadget --binary ./binary | grep "pop rdi"`  
**Vulnerabilidades frecuentes:** Desbordamiento de búfer, UAF (use-after-free), ROP chain, salto de memoria.

### 11.3 Forense / Esteganografía  
**Flujo recomendado:** Identificar archivo sospechoso → `strings`, `binwalk -e`, `exiftool`, `tesseract` (si imagen) → extraer datos ocultos → reconstruir.  
**Comandos típicos:**  
- `binwalk -e sample.img`  
- `tesseract image.png stdout`  
- `strings dump.bin | grep flag`  
**Vulnerabilidades frecuentes:** Datos ocultos en imágenes/audio, archivos comprimidos protegidos, fragmentos de memoria.

### 11.4 Redes / Active Directory  
**Flujo recomendado:** Escaneo de red (Nmap) → enumeración de hosts activos → SMB/LDAP/WinRM → credenciales por defecto/delegación → escalación.  
**Comandos típicos:**  
- `nmap -p 135,139,445,3389 <IP>`  
- `rpcclient -U "" <IP> -c "enumdomusers"`  
- `impacket-secretsdump -sam SAM -system SYSTEM local`  
**Vulnerabilidades frecuentes:** SMBv1 habilitado, políticas de contraseña débiles, delegación de cuentas, credenciales por defecto.

---

## 12. Plantillas visuales y estilo sugerido  
- Títulos en **color oscuro sólido** (por ejemplo: azul #003366) para coherencia visual.  
- Cuadros “¿Sabías que…?” con fondo claro (gris #f2f2f2) y borde fino para destacar.  
- Tablas con encabezado sombreado (por ejemplo fondo azul claro) y texto oscuro.  
- Comandos en fuente monoespaciada (`Courier New` o similar) y fondo ligeramente gris para diferenciarlos.  
- Íconos o símbolos pequeños (por ejemplo flechas, check-marks) para resaltar pasos del flujo.  
- Numerar las secciones y usar viñetas para mantener claridad en listas.

---

## Autor

Explicación elaborada por [Sebastian Peinador](https://www.linkedin.com/in/sebastian-j-peinador/) para propósitos didácticos y de investigación en ciberseguridad ofensiva.

---
## Licencia

Este material se distribuye bajo la licencia [MIT](LICENSE).

---

> Si te resulta útil, ¡no olvides darle ⭐ al repo o compartirlo!

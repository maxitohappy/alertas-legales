# Análisis de seguridad — Sistema de alertas legales

Un despacho de abogados maneja datos especialmente sensibles: identidad de clientes, causas penales,
estrategia procesal y documentación personal (DNI, certificados). Además está sujeto al **secreto
profesional**. Si sufre una brecha, el despacho incumple el RGPD y la LOPDGDD (multas y obligación de
notificar a la AEPD), pierde la confianza de sus clientes y puede perjudicar la defensa en sus casos.
Por eso este documento recoge los controles **implementados en el código** y los **controles
organizativos y de infraestructura** que deben aplicarse al desplegarlo.

## 1. Amenazas principales

| Amenaza | Ejemplo realista | Impacto |
|---|---|---|
| Robo de credenciales / phishing | Correo falso "del despacho" que pide la contraseña al abogado | Acceso a todos los casos |
| Fuerza bruta / *credential stuffing* | Bots que prueban contraseñas filtradas | Acceso no autorizado |
| Suplantación del despacho ante clientes | Atacante envía a un cliente un enlace falso para "subir documentos" | Robo de datos del cliente / malware |
| Subida de archivos maliciosos | Ejecutable o documento con macros disfrazado de PDF | Infección del equipo del abogado |
| Inyección (SQL, XSS) y CSRF | Formularios manipulados | Robo o alteración de datos |
| Fuga de secretos | Contraseña SMTP o clave de BD subida a GitHub (repo público) | Control total del sistema |
| Dependencias vulnerables | Librería con CVE conocida | Ejecución remota de código |
| Ransomware / pérdida de datos | Cifrado o borrado de la BD | Pérdida de plazos y expedientes |
| Interceptación | Wi-Fi pública sin TLS | Lectura de datos en tránsito |

## 2. Controles implementados en la aplicación (mapa OWASP Top 10)

| OWASP 2021 | Control | Dónde |
|---|---|---|
| A01 Control de acceso | Todas las rutas del panel exigen sesión; rol `admin` para gestionar usuarios y borrar clientes; el portal del cliente solo acepta un token válido | [app/deps.py](../app/deps.py), [app/routers/](../app/routers/) |
| A02 Fallos criptográficos | Contraseñas con **Argon2id**; documentos y secretos 2FA **cifrados en reposo** (Fernet: AES-128-CBC + HMAC-SHA256); TLS obligatorio con SMTP (STARTTLS con verificación de certificado); HSTS en producción | [app/security.py](../app/security.py), [app/storage.py](../app/storage.py), [app/mailer.py](../app/mailer.py) |
| A03 Inyección | ORM SQLAlchemy con consultas parametrizadas; Jinja2 con autoescape (XSS); validación de longitud y formato en cada campo; cabeceras de correo saneadas | todo el código |
| A04 Diseño inseguro | Enlaces de carga con token aleatorio de 256 bits, guardado **solo como hash SHA-256**, con caducidad (7 días) y **de un solo uso**; el portal no muestra datos del caso | [app/routers/client_upload.py](../app/routers/client_upload.py) |
| A05 Configuración insegura | Documentación OpenAPI deshabilitada; cabeceras CSP estricta, X-Frame-Options, nosniff, Referrer-Policy `no-referrer`, Permissions-Policy, COOP; `Cache-Control: no-store`; sin cabecera `Server`; contenedor con usuario sin privilegios | [app/main.py](../app/main.py), [Dockerfile](../Dockerfile) |
| A06 Componentes vulnerables | Versiones fijadas; **pip-audit** en cada push y semanalmente; **Dependabot**; **CodeQL** | [.github/](../.github/) |
| A07 Fallos de autenticación | **2FA TOTP obligatorio** (configuración forzada en el primer inicio); anti-replay del código; bloqueo de 15 min tras 5 fallos; *rate limiting* por IP; mensajes de error genéricos; tiempo constante aunque el usuario no exista; sesión regenerada al iniciar (anti fijación); expiración por inactividad (30 min) y máxima (8 h); cookie `HttpOnly`, `Secure`, `SameSite=Lax` | [app/routers/auth.py](../app/routers/auth.py) |
| A08 Integridad | Token **CSRF** en todos los formularios; validación de archivos por *magic bytes* + extensión; DOCX con macros o *zip bombs* rechazados; hash SHA-256 de cada documento | [app/storage.py](../app/storage.py) |
| A09 Registro y monitorización | Registro de auditoría (inicios de sesión, fallos, descargas, cambios) con IP; el proceso diario falla con código ≠ 0 y GitHub notifica por correo | [app/models.py](../app/models.py) `AuditLog` |
| A10 SSRF | La aplicación no hace peticiones a URLs proporcionadas por usuarios | — |

**Archivos subidos por clientes:** máx. 10 MB y 5 archivos por envío, solo PDF/JPG/PNG/DOCX, se
renombran con un UUID, se guardan cifrados y nunca se sirven directamente: solo un abogado autenticado
puede descargarlos y cada descarga queda auditada. Recomendación adicional: analizar con antivirus
(p. ej. ClamAV o el antivirus del almacenamiento cloud) antes de abrirlos.

## 3. Repositorio y pipeline (el repositorio es público)

- **Ningún secreto en el código.** Todo va en variables de entorno / *GitHub Secrets* / panel de Render.
  `.env` está en `.gitignore`. El correo de pruebas se lee de `DEMO_EMAIL`, no está en el código.
- **Secret scanning + push protection** activados: GitHub bloquea un push que contenga una clave.
- **CI** en cada cambio: ruff, tests, **bandit** (SAST), **pip-audit**; **CodeQL** semanal.
- Workflows con permisos mínimos (`permissions: contents: read`).
- Recomendado: proteger la rama `main` (PR obligatorio + CI en verde) y activar 2FA en la cuenta GitHub.

## 4. Infraestructura recomendada

| Área | Recomendación |
|---|---|
| Ubicación de datos | BD (Neon) y servidor (Render) en **región UE (Frankfurt)**; firmar sus DPA (contrato de encargado del tratamiento) |
| Base de datos | Conexión con `sslmode=require`; usuario con privilegios mínimos (sin superusuario); copias automáticas + **prueba de restauración trimestral** |
| Almacenamiento de documentos | Bucket S3/R2 **privado**, sin acceso público, con versionado (protege frente a ransomware) |
| Correo | Cuenta Gmail/Workspace dedicada al sistema con 2FA y **contraseña de aplicación**; configurar **SPF, DKIM y DMARC** (`p=quarantine` o `reject`) en el dominio del despacho para que nadie pueda suplantarlo ante los clientes |
| Secretos | Rotar `SECRET_KEY`, contraseña SMTP y credenciales de BD al menos una vez al año y ante cualquier sospecha. `ENCRYPTION_KEY` debe guardarse también fuera del sistema (gestor de contraseñas): si se pierde, los documentos no se pueden descifrar |
| Cuentas | 2FA en GitHub, Google, Render, Neon y el proveedor de almacenamiento |
| Varias instancias | El *rate limiting* es en memoria; si se escalan varias instancias, usar Redis |

## 5. Controles organizativos

1. **Formación anti-phishing** para el despacho, y aviso a los clientes: el sistema nunca pide
   contraseñas ni datos bancarios (ya figura en cada correo).
2. **Mínimo privilegio:** solo los administradores gestionan usuarios; dar de baja al personal que se va
   el mismo día (botón *Desactivar*).
3. **Equipos:** disco cifrado (BitLocker), sistema actualizado, antivirus, bloqueo de pantalla.
4. **Revisión periódica** del registro de auditoría y de los avisos de Dependabot/CodeQL.
5. **Plan de respuesta a incidentes:** detectar → contener (desactivar usuarios, rotar secretos) →
   evaluar → **notificar a la AEPD en un plazo de 72 h** si hay riesgo para los derechos de las
   personas (art. 33 RGPD) y a los afectados si el riesgo es alto (art. 34) → documentar.

## 6. Cumplimiento normativo (España)

- **RGPD + LOPDGDD:** base jurídica (ejecución del contrato de servicios jurídicos), registro de
  actividades de tratamiento, deber de información, **consentimiento/registro** (campo "Fecha de
  consentimiento RGPD" del cliente), derechos ARSOPL (el borrado de cliente elimina sus casos y
  documentos cifrados), minimización (los correos al cliente no incluyen datos del procedimiento).
- **Secreto profesional** (Estatuto General de la Abogacía): el cifrado en reposo, el control de
  acceso y la auditoría ayudan a demostrar la diligencia debida.
- **ENS (Esquema Nacional de Seguridad):** obligatorio solo para el sector público, pero sus medidas
  son un buen marco de referencia; este diseño cubre gran parte de las medidas de nivel básico.
- **Evaluación de impacto (EIPD):** recomendable si se tratan datos penales a gran escala (art. 35 RGPD).

## 7. Riesgos residuales conocidos

- Si un atacante obtiene la contraseña **y** el segundo factor de un abogado, accede a los casos:
  mitigar con formación y revisión de la auditoría.
- Los correos viajan cifrados hasta Gmail (TLS), pero no cifrados de extremo a extremo: por eso el
  resumen diario contiene solo lo mínimo necesario. **Decisión del despacho:** los documentos que sube
  el cliente se adjuntan al aviso interno "Documento recibido" (solo a los correos del despacho, máx.
  18 MB por correo). Es más cómodo, pero quedan copias en el buzón de Gmail: proteja esas cuentas con
  2FA, no reenvíe esos correos fuera del despacho y, si se prefiere máxima confidencialidad, desactive
  los adjuntos con `ATTACH_RECEIVED_DOCUMENTS=false` (el aviso llegará con el enlace al panel).
- El primer inicio de sesión de un usuario nuevo configura el 2FA: entregar la contraseña inicial por
  un canal distinto al correo y pedir que se cambie.

# Arquitectura 2FA (TOTP) desde cero + Observabilidad con Prefect

Laboratorio del curso **Patrones Arquitectónicos Avanzados**: prueba de concepto con 4 piezas que se sincronizan sin estar conectadas entre sí.

| # | Pieza | Carpeta | Tecnología |
|---|-------|---------|------------|
| 1 | App móvil Authenticator (funciona en modo avión) | [`/mobile-authenticator`](mobile-authenticator) | React Native + Expo (SDK 58) |
| 2 | Base de datos de usuarios | [`/supabase`](supabase) | Supabase (PostgreSQL) o SQLite local |
| 3 | Sistema de login (web app) | [`/backend-prefect/app/web`](backend-prefect/app/web) | HTML + JavaScript, servido por el backend |
| 4 | Backend Step-Up Auth instrumentado con Prefect | [`/backend-prefect`](backend-prefect) | Python, FastAPI y Prefect 3 |

```
├── mobile-authenticator/          # App propia (TOTP sin librerías TOTP)
│   ├── App.tsx                    # Lista de cuentas, escáner y entrada manual
│   ├── src/totp/                  # sha1.ts, base32.ts, totp.ts, otpauth.ts (desde cero)
│   ├── src/components/            # Tarjeta con código grande y contador 30→0, escáner QR
│   └── src/storage.ts             # Semillas en el llavero del teléfono (expo-secure-store)
├── backend-prefect/
│   ├── app/main.py                # API FastAPI (endpoints)
│   ├── app/flows.py               # @flow y @task de Prefect
│   ├── app/strategies/            # Strategy: TOTPStrategy y BackupCodeStrategy
│   ├── app/state_machine.py       # Máquina de estados del aprovisionamiento 2FA
│   ├── app/replay_cache.py        # Caché anti-replay en memoria (TTL 90 s)
│   ├── app/totp.py                # TOTP RFC 6238 desde cero (hmac + hashlib)
│   ├── app/crypto.py              # Cifrado AES-256-GCM de la semilla TOTP
│   ├── app/security.py            # Contraseñas con scrypt y JWT
│   ├── app/db.py                  # Modelos SQLAlchemy (Supabase o SQLite)
│   ├── app/web/index.html         # Web de login
│   └── tests/                     # 11 pruebas (RFC 6238, step-up, replay, cifrado)
└── supabase/schema.sql            # Tablas + consultas útiles
```

---

## 1. Flujo general y patrones

```
 Usuario web ──(1) POST /auth/login usuario+contraseña──▶ Backend ──▶ pre_auth_token (scope=mfa:verify)
                                                              │
 App móvil (modo avión) ──(2) HMAC-SHA1(secreto, ⌊t/30⌋) ──▶ código de 6 dígitos
                                                              │
 Usuario web ──(3) POST /auth/verify-2fa código + pre_auth──▶ @flow 2fa-verification-flow (Prefect)
                                                              ├─ Task 1 validate_pre_auth_state
                                                              ├─ Task 2 check_anti_replay_cache
                                                              ├─ Task 3 execute_mfa_strategy (TOTP | Backup)
                                                              └─ Task 4 issue_elevated_session ──▶ access_token (mfa_verified: true)
 Usuario web ──(4) GET /api/boveda-secreta + access_token──▶ 200 OK
```

| Patrón | Dónde | Qué hace |
|--------|-------|----------|
| **Process Manager / Máquina de estados** | `app/state_machine.py`, `app/flows.py` | `SIN_2FA → PENDING_VERIFICATION → ACTIVE`. El setup deja la 2FA en `PENDING_VERIFICATION` y solo el **primer código válido** la pasa a `ACTIVE`. Mientras esté pendiente se puede regenerar el QR, así nadie queda bloqueado si lo genera y nunca lo escanea. Las transiciones inválidas lanzan `InvalidStateTransition`. |
| **Step-Up Authentication** | `app/security.py`, `app/main.py` | `/auth/login` solo entrega un `pre_auth_token` (`typ=pre_auth`, 5 min, **un solo uso**, máx. 5 intentos fallidos). La bóveda solo acepta el `access_token` (`typ=access`, `mfa_verified=true`). |
| **Strategy** | `app/strategies/` | `SecondFactorStrategy` (ABC) con `TOTPStrategy` (ventanas C-1, C, C+1) y `BackupCodeStrategy` (códigos de un solo uso, consumo atómico). `get_strategy(method)` elige la estrategia en tiempo de ejecución. |
| **Idempotencia / Anti-Replay** | `app/replay_cache.py` | Diccionario en memoria `(user_id, código) → expira` con TTL de 90 s (3 ventanas). La marca es atómica (`add_if_absent` bajo lock), así que dos peticiones simultáneas con el mismo código no pueden pasar las dos. |

Seguridad extra: contraseñas con **scrypt** + sal, semilla TOTP **cifrada en reposo con AES-256-GCM** (llave en `.env`, ligada al `user_id`), códigos de respaldo guardados como hash SHA-256, comparaciones con `hmac.compare_digest`, tiempo constante ante usuarios inexistentes y parámetros sensibles de los flows como `SecretStr` (en la UI de Prefect aparecen como `**********`).

---

## 2. Base de datos en Supabase

1. Entra a <https://supabase.com>, pulsa **New project**, ponle un nombre, una contraseña de base de datos y una región, y créalo.
2. Abre **SQL Editor → New query**, pega el contenido de [`supabase/schema.sql`](supabase/schema.sql) y pulsa **Run**. Se crean estas tablas:
   - `users`: usuario y hash scrypt de la contraseña.
   - `mfa_config`: semilla **cifrada** (`aes256gcm$...`) y `status` (`PENDING_VERIFICATION` | `ACTIVE`).
   - `backup_codes`: hash SHA-256 del código y `used`.
3. Pulsa **Connect → pestaña Direct → Method: Session pooler** y copia la cadena de conexión. Usa el *Session pooler*: la *Direct connection* solo funciona por IPv6.
4. En el `.env` del backend cambia `postgresql://` por `postgresql+psycopg://` y pon la contraseña de la base de datos:

   ```
   DATABASE_URL=postgresql+psycopg://postgres.<ref>:<contraseña>@aws-0-<región>.pooler.supabase.com:5432/postgres
   ```

> La contraseña de la base se cambia en **Database → Settings → Reset database password**. Las *API Keys* (publishable/secret) no se usan: el backend se conecta directo a Postgres.
> Si no configuras Supabase, el backend usa SQLite local (`app.db`) y crea las tablas solo.

---

## 3. Backend + Prefect (`/backend-prefect`)

Requisitos: Python 3.11 o superior.

```bash
cd backend-prefect
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/Mac: source .venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env          # Linux/Mac: cp .env.example .env
```

Edita `.env`:

| Variable | Qué es | Cómo generarla |
|----------|--------|----------------|
| `DATABASE_URL` | Conexión a Supabase o SQLite | Ver sección 2 |
| `JWT_SECRET` | Firma de los tokens | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `TOTP_ENCRYPTION_KEY` | Llave AES-256 de las semillas TOTP | `python -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"` |
| `PREFECT_API_URL` | Servidor local de Prefect | `http://127.0.0.1:4200/api` |

> Si pierdes o cambias `TOTP_ENCRYPTION_KEY`, las semillas guardadas ya no se pueden descifrar y los usuarios deben volver a activar la 2FA.

**Terminal 1: servidor de Prefect**

```bash
prefect server start
```

Dashboard: <http://127.0.0.1:4200>

**Terminal 2: API y web** (dentro de `backend-prefect`)

```bash
cd backend-prefect
.venv\Scripts\activate
uvicorn app.main:app --reload --port 8000
```

- Web de login: <http://localhost:8000>
- Documentación interactiva: <http://localhost:8000/docs>

> Si lo corres desde la raíz del repositorio aparece `ModuleNotFoundError: No module named 'app'`.
> `--reload` solo detecta cambios en el código. Si cambias el `.env`, reinicia uvicorn.

### Endpoints

| Método | Ruta | Token | Flow de Prefect |
|--------|------|-------|-----------------|
| POST | `/auth/register` | — | — |
| POST | `/auth/login` | — | `login-flow` |
| POST | `/auth/2fa/setup` | pre_auth (`mfa:enroll`) | `2fa-provisioning-flow` (devuelve QR y semilla) |
| POST | `/auth/2fa/activate` | pre_auth (`mfa:enroll`) | `2fa-activation-flow` (`PENDING_VERIFICATION → ACTIVE`, devuelve los códigos de respaldo) |
| POST | `/auth/verify-2fa` `{code, method: "totp"\|"backup"}` | pre_auth (`mfa:verify`) | `2fa-verification-flow` (las 4 tasks de la guía) |
| GET | `/api/boveda-secreta` | access (`mfa_verified=true`) | — |

### Pruebas automáticas

```bash
python -m pytest -q
```

Las 11 pruebas cubren los vectores de RFC 6238, step-up completo, replay, uso único de los códigos de respaldo, límite de intentos, máquina de estados y el cifrado AES-256-GCM. Usan SQLite y un Prefect temporal, así que no tocan Supabase.

---

## 4. Web de login

La sirve el mismo backend en <http://localhost:8000>, así que no hay que instalar nada aparte.

Pantallas: **Credenciales** → (si la 2FA no está activa) **Generar QR → Activar 2FA** → códigos de respaldo → **Segundo factor** (TOTP o código de respaldo) → **Bóveda**. A la derecha, un panel muestra cada respuesta del backend. Incluye el botón **Demo replay**, que inicia sesión de nuevo y reenvía el último código usado.

---

## 5. App móvil (`/mobile-authenticator`) en Expo Go

### Algoritmo (implementado desde cero, sin otplib ni speakeasy)

| Paso | Archivo |
|------|---------|
| 1. Base32 → bytes K | `src/totp/base32.ts` → `decodeBase32` |
| 2. C = ⌊UnixTime / 30⌋ | `src/totp/totp.ts` → `timeCounter` |
| 3. C como 8 bytes Big-Endian | `counterToBytes` |
| 4. HMAC-SHA1(K, C) → 20 bytes | `src/totp/sha1.ts` → `hmacSha1` + `sha1` (SHA-1 propio) |
| 5. offset = hash[19] & 0x0f, 4 bytes, & 0x7f, % 1 000 000, padStart(6) | `src/totp/totp.ts` → `hotp` |

Todo se calcula en el teléfono con su reloj local, **sin red**. La app muestra el código en grande, un contador 30→0 con barra de progreso que regenera el código, el valor de C, permite escanear el QR (`otpauth://totp/...?secret=`) o pegar la semilla/URI a mano, y guarda las cuentas en el almacenamiento seguro del dispositivo (`expo-secure-store`).

### Cómo verla en Expo Go

1. En tu celular, instala **Expo Go** desde Play Store o App Store. La versión de la tienda soporta el SDK 58.
2. En el PC:

   ```bash
   cd mobile-authenticator
   npm install
   npx expo start
   ```

3. Aparece un **código QR en la terminal**:
   - **Android**: abre Expo Go → *Scan QR code*.
   - **iPhone**: abre la app **Cámara** y apunta al QR; se abre en Expo Go.
4. El celular y el PC deben estar en la **misma red Wi-Fi**. Si la red lo bloquea (redes universitarias, hotspot), usa:

   ```bash
   npx expo start --tunnel
   ```

5. Para usarla:
   - Pulsa **Escanear QR** y apunta al QR que muestra la web.
   - Sin cámara (emulador), usa **Pegar secreto** y pega la semilla Base32 que aparece debajo del QR en la web.
   - Mantén presionada una tarjeta para eliminar la cuenta.

> **Modo avión:** una vez que la app cargó en Expo Go, el JavaScript queda en memoria y el cálculo es 100 % local. Activa el modo avión y los códigos se siguen generando.
> En iPhone, si se queda cargando, activa **Ajustes → Privacidad y seguridad → Red local → Expo Go**.

---

## 6. Guion de las 4 pruebas de aceptación

Antes de empezar, arranca todo, cada comando en su propia terminal:

```bash
prefect server start
uvicorn app.main:app --reload --port 8000
npx expo start
```

Abre la web (<http://localhost:8000>) y el dashboard de Prefect (<http://127.0.0.1:4200/runs>).

1. **Paridad estándar.** Haz login en la web y pulsa **Generar QR**. Escanea el **mismo QR** con la app propia y con **Google/Microsoft Authenticator**. Los dos muestran los mismos 6 dígitos al mismo tiempo. Después escribe el código en la web y pulsa **Activar 2FA** (estado `PENDING_VERIFICATION → ACTIVE`).
2. **Modo avión.** Activa el modo avión en el celular y espera a que cambie la ventana de 30 s. Vuelve a iniciar sesión en la web, escribe el código nuevo y abre `GET /api/boveda-secreta`, que responde con `mfa_verified: true`.
3. **Anti-replay.**
   1. Pulsa **Demo replay** (hace un login nuevo y reenvía el mismo código antes de que pasen 30 s).
   2. La web muestra `409 replay_attack_detected`.
   3. En Prefect, el run `verify-2fa-totp` aparece **Failed** (rojo), exactamente en la tarea `check_anti_replay_cache`, con el log `REPLAY ATTACK: el código 12**** ya fue usado…`.
4. **Clock skew o código de respaldo.**
   - En Prefect, abre un run verde de `verify-2fa-totp`. En los logs de `execute_mfa_strategy` aparece, por ejemplo: `ventana C-1: el reloj del celular va ~30 s ATRASADO`. Para forzarlo, escribe el código justo después de que cambie la ventana.
   - O elige **Código de respaldo** con uno de los códigos `XXXX-XXXX`. Funciona una sola vez; al segundo intento falla.

---

## 7. Solución de problemas

| Problema | Solución |
|----------|----------|
| Los flows no aparecen en Prefect | Verifica que `PREFECT_API_URL=http://127.0.0.1:4200/api` esté en `.env` y que `prefect server start` esté corriendo **antes** que uvicorn. |
| `Port 4200 is already in use` | Prefect ya está corriendo en otra terminal. Abre directamente <http://127.0.0.1:4200>. |
| `failed to resolve host` al arrancar el backend | El host de `DATABASE_URL` está mal. Usa el del *Session pooler* (`aws-0-<región>.pooler.supabase.com`). |
| `Falta TOTP_ENCRYPTION_KEY en .env` | Genera la llave (sección 3) y agrégala al `.env`. |
| Código siempre inválido | Revisa la hora automática del celular y del PC. El backend acepta ±30 s (C-1, C, C+1). |
| Expo Go: "This is taking much longer than it should" | Revisa que la IP debajo del QR (`exp://...`) sea la de tu red actual, o usa `npx expo start --tunnel`. |
| Expo Go: "incompatible SDK" | Actualiza Expo Go desde la tienda. El proyecto usa el SDK 58. |
| `invalid_pre_auth_token` | El pre_auth_token dura 5 min y es de un solo uso. Vuelve a iniciar sesión. |
| `429 too_many_attempts` | Se agotaron los 5 intentos de ese pre_auth_token. Vuelve a iniciar sesión. |

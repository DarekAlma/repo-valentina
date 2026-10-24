# Laboratorio: arquitectura 2FA (TOTP) desde cero + observabilidad con Prefect

| Carpeta | Contenido |
|---|---|
| `/mobile-authenticator` | App Authenticator propia en **React Native (Expo SDK 58)**. Calcula el TOTP desde cero (SHA-1, HMAC, Base32 y truncamiento dinámico escritos a mano), sin red. |
| `/backend-prefect` | Backend **FastAPI** + **Prefect 3** + SQLAlchemy (SQLite o Supabase). Incluye la web app de login en `http://localhost:8000`. |

```
Web app ──(usuario+contraseña)──► POST /auth/login ──► pre_auth_token (solo sirve para 2FA)
App móvil (modo avión) ── HMAC-SHA1(K, floor(t/30)) ──► código de 6 dígitos
Web app ──(código + pre_auth_token)──► POST /auth/verify-2fa ──► Prefect flow ──► access_token (mfa_verified: true)
                                                                                └──► GET /api/boveda-secreta
```

## Patrones implementados

| Patrón | Dónde |
|---|---|
| **Process Manager / máquina de estados** | `app/state_machine.py`: `SIN_2FA → PENDING_VERIFICATION → ACTIVE`. Solo el primer código válido activa el 2FA (`2fa-activation-flow`). Mientras siga en `PENDING_VERIFICATION` el usuario puede regenerar el QR y no queda bloqueado. |
| **Step-Up Authentication** | `POST /auth/login` entrega un `pre_auth_token` (`typ: pre_auth`, scope `mfa:verify` o `mfa:enroll`, 5 min, un solo uso) que la bóveda rechaza. `POST /auth/verify-2fa` entrega el `access_token` con `mfa_verified: true`. |
| **Strategy** | `app/strategies/`: `SecondFactorStrategy` con `TOTPStrategy` (ventanas C-1, C, C+1) y `BackupCodeStrategy` (8 códigos de un solo uso, guardados como hash y canjeados con un `UPDATE` atómico). |
| **Anti-replay / idempotencia** | `app/replay_cache.py`: `(user_id, código)` se recuerda 90 s. `check_anti_replay_cache` lo consulta y `issue_elevated_session` lo registra de forma atómica, así dos peticiones simultáneas no pueden usar el mismo código. |

Extras de seguridad: contraseñas con scrypt, límite de 5 intentos fallidos por `pre_auth_token`, comparación en tiempo constante, y contraseña y tokens enviados a Prefect como `SecretStr` (en la UI se ven como `**********`).

## Flows en Prefect

| Flow | Tasks |
|---|---|
| `login-flow` | `authenticate_credentials` → `issue_pre_auth_token` |
| `2fa-provisioning-flow` | `validate_pre_auth_state` → `create_pending_2fa_config` → `build_provisioning_uri` |
| `2fa-activation-flow` | `validate_pre_auth_state` → `check_anti_replay_cache` → `verify_first_totp_code` → `activate_2fa_config` |
| `2fa-verification-flow` | `validate_pre_auth_state` → `check_anti_replay_cache` → `execute_mfa_strategy` → `issue_elevated_session` |

---

## Cómo levantarlo (Windows / PowerShell)

Requisitos: Python 3.11+, Node 20+, y **Expo Go** en el celular (Play Store / App Store).

### 1. Servidor de Prefect (terminal 1)

```powershell
cd backend-prefect
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
prefect server start
```

Dashboard: http://127.0.0.1:4200

### 2. Backend + web app (terminal 2)

```powershell
cd backend-prefect
.\.venv\Scripts\Activate.ps1
copy .env.example .env      # y pon un JWT_SECRET
uvicorn app.main:app --reload --port 8000
```

- Web app: http://localhost:8000
- Swagger: http://localhost:8000/docs

> Para usar **Supabase** en lugar de SQLite cambia `DATABASE_URL` en `.env` por la connection string de Postgres de tu proyecto (formato en `.env.example`). Las tablas se crean solas al arrancar.

### 3. App móvil en tu celular (terminal 3)

```powershell
cd mobile-authenticator
npm install
npx expo start
```

Escanea el QR de la terminal con la cámara (iOS) o con Expo Go (Android). El PC y el celular deben estar en la misma red Wi-Fi. Si no conecta, usa `npx expo start --tunnel`.

Cuando la app ya cargó, puedes activar el **modo avión**: el cálculo TOTP es 100 % local. Para tener una app instalable que no dependa de Metro, genera un APK con EAS: `npx eas-cli@latest build:configure` y después `npx eas-cli@latest build -p android --profile preview` (en `eas.json`, el perfil `preview` debe tener `"android": { "buildType": "apk" }`).

> El reloj del celular debe estar en **hora automática**: TOTP depende de la hora exacta.

### Tests

```powershell
cd backend-prefect
.\.venv\Scripts\python.exe -m pytest -q
```

Verifican los vectores oficiales de RFC 6238, el flujo step-up completo, el replay, el uso único de los códigos de respaldo, el límite de intentos y la máquina de estados.

---

## Guion de la demo (pruebas de aceptación)

1. **Registro y activación**: en la web registra un usuario e inicia sesión. Pulsa *Generar QR*. Prefect muestra el estado en `PENDING_VERIFICATION`.
2. **Paridad estándar**: escanea el mismo QR con esta app **y** con Google/Microsoft Authenticator; ambas muestran los mismos 6 dígitos. Escribe el código en la web → `ACTIVE` y se muestran los códigos de respaldo.
3. **Modo avión**: activa el modo avión, espera a que cambie la ventana de 30 s, vuelve a iniciar sesión en la web, escribe el código nuevo y abre `GET /api/boveda-secreta`.
4. **Anti-replay**: pulsa *Demo replay: reenviar el mismo código* (hace un login nuevo y reenvía el código recién usado). Respuesta `409 replay_attack_detected`, y en Prefect el flow `verify-2fa-totp` aparece **Failed** en `check_anti_replay_cache`.
5. **Desfase de reloj / respaldo**: en los logs de `execute_mfa_strategy` se ve `ventana C-1 / C / C+1` con la interpretación (reloj atrasado o adelantado). O elige *Código de respaldo* e inicia sesión con uno de los códigos de emergencia (`BackupCodeStrategy`).

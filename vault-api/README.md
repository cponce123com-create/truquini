# vault-api — Backend para Bóveda de Credenciales

API que persiste un blob cifrado (AES-256-GCM) generado por la app frontend
de bóveda de credenciales. El servidor **nunca** ve, almacena ni loguea la
contraseña maestra de cifrado — solo maneja ciphertext opaco.

## Stack

- Node.js + Express 5
- Drizzle ORM + Neon Postgres (serverless) o SQLite local
- bcrypt (login), jsonwebtoken (sesiones vía cookie httpOnly)
- Render (free tier) para deploy

## Frontend canónico

El frontend activo está en `vault-api/public/` y se sirve desde la misma API
en `/`. Las carpetas `html5/` y `Otros/` de la raíz son versiones anteriores
y **no** reciben los cambios de seguridad de esta fase; no las uses para
desplegar.

## Estructura

```
vault-api/
├── public/                  # Frontend activo (HTML/CSS/JS + d3)
├── src/
│   ├── db/
│   │   ├── schema.ts        # Drizzle schema: users + vault_blobs
│   │   └── index.ts         # Conexión Neon / SQLite
│   ├── middleware/
│   │   ├── auth.ts          # Verificación de JWT desde cookie
│   │   └── rateLimit.ts     # Rate limiting para login
│   ├── routes/
│   │   ├── auth.ts          # /api/auth/*
│   │   └── vault.ts         # /api/vault/*
│   ├── tests/
│   └── index.ts             # App Express principal
├── drizzle.config.ts
├── package.json
├── tsconfig.json
├── .env.example
└── README.md
```

## Variables de entorno

| Variable | Descripción |
|---|---|
| `NODE_ENV` | `development` en local, `production` en Render |
| `DB_TYPE` | `sqlite` para desarrollo local, `neon` para producción |
| `DATABASE_URL` | Connection string de Neon Postgres (solo con `DB_TYPE=neon`) |
| `JWT_SECRET` | Secreto largo y aleatorio para firmar JWTs (mínimo 64 bytes recomendado) |
| `FRONTEND_ORIGIN` | Origen permitido por CORS. Si la API sirve `public/`, usa el mismo origen |
| `ALLOW_REGISTRATION` | `false` por defecto. `true` solo para crear el usuario inicial |
| `TRUST_PROXY` | Número de proxies de confianza delante de la API (`1` en Render, `false` sin proxy) |
| `PORT` | Puerto del servidor (Render asigna automáticamente) |

## Setup local

```bash
cd vault-api
cp .env.example .env
# Editar .env con los valores reales
npm install
npm run db:push    # Crea/actualiza las tablas (paso manual, una vez)
npm run dev        # Arranca en modo desarrollo (tsx watch)
```

`npm run db:push` ya no forma parte de `build` ni de `start`. Se ejecuta a
mano cuando cambia el esquema, para evitar que un `--force` accidental
modifique datos en producción durante un deploy.

## Deploy en Render + Neon

### 1. Crear base de datos en Neon (free tier)

1. Ir a [neon.tech](https://neon.tech) → New Project
2. Elegir región cercana a Render (ej: Oregon/us-west)
3. Copiar el **connection string** (formato `postgresql://...`)

### 2. Crear el Web Service en Render

1. Ir a [render.com](https://render.com) → New → Web Service
2. Conectar este repositorio
3. Configurar:
   - **Root Directory**: `vault-api`
   - **Runtime**: Node
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm start`
   - **Plan**: Free

4. Agregar las variables de entorno:
   - `NODE_ENV` → `production`
   - `DB_TYPE` → `neon`
   - `DATABASE_URL` → el connection string de Neon
   - `JWT_SECRET` → generar uno largo: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`
   - `FRONTEND_ORIGIN` → el origen público de la app (si la API sirve `public/`, es el mismo `https://tu-app.onrender.com`)
   - `TRUST_PROXY` → `1`
   - `ALLOW_REGISTRATION` → `false` (se cambia temporalmente a `true` en el paso 4)
   - `PORT` → `3000` (Render lo sobreescribe automáticamente)

5. Hacer deploy.

### 3. Crear tablas en Neon

Desde tu máquina local, con el `.env` apuntando a Neon:

```bash
npm run db:push
```

Este paso es manual. No lo agregues al build de Render: `drizzle-kit push`
puede modificar el esquema y no debe ejecutarse en cada deploy.

> **Fase 2:** el esquema añade la columna nullable `kdf` en `vault_blobs`.
> Ejecuta `npm run db:push` antes de desplegar el frontend nuevo. Las filas
> existentes quedan con `kdf = NULL` y se interpretan como PBKDF2 legado
> (310.000 iteraciones); se migran automáticamente al desbloquear.

### 4. Registrar el único usuario

Cambia temporalmente `ALLOW_REGISTRATION` a `true` y crea tu usuario:

```bash
curl -X POST https://tu-backend.onrender.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"carlos","password":"tu-contraseña-de-login"}'
```

La contraseña de login debe tener máximo 72 bytes (límite de bcrypt). Después
vuelve a poner `ALLOW_REGISTRATION=false` y haz redeploy.

### 5. Probar endpoints

```bash
# Login (guarda la cookie en un archivo)
curl -X POST https://tu-backend.onrender.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"carlos","password":"tu-contraseña-de-login"}' \
  -c cookies.txt -v

# Verificar sesión
curl https://tu-backend.onrender.com/api/auth/me -b cookies.txt

# Guardar bóveda (cifrada — el frontend genera estos valores)
# baseVersion 0 = crear; luego usa la version que devolvió el GET/PUT anterior.
curl -X PUT https://tu-backend.onrender.com/api/vault \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "salt":"...base64...",
    "iv":"...base64...",
    "data":"...base64...",
    "kdf":"{\"version\":2,\"name\":\"PBKDF2\",\"hash\":\"SHA-256\",\"iterations\":600000}",
    "baseVersion":0
  }'

# Obtener bóveda
curl https://tu-backend.onrender.com/api/vault -b cookies.txt

# Logout
curl -X POST https://tu-backend.onrender.com/api/auth/logout -b cookies.txt
```

## Endpoints

### Auth

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/auth/register` | Crear usuario (requiere `ALLOW_REGISTRATION=true`) |
| POST | `/api/auth/login` | Login, setea cookie `token` httpOnly |
| POST | `/api/auth/logout` | Limpia la cookie |
| GET | `/api/auth/me` | Retorna `{ username }` del usuario autenticado |

### Vault (requieren autenticación)

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/vault` | Retorna `{ salt, iv, data, kdf, version, updatedAt }` o 404 |
| PUT | `/api/vault` | Crea/actualiza el blob y retorna `{ version, updatedAt }` |

El `PUT` es un **upsert atómico con control optimista**:

- `baseVersion` es obligatorio y debe ser la `version` que el cliente leyó.
  Para crear una bóveda nueva se envía `0`.
- La escritura solo ocurre si `baseVersion` coincide con la versión actual.
  Si otra pestaña/dispositivo guardó antes, responde **409** con
  `{ error, version, updatedAt }` y **no modifica** el blob.
- `kdf` es metadata pública opaca para el servidor (algoritmo, hash e
  iteraciones). Es `NULL` en filas antiguas, que se tratan como PBKDF2 legado.
- El servidor incrementa `version` y actualiza `updatedAt` en la misma
  sentencia, incluso si dos peticiones llegan casi a la vez.

### Health

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/health` | `{ status: "ok" }` |

### Frontend (Fase 2)

- **Auto-bloqueo:** tras 15 minutos sin actividad se bloquea la bóveda. Si hay
  autosaves pendientes, espera a que termine la cola antes de limpiar el
  estado. Los timers retrasados en background se compensan al recuperar
  `focus`/visibilidad.
- **Conflictos:** si dos pestañas/dispositivos guardan a la vez, el segundo
  recibe 409. El cliente conserva su copia local, bloquea más guardados y
  ofrece descargarla en `.vault` o recargar la versión del servidor. No hay
  sobrescritura silenciosa.

## Seguridad

- La contraseña maestra del frontend debe tener al menos 12 caracteres y se
  limpia del DOM al desbloquear. No se envía al servidor.
- KDF versionado: las bóvedas nuevas usan PBKDF2-HMAC-SHA256 con **600.000**
  iteraciones; las antiguas (310.000) se abren con sus parámetros guardados y
  se migran a 600.000 en el siguiente desbloqueo. El cliente valida que las
  iteraciones estén entre 100.000 y 2.000.000 para evitar un DoS desde un blob
  manipulado.
- Las contraseñas de login se hashean con bcrypt (cost factor 12) y se
  limitan a 72 bytes. Los usuarios inexistentes también ejecutan una
  comparación dummy para reducir diferencias de tiempo.
- El JWT viaja en cookie `httpOnly`, `secure` (en prod), `sameSite=strict`.
  La verificación y la rotación están restringidas a `HS256`.
- Rate limiting en login: 10 intentos por IP cada 15 minutos. `TRUST_PROXY`
  debe configurarse para que la IP sea la del cliente y no la del proxy.
- CORS solo acepta el `FRONTEND_ORIGIN` configurado.
- Helmet.js para cabeceras HTTP de seguridad.
- Las respuestas de `/api` y `index.html` llevan `Cache-Control: no-store`.
- El servidor **nunca** loguea los cuerpos de las requests a `/api/vault`.
- El servidor **nunca** recibe ni conoce la contraseña maestra de cifrado.

> Si sirves el frontend desde un dominio distinto al de la API, la cookie
> `sameSite=strict` no se enviará. Para este proyecto se recomienda servir
> `vault-api/public` desde la misma API/origen.

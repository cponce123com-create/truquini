# vault-api — Backend para Bóveda de Credenciales

API que persiste un blob cifrado (AES-256-GCM) generado por la app frontend
de bóveda de credenciales. El servidor **nunca** ve, almacena ni loguea la
contraseña maestra de cifrado — solo maneja ciphertext opaco.

## Stack

- Node.js + Express 5
- Drizzle ORM + Neon Postgres (serverless)
- bcrypt (login), jsonwebtoken (sesiones vía cookie httpOnly)
- Render (free tier) para deploy

## Estructura

```
vault-api/
├── src/
│   ├── db/
│   │   ├── schema.ts       # Drizzle schema: users + vault_blobs
│   │   └── index.ts         # Conexión Neon
│   ├── middleware/
│   │   ├── auth.ts          # Verificación de JWT desde cookie
│   │   └── rateLimit.ts     # Rate limiting para login
│   ├── routes/
│   │   ├── auth.ts          # /api/auth/*
│   │   └── vault.ts         # /api/vault/*
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
| `DATABASE_URL` | Connection string de Neon Postgres |
| `JWT_SECRET` | Secreto largo y aleatorio para firmar JWTs |
| `FRONTEND_ORIGIN` | URL del frontend (CORS), ej: `https://tu-app.onrender.com` |
| `ALLOW_REGISTRATION` | `true` para permitir nuevos registros, `false` para bloquear |
| `PORT` | Puerto del servidor (Render asigna automáticamente) |

## Setup local

```bash
cd vault-api
cp .env.example .env
# Editar .env con los valores reales
npm install
npm run db:push    # Crea las tablas en Neon
npm run dev        # Arranca en modo desarrollo (tsx watch)
```

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
   - `DATABASE_URL` → el connection string de Neon
   - `JWT_SECRET` → generar uno largo: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`
   - `FRONTEND_ORIGIN` → `https://tu-frontend.onrender.com`
   - `ALLOW_REGISTRATION` → `true`
   - `PORT` → `3000` (Render lo sobreescribe automáticamente)

5. Hacer deploy.

### 3. Crear tablas en Neon

Desde tu máquina local (con el `.env` apuntando a Neon):

```bash
npx drizzle-kit push
```

O también puedes ejecutar este comando como parte del build en Render.

### 4. Registrar el único usuario

Una vez deployado, crear tu usuario:

```bash
curl -X POST https://tu-backend.onrender.com/api/auth/register 
  -H "Content-Type: application/json" 
  -d '{"username":"carlos","password":"tu-contraseña-de-login"}'
```

Luego, en Render Dashboard, cambiar `ALLOW_REGISTRATION` a `false` y hacer redeploy.

### 5. Probar endpoints

```bash
# Login (guarda la cookie en un archivo)
curl -X POST https://tu-backend.onrender.com/api/auth/login 
  -H "Content-Type: application/json" 
  -d '{"username":"carlos","password":"tu-contraseña-de-login"}' 
  -c cookies.txt -v

# Verificar sesión
curl https://tu-backend.onrender.com/api/auth/me -b cookies.txt

# Guardar bóveda (cifrada — el frontend genera estos valores)
curl -X PUT https://tu-backend.onrender.com/api/vault 
  -H "Content-Type: application/json" 
  -b cookies.txt 
  -d '{"salt":"...base64...","iv":"...base64...","data":"...base64..."}'

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
| GET | `/api/vault` | Retorna `{ salt, iv, data, version, updatedAt }` o 404 |
| PUT | `/api/vault` | Crea/actualiza el blob `{ salt, iv, data }` |

### Health

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/health` | `{ status: "ok" }` |

## Seguridad

- Las contraseñas de login se hashean con bcrypt (cost factor 12).
- El JWT viaja en cookie `httpOnly`, `secure` (en prod), `sameSite=strict`.
- Rate limiting en login: 10 intentos por IP cada 15 minutos.
- CORS solo acepta el `FRONTEND_ORIGIN` configurado.
- Helmet.js para cabeceras HTTP de seguridad.
- El servidor **nunca** loguea los cuerpos de las requests a `/api/vault`.
- El servidor **nunca** recibe ni conoce la contraseña maestra de cifrado.

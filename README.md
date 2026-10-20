# truquini

Bóveda de credenciales cifrada en el navegador (AES-256-GCM). El servidor solo
guarda un blob cifrado y nunca recibe la contraseña maestra.

## Estructura

- `vault-api/` — API Express + frontend canónico en `vault-api/public/`.
- `html5/` y `Otros/` — versiones anteriores. No están parcheadas con los
  cambios de seguridad de las Fases 1 y 2; no las uses para desplegar.

## Desarrollo

```bash
cd vault-api
cp .env.example .env
npm install
npm run db:push    # paso manual, cuando cambie el esquema
npm run dev
```

La app queda disponible en `http://localhost:3000`. Para producción, consulta
`vault-api/README.md`.

## Fases 1 y 2

Los cambios aplicados están documentados en [CAMBIOS.md](CAMBIOS.md):

- **Fase 1:** contraseña maestra, limpieza al bloquear, autosave serializado,
  XSS, upsert con versión y `trust proxy`.
- **Fase 2:** auto-bloqueo tras 15 minutos de inactividad, KDF versionado con
  migración de bóvedas antiguas y resolución de conflictos por `version`
  (respuesta 409 sin sobrescribir).

La Fase 2 añade la columna `kdf` a `vault_blobs`. Ejecuta `npm run db:push`
antes de desplegar el frontend nuevo; es un paso manual.

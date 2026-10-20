# CAMBIOS — Fases 1 y 2 de seguridad

Trabajo realizado sobre una **copia local** de `truquini`. La app local “Mis
tareas” no se modificó. El frontend canónico es `vault-api/public/`; `html5/` y
`Otros/` quedaron intactos.

---

# Fase 1

## 1. Contraseña maestra

- Mínimo **12 caracteres** y máximo 256 en la creación de la bóveda (antes 6).
- El campo de contraseña y su confirmación se vacían al entrar a la app: la
  contraseña no queda en el DOM después de derivar la clave.
- `maxlength` y `autocomplete="off"` en los campos maestros.
- El login del servidor limita la contraseña a **72 bytes** (límite real de
  bcrypt) y responde con un error claro.

## 2. Bloqueo y limpieza de estado

- `lockVault()` ahora:
  - espera a que termine la cola de guardados pendientes antes de bloquear;
  - cierra y elimina **todos** los modales (incluidos los que están fuera de
    `#app-screen`);
  - vacía tarjetas, estadísticas, categorías, pendientes, recomendaciones,
    leyenda y grafos;
  - limpia la búsqueda y el filtro de categorías;
  - borra `MASTER_KEY`, `MASTER_SALT`, `SERVER_BLOB`, `pendingFileObj` y `VAULT`;
  - vacía los inputs de contraseña y la contraseña de login.
- Se evita que una petición de autosave vieja se ejecute después de bloquear y
  sobrescriba una bóveda nueva: el bloqueo espera la cola y las tareas nuevas
  se rechazan mientras `isLocking` está activo.
- Se corrigió el botón **Desbloquear**: tenía la clase `hidden` además de
  `display:none`, por lo que no aparecía al abrir una bóveda existente.

## 3. Autosave y guardado

- Todos los guardados pasan por una **cola serializada** (`saveChain`): una
  respuesta lenta no puede sobrescribir un estado más nuevo.
- Cada autosave captura un snapshot de `VAULT` antes de encolarse.
- Indicador de estado visible: “Guardando…”, “Sincronizado”, “Sin guardar”,
  “Bloqueado”.
- Las peticiones tienen timeout de 15 s mediante `AbortController`.
- `beforeunload` avisa si hay guardados pendientes o fallidos.
- “Guardar” y “Exportar .vault” usan la misma cola y el mismo `syncVault`.

## 4. XSS y validación del frontend

- Todos los IDs que se insertan en atributos HTML se escapan con `escapeHtml`.
- Los colores de categoría se validan con `safeColor` (`#rrggbb`).
- Los campos de credenciales generados dinámicamente llevan
  `autocomplete="off"`.
- La URL del servidor debe ser un origen HTTPS; se permite HTTP solo para
  `localhost`/`127.0.0.1`/`[::1]`, y se rechazan rutas, credenciales y query.
- `bufToB64` procesa el ciphertext por trozos para evitar el desbordamiento de
  pila con bóvedas grandes.
- `uid()` tiene fallback si `crypto.randomUUID` no existe.

## 5. Backend

- `PUT /api/vault` es un **upsert atómico** con `onConflictDoUpdate`.
- Errores internos se registran sin stack en la respuesta al cliente.
- Login: máximo 72 bytes de contraseña y comparación dummy para usuarios
  inexistentes.
- JWT: verificación y rotación restringidas a `HS256`.
- `trust proxy` configurable con `TRUST_PROXY` (por defecto `1`).
- `Cache-Control: no-store` para `/api` e `index.html`.
- El registro sigue deshabilitado por defecto (`ALLOW_REGISTRATION=false`).

## 6. Build y despliegue

- `npm run build` ahora es solo `tsc`.
- `npm start` ahora es solo `node dist/index.js`.
- Se eliminó `drizzle-kit push --force` de `build`/`start`.
- La creación/actualización del esquema es un paso manual:
  `npm run db:push`.
- `package.json` declara Node `>=20.0.0`.

---

# Fase 2

## 7. Auto-bloqueo por inactividad

- La bóveda se bloquea automáticamente tras **15 minutos** sin actividad
  (`AUTO_LOCK_MS` en `public/boveda.js`).
- La actividad se mide con `pointerdown`, `keydown`, `touchstart`, `wheel`,
  `mousemove` y scroll; los eventos de alta frecuencia se limitan a uno por
  segundo para no reiniciar el temporizador cientos de veces.
- `visibilitychange` y `focus` comprueban el tiempo transcurrido al volver a
  la pestaña. Esto cubre el caso en que el navegador retrasa temporizadores en
  segundo plano.
- Antes de limpiar el estado, el auto-bloqueo **espera la cola de guardados**
  igual que el bloqueo manual. Así no se pierde un autosave en curso.
- El bloqueo elimina también el modal de conflicto y deja la pantalla de
  login; `MASTER_KEY`, `MASTER_SALT`, `MASTER_KDF`, `SERVER_BLOB`, `VAULT` y
  los inputs maestros quedan limpios.
- No se bloquea inmediatamente en `pagehide`: se prefiere dejar terminar el
  autosave.
- El botón **Bloquear** muestra en su tooltip que el bloqueo automático es de
  15 minutos.

## 8. KDF versionado y migración

- Se añadió la columna nullable `kdf` a `vault_blobs` en SQLite y Postgres.
  `NULL` significa **PBKDF2 legado** (310.000 iteraciones, versión 1).
- Las bóvedas nuevas usan **PBKDF2-HMAC-SHA256 con 600.000 iteraciones**
  (versión 2) y guardan la metadata como JSON público:
  `{"version":2,"name":"PBKDF2","hash":"SHA-256","iterations":600000}`.
- La metadata se guarda junto al blob (`salt`, `iv`, `data`) y **no contiene**
  la contraseña ni la clave. El servidor la trata como un string opaco.
- `parseKdf()` valida nombre, hash, versión e iteraciones. El rango permitido
  es 100.000–2.000.000 para evitar que un blob manipulado fuerce un KDF
  costoso y bloquee el navegador.
- Las bóvedas antiguas (sin `kdf`) se abren con 310.000 iteraciones. Al
  desbloquearlas se derivan de nuevo la clave y una sal nueva con el KDF
  actual, y el siguiente autosave/export guarda la versión migrada. Si el
  guardado falla, el blob viejo sigue siendo válido para reintentar.
- Los archivos `.vault` exportados incluyen `kdf` y `v` (versión del KDF).
- **Migración de base de datos:** ejecutar `npm run db:push` antes de
  desplegar este frontend. No se ejecuta automáticamente en `build`/`start`.

## 9. Conflictos entre pestañas/dispositivos

- `PUT /api/vault` ahora exige `baseVersion` (entero >= 0). `0` significa
  “no hay blob todavía”.
- El upsert usa `WHERE version = baseVersion` en el `DO UPDATE`: la escritura
  es atómica y solo se aplica si el cliente sigue viendo la versión actual.
- Si otra pestaña/dispositivo guardó antes, el servidor responde **409** con
  `{ error, version, updatedAt }` y **no sobrescribe** el blob.
- El cliente:
  - guarda la versión del servidor en `SERVER_BLOB.version`;
  - envía `baseVersion` en cada `syncVault`;
  - al recibir 409, bloquea autosaves y guardados manuales para no repetir la
    escritura;
  - muestra un modal con “Descargar mi copia”, “Recargar del servidor” y
    “Seguir sin guardar”;
  - permite exportar la copia local aunque el guardado esté bloqueado;
  - mantiene el aviso de `beforeunload` mientras hay un conflicto sin resolver.
- “Recargar del servidor” pide confirmación y descarta explícitamente los
  cambios locales; no hay merge automático.
- Un cliente antiguo que no envíe `baseVersion` recibe 400 y debe recargar la
  página para usar el frontend nuevo.

## 10. Tests y validación

| Prueba | Resultado |
|---|---|
| `node --check public/boveda.js` | OK |
| `tsc` / `npm run build` | OK |
| `npm test` | 19/19 tests OK |
| Smoke test E2E con SQLite y navegador | OK |

El smoke test de Fase 2 comprobó:

- creación de una bóveda nueva: primer `PUT` en versión 1 con
  `kdf.version = 2` y 600.000 iteraciones;
- recarga, login y desbloqueo de una bóveda v2;
- creación de un blob legado (sin `kdf`, 310.000 iteraciones) y migración
  automática al desbloquear: versión 2 → 3 y `kdf.version = 2`;
- auto-bloqueo forzando el reloj de inactividad: la app queda en login,
  `MASTER_KEY`/`MASTER_KDF` son `null` y el temporizador se cancela;
- simulación de otro dispositivo: guardado externo versión 3 → 4, guardado
  local con base 3, respuesta 409, modal visible y versión del servidor sin
  cambios;
- “Guardar” con conflicto reabre el modal y no escribe;
- consola sin errores propios; solo aparece el 409 esperado.
- `vitest` excluye `dist/` para no ejecutar tests compilados por accidente.

---

## Limitaciones y siguientes pasos

- `html5/` y `Otros/` son copias antiguas y **no** se parchearon.
- El auto-bloqueo es fijo en 15 minutos y no tiene configuración visual.
  Los navegadores pueden retrasar timers en background; la comprobación al
  recuperar `focus`/visibilidad cubre ese caso.
- El conflicto no se resuelve con merge automático ni con un botón de
  “sobrescribir”: hay que exportar la copia local y recargar, o descargar y
  fusionar manualmente.
- `better-sqlite3` sigue como dependencia de producción; podría pasar a
  `optionalDependencies` para facilitar el deploy.
- No se hizo commit/push: no hay git instalado ni credenciales de GitHub en
  este entorno. La entrega es la carpeta/zip local.

# Sistema experto para la identificación y diagnóstico de riesgos de seguridad informática

Aplicación web que expone un sistema experto como servicio en la nube (Cloudflare Workers + Cloudflare D1).
El conocimiento (preguntas, fallas y reglas IF / AND / OR / THEN) vive en una base de datos SQL, separado del
motor de inferencia, y la aplicación registra y gestiona los casos diagnosticados.

## Arquitectura

```
Navegador ──► Cloudflare Worker (worker.js) ──► Cloudflare D1 (SQL)
              · interfaz web                    · base de conocimiento
              · API REST                        · casos diagnosticados
              · motor de inferencia
```

- **Motor de inferencia:** evalúa las reglas con lógica de tres valores (sí / no / desconocido) y decide cuál es la
  siguiente pregunta según las respuestas previas, siguiendo el árbol de decisión (29 preguntas, 29 fallas).
- **Explicación:** cada diagnóstico muestra las respuestas que activaron la regla.
- **Post-reglas:** según la categoría de la falla se activan protocolos (Seguridad) o se deriva a soporte (Operativa).

## Modelo de datos (D1 / SQLite)

| Tabla | Contenido |
|---|---|
| `preguntas`, `opciones` | Nodos del árbol (N-01 a N-29) y opciones de la pregunta raíz |
| `fallas` | F-01 a F-29 con categoría y recomendación |
| `reglas`, `regla_condiciones` | Reglas R-01 a R-29; condiciones `all` (AND) y `any` (OR, con grupos AND) |
| `post_reglas` | Acciones automáticas por categoría |
| `diagnosticos`, `diagnostico_respuestas` | Casos guardados, su estado y las respuestas dadas |

El script completo (tablas + datos iniciales) está en `database.sql`.

## Procesos transaccionales

- **Guardar un caso:** el diagnóstico y todas sus respuestas se insertan en una sola transacción (`DB.batch`).
- **Historial:** consulta con filtros por categoría y estado, y estadísticas.
- **Seguimiento:** cambiar el estado (abierto / en atención / cerrado), agregar notas, eliminar casos.
- **Administración de la base de conocimiento:** crear, editar y eliminar fallas, preguntas y reglas, con validaciones
  (cada diagnóstico debe depender de al menos 2 preguntas; no se borra lo que otra regla usa).

Las operaciones de modificación requieren el token de administrador (`ADMIN_TOKEN`).

## API

| Método y ruta | Descripción |
|---|---|
| `POST /api/diagnose` | Recibe `{answers}` y devuelve la siguiente pregunta o el diagnóstico |
| `POST /api/diagnoses` | Guarda un caso |
| `GET /api/diagnoses`, `GET /api/diagnoses/:id` | Historial y detalle |
| `PATCH /api/diagnoses/:id`, `DELETE /api/diagnoses/:id` | Seguimiento (admin) |
| `GET /api/stats`, `GET /api/info`, `GET /api/kb` | Estadísticas, resumen y base de conocimiento |
| `POST / PUT / DELETE /api/fallas`, `/api/preguntas`, `/api/reglas` | Administración (admin) |

## Despliegue desde el dashboard de Cloudflare

1. **Storage & Databases → D1 SQL database → Create**, nombre `se-seguridad`.
2. En la pestaña **Console** de la base, pega el contenido de `database.sql` y ejecútalo.
3. En el Worker: **Settings → Bindings → Add → D1 database**, variable `DB`, base `se-seguridad`.
4. **Settings → Variables and Secrets → Add**, tipo *Secret*, nombre `ADMIN_TOKEN` y una clave larga.
5. **Edit code**: pega `worker.js` y pulsa **Deploy**.

## Despliegue con la CLI (opcional)

```bash
npx wrangler d1 create se-seguridad          # copia el database_id en wrangler.jsonc
npx wrangler d1 execute se-seguridad --remote --file=database.sql
npx wrangler secret put ADMIN_TOKEN
npx wrangler deploy
```

## Archivos

- `worker.js`: Worker (API, motor de inferencia e interfaz web).
- `database.sql`: esquema y datos iniciales de D1.
- `rules.json`: base de conocimiento original en JSON (fuente de `database.sql`).
- `wrangler.jsonc`: configuración para la CLI.

-- =====================================================================
-- Sistema experto: diagnóstico de riesgos de seguridad informática
-- Base de datos en Cloudflare D1 (SQLite). Ejecutar completo en la consola de D1.
-- =====================================================================

-- Limpieza (orden inverso a las dependencias)
DROP TABLE IF EXISTS diagnostico_respuestas;
DROP TABLE IF EXISTS diagnosticos;
DROP TABLE IF EXISTS regla_condiciones;
DROP TABLE IF EXISTS reglas;
DROP TABLE IF EXISTS post_reglas;
DROP TABLE IF EXISTS fallas;
DROP TABLE IF EXISTS opciones;
DROP TABLE IF EXISTS preguntas;

-- ---------- Base de conocimiento ----------

CREATE TABLE preguntas (
  id    TEXT PRIMARY KEY,                                   -- q1 .. q29
  nodo  TEXT NOT NULL UNIQUE,                               -- N-01 .. N-29 (nodo del árbol)
  texto TEXT NOT NULL,
  tipo  TEXT NOT NULL CHECK (tipo IN ('si_no', 'opciones'))
);

CREATE TABLE opciones (
  pregunta_id TEXT NOT NULL REFERENCES preguntas(id) ON DELETE CASCADE,
  valor       TEXT NOT NULL,                                -- A, B, C
  texto       TEXT NOT NULL,
  PRIMARY KEY (pregunta_id, valor)
);

CREATE TABLE fallas (
  codigo        TEXT PRIMARY KEY,                           -- F-01 .. F-29
  nombre        TEXT NOT NULL,
  categoria     TEXT NOT NULL CHECK (categoria IN ('Seguridad', 'Operativa')),
  recomendacion TEXT NOT NULL
);

CREATE TABLE reglas (
  id           TEXT PRIMARY KEY,                            -- R-01 .. R-29
  orden        INTEGER NOT NULL,                            -- prioridad de evaluación
  falla_codigo TEXT NOT NULL REFERENCES fallas(codigo),     -- THEN
  diagnostico  TEXT
);

-- Condiciones de cada regla:
--   bloque 'all' (grupo 0)  -> condiciones unidas por AND (IF ... AND ...)
--   bloque 'any' (grupo n)  -> cada grupo es una alternativa del OR; las
--                              condiciones de un mismo grupo se unen por AND
CREATE TABLE regla_condiciones (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  regla_id TEXT NOT NULL REFERENCES reglas(id) ON DELETE CASCADE,
  bloque   TEXT NOT NULL CHECK (bloque IN ('all', 'any')),
  grupo    INTEGER NOT NULL DEFAULT 0,
  hecho    TEXT NOT NULL                                    -- q5 (SÍ), q5_no (NO), q1_A (opción)
);

CREATE TABLE post_reglas (
  id        TEXT PRIMARY KEY,                               -- RA-01, RA-02
  categoria TEXT NOT NULL CHECK (categoria IN ('Seguridad', 'Operativa')),
  accion    TEXT NOT NULL
);

-- ---------- Procesos transaccionales ----------

CREATE TABLE diagnosticos (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  creado_en      TEXT NOT NULL DEFAULT (datetime('now')),
  actualizado_en TEXT,
  titulo         TEXT,
  regla_id       TEXT NOT NULL,
  falla_codigo   TEXT NOT NULL,
  falla_nombre   TEXT NOT NULL,                             -- copia del nombre al momento del diagnóstico
  categoria      TEXT NOT NULL,
  estado         TEXT NOT NULL DEFAULT 'abierto' CHECK (estado IN ('abierto', 'en_atencion', 'cerrado')),
  notas          TEXT
);

CREATE TABLE diagnostico_respuestas (
  diagnostico_id INTEGER NOT NULL REFERENCES diagnosticos(id) ON DELETE CASCADE,
  orden          INTEGER NOT NULL,
  pregunta_id    TEXT NOT NULL,
  pregunta_texto TEXT NOT NULL,
  respuesta      TEXT NOT NULL,
  PRIMARY KEY (diagnostico_id, orden)
);

CREATE INDEX idx_diag_categoria ON diagnosticos(categoria);
CREATE INDEX idx_diag_estado ON diagnosticos(estado);
CREATE INDEX idx_diag_falla ON diagnosticos(falla_codigo);

-- ---------- Datos iniciales ----------

-- preguntas
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q1', 'N-01', '¿Cuál es el síntoma principal que reporta el usuario o el sistema de monitoreo?', 'opciones');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q2', 'N-02', '¿El servicio está caído para la totalidad de los usuarios?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q3', 'N-03', '¿El servidor responde a la prueba ping?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q4', 'N-04', '¿El equipo enciende (luces y ventiladores) y recibe energía eléctrica?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q5', 'N-05', '¿El autodiagnóstico de hardware (POST/SMART) del disco y la memoria es correcto?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q6', 'N-06', '¿El consumo de CPU o de memoria supera el 90 %?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q7', 'N-07', '¿Se detectan procesos desconocidos con nombres aleatorios en ejecución?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q8', 'N-08', '¿El consumo coincide con un pico anómalo de tráfico de red simultáneo?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q9', 'N-09', '¿Hubo un cambio reciente de configuración, parcheo o despliegue en el servidor?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q10', 'N-10', '¿Los usuarios afectados comparten la misma subred o ubicación física?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q11', 'N-11', '¿El problema ocurre solo en conexiones inalámbricas (Wi-Fi)?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q12', 'N-12', '¿Existen redes con nombre similar al corporativo disponibles cerca?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q13', 'N-13', '¿El switch o punto de acceso de la zona reporta errores o puertos caídos?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q14', 'N-14', '¿Hubo un cambio reciente en la configuración de red (VLAN, DHCP o firmware)?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q15', 'N-15', '¿La resolución de nombres (DNS) devuelve direcciones incorrectas?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q16', 'N-16', '¿El sitio o servicio muestra errores de certificado SSL/TLS?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q17', 'N-17', '¿Los archivos aparecen cifrados o con extensiones desconocidas?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q18', 'N-18', '¿Se encontraron notas de extorsión o archivos de rescate en los equipos?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q19', 'N-19', '¿Los archivos fueron eliminados o movidos sin autorización del propietario?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q20', 'N-20', '¿Las acciones provienen de una cuenta interna válida con permisos sobre los archivos?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q21', 'N-21', '¿Las aplicaciones muestran datos inconsistentes o registros perdidos?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q22', 'N-22', '¿Los registros de la base de datos muestran consultas SQL anómalas o masivas?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q23', 'N-23', '¿La inconsistencia aparece solo entre réplicas o respaldos del mismo servidor?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q24', 'N-24', '¿Las cuentas están bloqueadas o se registran intentos de acceso fallidos masivos?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q25', 'N-25', '¿Los intentos fallidos provienen de muchas direcciones IP distintas?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q26', 'N-26', '¿El bloqueo ocurre en horario no laboral o sin actividad del usuario legítimo?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q27', 'N-27', '¿Se detectaron inicios de sesión desde ubicaciones, horarios o dispositivos inusuales?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q28', 'N-28', '¿La sesión anómala utiliza privilegios administrativos?', 'si_no');
INSERT INTO preguntas (id, nodo, texto, tipo) VALUES ('q29', 'N-29', '¿Se crearon cuentas nuevas o se modificaron permisos sin autorización?', 'si_no');

-- opciones (pregunta raíz)
INSERT INTO opciones (pregunta_id, valor, texto) VALUES ('q1', 'A', 'A. Interrupción total o degradación severa del servicio');
INSERT INTO opciones (pregunta_id, valor, texto) VALUES ('q1', 'B', 'B. Archivos cifrados, alterados o inaccesibles');
INSERT INTO opciones (pregunta_id, valor, texto) VALUES ('q1', 'C', 'C. Comportamiento anómalo de cuentas o accesos');

-- fallas
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-01', 'Falla eléctrica o de fuente de poder', 'Operativa', 'Restablecer la energía, revisar UPS y fuente de poder y verificar el circuito eléctrico.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-02', 'Falla de hardware (disco o memoria dañados)', 'Operativa', 'Reemplazar el disco o módulo de memoria dañado y restaurar desde respaldo.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-03', 'Caída del sistema operativo', 'Operativa', 'Iniciar en modo seguro, revertir la última actualización y aplicar parches oficiales.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-04', 'Criptominero o malware que consume recursos', 'Seguridad', 'Aislar el equipo, eliminar el proceso malicioso y desplegar antivirus/EDR actualizado.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-05', 'Ataque de denegación de servicio (DoS/DDoS)', 'Seguridad', 'Activar mitigación DDoS, filtrar tráfico en el perímetro y escalar al proveedor.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-06', 'Fuga de memoria o mala configuración de la aplicación', 'Operativa', 'Identificar el proceso con fuga, aplicar parche de la aplicación y ajustar límites de memoria.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-07', 'Configuración incorrecta tras un cambio no controlado', 'Operativa', 'Revertir el cambio no controlado, restaurar la línea base aprobada y activar gestión de cambios.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-08', 'Agotamiento del pool de conexiones de la base de datos', 'Operativa', 'Reiniciar el servicio, aumentar el pool de conexiones y optimizar las consultas.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-09', 'Punto de acceso rogue / ataque Evil Twin', 'Seguridad', 'Localizar y desactivar el punto de acceso no autorizado y rotar las credenciales Wi-Fi.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-10', 'Saturación o interferencia del canal Wi-Fi', 'Operativa', 'Reasignar canales y potencia de transmisión y analizar fuentes de interferencia.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-11', 'Falla de hardware de red (switch, AP o puerto)', 'Operativa', 'Reemplazar el equipo o puerto dañado y redistribuir la carga en la topología.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-12', 'Error de configuración de VLAN o DHCP', 'Operativa', 'Corregir la configuración de VLAN/DHCP contra la línea base y validar la conectividad.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-13', 'Envenenamiento de DNS (spoofing/poisoning)', 'Seguridad', 'Purgar la caché DNS, forzar DNSSEC y auditar el servidor DNS comprometido.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-14', 'Ataque de intermediario (Man-in-the-Middle)', 'Seguridad', 'Rotar certificados, verificar el gateway de salida y buscar equipos intermediarios.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-15', 'Caída del enlace o del proveedor de Internet', 'Operativa', 'Validar el enlace con el proveedor, activar el enlace de respaldo y monitorear.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-16', 'Ataque de ransomware', 'Seguridad', 'Aislar equipos, no pagar el rescate, restaurar desde respaldos verificados y segmentar la red.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-17', 'Malware de cifrado sin nota de rescate (wiper)', 'Seguridad', 'Contener el equipo, identificar y eliminar la muestra y restaurar desde respaldo.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-18', 'Amenaza interna (insider) con uso indebido de privilegios', 'Seguridad', 'Suspender la cuenta, revisar registros, aplicar mínimo privilegio y medidas disciplinarias.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-19', 'Borrado remoto por atacante (acceso no autorizado)', 'Seguridad', 'Bloquear IP y credenciales usadas, cerrar la vía de entrada y restaurar los archivos.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-20', 'Inyección SQL con manipulación de datos', 'Seguridad', 'Sanear la base de datos, usar consultas parametrizadas y corregir el código vulnerable.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-21', 'Error de replicación o sincronización entre servidores', 'Operativa', 'Revisar la réplica inconsistente, reforzar la sincronización y verificar integridad.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-22', 'Corrupción de la base de datos o falla de integridad', 'Operativa', 'Restaurar la base de datos desde el último respaldo íntegro y verificar el sistema de archivos.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-23', 'Fuerza bruta distribuida / credential stuffing', 'Seguridad', 'Activar bloqueo por IP, captcha/WAF y validar credenciales contra filtraciones.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-24', 'Fuerza bruta dirigida a una cuenta específica', 'Seguridad', 'Reforzar la política de contraseñas, habilitar MFA y monitorear la cuenta objetivo.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-25', 'Política de bloqueo automático mal configurada', 'Operativa', 'Ajustar los umbrales de la política de bloqueo y notificar a los usuarios.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-26', 'Compromiso de una cuenta privilegiada', 'Seguridad', 'Revocar sesiones y credenciales, analizar el alcance y rotar claves de administración.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-27', 'Uso indebido de credenciales (cuenta compartida o sesión robada)', 'Seguridad', 'Invalidar la sesión, verificar la identidad del usuario y desplegar MFA.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-28', 'Puerta trasera o escalada de privilegios', 'Seguridad', 'Eliminar cuentas o permisos no autorizados, rastrear su origen y revisar la gestión de identidades.');
INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES ('F-29', 'Comportamiento legítimo no documentado (falsa alarma)', 'Operativa', 'Documentar el comportamiento como legítimo y ajustar reglas y umbrales de detección.');

-- reglas
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-01', 1, 'F-01', 'Falla eléctrica o de fuente de poder');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-02', 2, 'F-02', 'Falla de hardware (disco o memoria dañados)');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-03', 3, 'F-03', 'Caída del sistema operativo');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-04', 4, 'F-04', 'Criptominero o malware que consume recursos');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-05', 5, 'F-05', 'Ataque de denegación de servicio (DoS/DDoS)');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-06', 6, 'F-06', 'Fuga de memoria o mala configuración de la aplicación');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-07', 7, 'F-07', 'Configuración incorrecta tras un cambio no controlado');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-08', 8, 'F-08', 'Agotamiento del pool de conexiones de la base de datos');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-09', 9, 'F-09', 'Punto de acceso rogue / ataque Evil Twin');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-10', 10, 'F-10', 'Saturación o interferencia del canal Wi-Fi');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-11', 11, 'F-11', 'Falla de hardware de red (switch, AP o puerto)');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-12', 12, 'F-12', 'Error de configuración de VLAN o DHCP');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-13', 13, 'F-13', 'Envenenamiento de DNS (spoofing/poisoning)');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-14', 14, 'F-14', 'Ataque de intermediario (Man-in-the-Middle)');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-15', 15, 'F-15', 'Caída del enlace o del proveedor de Internet');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-16', 16, 'F-16', 'Ataque de ransomware');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-17', 17, 'F-17', 'Malware de cifrado sin nota de rescate (wiper)');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-18', 18, 'F-18', 'Amenaza interna (insider) con uso indebido de privilegios');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-19', 19, 'F-19', 'Borrado remoto por atacante (acceso no autorizado)');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-20', 20, 'F-20', 'Inyección SQL con manipulación de datos');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-21', 21, 'F-21', 'Error de replicación o sincronización entre servidores');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-22', 22, 'F-22', 'Corrupción de la base de datos o falla de integridad');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-23', 23, 'F-23', 'Fuerza bruta distribuida / credential stuffing');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-24', 24, 'F-24', 'Fuerza bruta dirigida a una cuenta específica');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-25', 25, 'F-25', 'Política de bloqueo automático mal configurada');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-26', 26, 'F-26', 'Compromiso de una cuenta privilegiada');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-27', 27, 'F-27', 'Uso indebido de credenciales (cuenta compartida o sesión robada)');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-28', 28, 'F-28', 'Puerta trasera o escalada de privilegios');
INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES ('R-29', 29, 'F-29', 'Comportamiento legítimo no documentado (falsa alarma)');

-- condiciones de las reglas (IF ... AND ... / OR)
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-01', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-01', 'all', 0, 'q2');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-01', 'all', 0, 'q3_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-01', 'all', 0, 'q4_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-02', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-02', 'all', 0, 'q2');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-02', 'all', 0, 'q3_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-02', 'all', 0, 'q4');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-02', 'all', 0, 'q5_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-03', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-03', 'all', 0, 'q2');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-03', 'all', 0, 'q3_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-03', 'all', 0, 'q4');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-03', 'all', 0, 'q5');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-04', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-04', 'all', 0, 'q2');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-04', 'all', 0, 'q3');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-04', 'all', 0, 'q6');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-04', 'all', 0, 'q7');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-05', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-05', 'all', 0, 'q2');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-05', 'all', 0, 'q3');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-05', 'all', 0, 'q6');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-05', 'all', 0, 'q7_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-05', 'all', 0, 'q8');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-06', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-06', 'all', 0, 'q2');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-06', 'all', 0, 'q3');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-06', 'all', 0, 'q6');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-06', 'all', 0, 'q7_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-06', 'all', 0, 'q8_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-07', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-07', 'any', 1, 'q2');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-07', 'any', 1, 'q3');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-07', 'any', 1, 'q6_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-07', 'any', 1, 'q9');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-07', 'any', 2, 'q2_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-07', 'any', 2, 'q10');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-07', 'any', 2, 'q11_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-07', 'any', 2, 'q13_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-07', 'any', 2, 'q14');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-08', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-08', 'all', 0, 'q2');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-08', 'all', 0, 'q3');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-08', 'all', 0, 'q6_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-08', 'all', 0, 'q9_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-09', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-09', 'all', 0, 'q2_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-09', 'all', 0, 'q10');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-09', 'all', 0, 'q11');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-09', 'all', 0, 'q12');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-10', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-10', 'all', 0, 'q2_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-10', 'all', 0, 'q10');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-10', 'all', 0, 'q11');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-10', 'all', 0, 'q12_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-11', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-11', 'all', 0, 'q2_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-11', 'all', 0, 'q10');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-11', 'all', 0, 'q11_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-11', 'all', 0, 'q13');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-12', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-12', 'all', 0, 'q2_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-12', 'all', 0, 'q10');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-12', 'all', 0, 'q11_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-12', 'all', 0, 'q13_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-12', 'all', 0, 'q14_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-13', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-13', 'all', 0, 'q2_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-13', 'all', 0, 'q10_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-13', 'all', 0, 'q15');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-14', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-14', 'all', 0, 'q2_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-14', 'all', 0, 'q10_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-14', 'all', 0, 'q15_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-14', 'all', 0, 'q16');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-15', 'all', 0, 'q1_A');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-15', 'all', 0, 'q2_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-15', 'all', 0, 'q10_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-15', 'all', 0, 'q15_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-15', 'all', 0, 'q16_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-16', 'all', 0, 'q1_B');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-16', 'all', 0, 'q17');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-16', 'all', 0, 'q18');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-17', 'all', 0, 'q1_B');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-17', 'all', 0, 'q17');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-17', 'all', 0, 'q18_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-18', 'all', 0, 'q1_B');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-18', 'all', 0, 'q17_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-18', 'all', 0, 'q19');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-18', 'all', 0, 'q20');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-19', 'all', 0, 'q1_B');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-19', 'all', 0, 'q17_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-19', 'all', 0, 'q19');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-19', 'all', 0, 'q20_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-20', 'all', 0, 'q1_B');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-20', 'all', 0, 'q17_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-20', 'all', 0, 'q19_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-20', 'all', 0, 'q21');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-20', 'all', 0, 'q22');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-21', 'all', 0, 'q1_B');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-21', 'all', 0, 'q17_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-21', 'all', 0, 'q19_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-21', 'all', 0, 'q21');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-21', 'all', 0, 'q22_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-21', 'all', 0, 'q23');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-22', 'all', 0, 'q1_B');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-22', 'all', 0, 'q17_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-22', 'all', 0, 'q19_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-22', 'any', 1, 'q21_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-22', 'any', 2, 'q22_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-22', 'any', 2, 'q23_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-23', 'all', 0, 'q1_C');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-23', 'all', 0, 'q24');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-23', 'all', 0, 'q25');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-24', 'all', 0, 'q1_C');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-24', 'all', 0, 'q24');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-24', 'all', 0, 'q25_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-24', 'all', 0, 'q26');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-25', 'all', 0, 'q1_C');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-25', 'all', 0, 'q24');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-25', 'all', 0, 'q25_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-25', 'all', 0, 'q26_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-26', 'all', 0, 'q1_C');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-26', 'all', 0, 'q24_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-26', 'all', 0, 'q27');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-26', 'all', 0, 'q28');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-27', 'all', 0, 'q1_C');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-27', 'all', 0, 'q24_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-27', 'all', 0, 'q27');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-27', 'all', 0, 'q28_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-28', 'all', 0, 'q1_C');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-28', 'all', 0, 'q24_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-28', 'all', 0, 'q27_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-28', 'all', 0, 'q29');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-29', 'all', 0, 'q1_C');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-29', 'all', 0, 'q24_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-29', 'all', 0, 'q27_no');
INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES ('R-29', 'all', 0, 'q29_no');

-- post-reglas (acciones según la categoría)
INSERT INTO post_reglas (id, categoria, accion) VALUES ('RA-01', 'Seguridad', 'activar_protocolo(''P-12 Escalamiento'', ''P-13 Contención'', ''P-14 Remediación'')');
INSERT INTO post_reglas (id, categoria, accion) VALUES ('RA-02', 'Operativa', 'derivar_a_soporte_tecnico()');

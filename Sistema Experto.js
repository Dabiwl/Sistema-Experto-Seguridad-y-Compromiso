// Sistema experto de diagnóstico de riesgos de seguridad informática
// Cloudflare Worker + base de datos Cloudflare D1 (SQL).
//   - Bindings requeridos: DB (D1). Secreto opcional pero recomendado: ADMIN_TOKEN.
//   - Motor de inferencia con encadenamiento sobre reglas IF/AND/OR/THEN guardadas en D1.
//   - Procesos transaccionales: guardar casos, historial, seguimiento, administración de la base de conocimiento.

const CACHE_MS = 10000;
const ESTADOS = ['abierto', 'en_atencion', 'cerrado'];
const CATEGORIAS = ['Seguridad', 'Operativa'];
let cache = { kb: null, at: 0 };

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'content-type': 'application/json;charset=utf-8', 'cache-control': 'no-store' }
  });
}

/* =====================  Carga de la base de conocimiento desde D1  ===================== */

async function loadKB(env, force) {
  const now = Date.now();
  if (!force && cache.kb && now - cache.at < CACHE_MS) return cache.kb;

  const rs = await env.DB.batch([
    env.DB.prepare('SELECT id, nodo, texto, tipo FROM preguntas ORDER BY CAST(substr(id, 2) AS INTEGER)'),
    env.DB.prepare('SELECT pregunta_id, valor, texto FROM opciones ORDER BY pregunta_id, valor'),
    env.DB.prepare('SELECT codigo, nombre, categoria, recomendacion FROM fallas ORDER BY codigo'),
    env.DB.prepare('SELECT id, orden, falla_codigo, diagnostico FROM reglas ORDER BY orden, id'),
    env.DB.prepare('SELECT regla_id, bloque, grupo, hecho FROM regla_condiciones ORDER BY id'),
    env.DB.prepare('SELECT id, categoria, accion FROM post_reglas ORDER BY id')
  ]);
  const preguntasRows = rs[0].results;
  const opcionesRows = rs[1].results;
  const fallasRows = rs[2].results;
  const reglasRows = rs[3].results;
  const condRows = rs[4].results;
  const postRows = rs[5].results;

  const kb = {
    preguntas: [],
    preguntasMap: {},
    questions: {},
    nodos: {},
    opciones: {},
    hechos: {},
    fallas: {},
    rules: [],
    post_rules: []
  };

  preguntasRows.forEach(function (p) {
    const q = { id: p.id, nodo: p.nodo, texto: p.texto, tipo: p.tipo, opciones: [] };
    kb.preguntas.push(q);
    kb.preguntasMap[p.id] = q;
    kb.questions[p.id] = p.texto;
    kb.nodos[p.id] = p.nodo;
  });
  opcionesRows.forEach(function (o) {
    const q = kb.preguntasMap[o.pregunta_id];
    if (q) q.opciones.push({ valor: o.valor, texto: o.texto });
  });
  kb.preguntas.forEach(function (q) {
    if (q.tipo === 'opciones') {
      kb.opciones[q.id] = q.opciones;
      q.opciones.forEach(function (o) {
        kb.hechos[q.id + '_' + o.valor] = q.texto + ' → ' + o.texto;
      });
    } else {
      kb.hechos[q.id] = 'Respuesta SÍ a: ' + q.texto;
      kb.hechos[q.id + '_no'] = 'Respuesta NO a: ' + q.texto;
    }
  });
  fallasRows.forEach(function (f) {
    kb.fallas[f.codigo] = { nombre: f.nombre, categoria: f.categoria, recomendacion: f.recomendacion };
  });

  const condPorRegla = {};
  condRows.forEach(function (c) {
    (condPorRegla[c.regla_id] = condPorRegla[c.regla_id] || []).push(c);
  });
  reglasRows.forEach(function (r) {
    const conds = condPorRegla[r.id] || [];
    const all = conds.filter(function (c) { return c.bloque === 'all'; }).map(function (c) { return c.hecho; });
    const grupos = {};
    conds.filter(function (c) { return c.bloque === 'any'; }).forEach(function (c) {
      (grupos[c.grupo] = grupos[c.grupo] || []).push(c.hecho);
    });
    const any = Object.keys(grupos)
      .sort(function (a, b) { return Number(a) - Number(b); })
      .map(function (g) { return grupos[g].length === 1 ? grupos[g][0] : { if_all: grupos[g] }; });
    const rule = { id: r.id, orden: r.orden, then: r.falla_codigo, diagnostico: r.diagnostico || '' };
    if (all.length) rule.if_all = all;
    if (any.length) rule.if_any = any;
    kb.rules.push(rule);
  });
  postRows.forEach(function (p) {
    kb.post_rules.push({ id: p.id, if_any: ['categoria=' + p.categoria], then: p.accion });
  });

  cache = { kb: kb, at: now };
  return kb;
}

function invalidate() {
  cache = { kb: null, at: 0 };
}

/* =====================  Motor de inferencia (lógica de 3 valores)  ===================== */

function parseToken(t) {
  const m = /^q(\d+)(?:_(no|[A-Z]))?$/.exec(String(t));
  return m ? { n: Number(m[1]), suf: m[2] || null } : null;
}

function tokenValue(t, answers) {
  const p = parseToken(t);
  if (!p) return null;
  const a = answers['q' + p.n];
  if (a === undefined || a === null) return null;
  if (p.suf === 'no') return a === false;
  if (p.suf) return a === p.suf;
  return a === true;
}

function and3(vs) {
  if (vs.some(function (v) { return v === false; })) return false;
  if (vs.every(function (v) { return v === true; })) return true;
  return null;
}

function or3(vs) {
  if (vs.some(function (v) { return v === true; })) return true;
  if (vs.every(function (v) { return v === false; })) return false;
  return null;
}

function listsOf(node) {
  const lists = [];
  if (node.if_all) lists.push({ kind: 'all', items: node.if_all });
  if (node.if_any) lists.push({ kind: 'any', items: node.if_any });
  return lists;
}

function evalNode(node, a) {
  if (typeof node === 'string') return tokenValue(node, a);
  const parts = listsOf(node).map(function (l) {
    const vs = l.items.map(function (n) { return evalNode(n, a); });
    return l.kind === 'all' ? and3(vs) : or3(vs);
  });
  return and3(parts);
}

function firstUnknown(node, a) {
  if (typeof node === 'string') {
    return tokenValue(node, a) === null ? parseToken(node).n : null;
  }
  const lists = listsOf(node);
  for (let i = 0; i < lists.length; i++) {
    const l = lists[i];
    const vs = l.items.map(function (n) { return evalNode(n, a); });
    const v = l.kind === 'all' ? and3(vs) : or3(vs);
    if (v !== null) continue;
    for (let j = 0; j < l.items.length; j++) {
      if (vs[j] === null) {
        const r = firstUnknown(l.items[j], a);
        if (r !== null) return r;
      }
    }
  }
  return null;
}

function flatTokens(node, out) {
  if (typeof node === 'string') { out.push(node); return out; }
  listsOf(node).forEach(function (l) {
    l.items.forEach(function (n) { flatTokens(n, out); });
  });
  return out;
}

function questionPayload(kb, n) {
  const id = 'q' + n;
  const q = kb.preguntasMap[id];
  return {
    id: id,
    nodo: q ? q.nodo : 'N-' + String(n).padStart(2, '0'),
    texto: q ? q.texto : id,
    tipo: q && q.tipo === 'opciones' ? 'opciones' : 'si_no',
    opciones: q && q.tipo === 'opciones' ? q.opciones : []
  };
}

function formatAction(then) {
  if (/^activar_protocolo\(/.test(then)) {
    const items = [];
    const re = /'([^']+)'/g;
    let m;
    while ((m = re.exec(then))) items.push(m[1]);
    return 'Activar protocolos: ' + items.join(' · ');
  }
  if (/^derivar_a_soporte_tecnico\(/.test(then)) return 'Derivar a soporte técnico';
  return then;
}

function diagnose(kb, answers) {
  for (let i = 0; i < kb.rules.length; i++) {
    const rule = kb.rules[i];
    if (evalNode(rule, answers) === true) {
      const falla = kb.fallas[rule.then] || {};
      const razones = [];
      flatTokens(rule, []).forEach(function (t) {
        if (tokenValue(t, answers) === true && kb.hechos[t] && razones.indexOf(kb.hechos[t]) < 0) {
          razones.push(kb.hechos[t]);
        }
      });
      const categoria = falla.categoria || null;
      const acciones = kb.post_rules
        .filter(function (pr) { return pr.if_any.indexOf('categoria=' + categoria) >= 0; })
        .map(function (pr) { return { id: pr.id, texto: formatAction(pr.then) }; });
      return {
        estado: 'diagnostico',
        regla: rule.id,
        codigo: rule.then,
        nombre: falla.nombre || rule.diagnostico,
        categoria: categoria,
        recomendacion: falla.recomendacion || '',
        razones: razones,
        acciones: acciones
      };
    }
  }
  for (let i = 0; i < kb.rules.length; i++) {
    if (evalNode(kb.rules[i], answers) === null) {
      const n = firstUnknown(kb.rules[i], answers);
      if (n !== null) return { estado: 'pregunta', pregunta: questionPayload(kb, n) };
    }
  }
  return {
    estado: 'sin_diagnostico',
    mensaje: 'Las respuestas no coinciden con ninguna regla de la base de conocimiento.'
  };
}

function validateAnswers(kb, raw) {
  const out = {};
  if (!raw || typeof raw !== 'object') return out;
  Object.keys(raw).forEach(function (id) {
    const q = kb.preguntasMap[id];
    if (!q) return;
    const v = raw[id];
    if (q.tipo === 'si_no') {
      if (v !== true && v !== false) throw new HttpError(400, 'Respuesta inválida para ' + id);
    } else if (!q.opciones.some(function (o) { return o.valor === v; })) {
      throw new HttpError(400, 'Opción inválida para ' + id);
    }
    out[id] = v;
  });
  return out;
}

/* =====================  Utilidades de validación  ===================== */

async function readBody(request) {
  const text = await request.text();
  if (text.length > 100000) throw new HttpError(413, 'Solicitud demasiado grande');
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new HttpError(400, 'JSON inválido');
  }
}

function clean(v, max) {
  if (v === undefined || v === null) return '';
  return String(v).trim().slice(0, max);
}

function required(v, label, max) {
  const s = clean(v, max);
  if (!s) throw new HttpError(400, 'Falta el campo: ' + label);
  return s;
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function requireAdmin(request, env) {
  if (!env.ADMIN_TOKEN) {
    throw new HttpError(503, 'La administración está desactivada: configura el secreto ADMIN_TOKEN en el Worker.');
  }
  const t = request.headers.get('x-admin-token') || '';
  if (!safeEqual(t, String(env.ADMIN_TOKEN))) throw new HttpError(401, 'Token de administrador inválido');
}

function tokenValido(kb, t) {
  const p = parseToken(t);
  if (!p) return false;
  const q = kb.preguntasMap['q' + p.n];
  if (!q) return false;
  if (p.suf === null || p.suf === 'no') return q.tipo === 'si_no';
  return q.tipo === 'opciones' && q.opciones.some(function (o) { return o.valor === p.suf; });
}

function validateRule(kb, body, idPath) {
  const id = idPath || clean(body.id, 20);
  if (!/^[A-Za-z0-9_-]{1,20}$/.test(id)) throw new HttpError(400, 'Id de regla inválido (letras, números, guion).');
  const fallaCodigo = clean(body.falla_codigo, 20);
  if (!kb.fallas[fallaCodigo]) throw new HttpError(400, 'La falla indicada no existe: ' + fallaCodigo);

  const ifAll = body.if_all === undefined ? [] : body.if_all;
  const ifAny = body.if_any === undefined ? [] : body.if_any;
  if (!Array.isArray(ifAll) || !Array.isArray(ifAny)) throw new HttpError(400, 'if_all e if_any deben ser listas.');

  const preguntas = {};
  function chequear(t) {
    if (typeof t !== 'string' || !tokenValido(kb, t)) {
      throw new HttpError(400, 'Condición inválida: ' + JSON.stringify(t) + ' (usa qN, qN_no o qN_LETRA según la pregunta).');
    }
    preguntas[parseToken(t).n] = true;
    return t;
  }
  const all = ifAll.map(chequear);
  const any = ifAny.map(function (g) {
    if (typeof g === 'string') return [chequear(g)];
    if (g && Array.isArray(g.if_all) && g.if_all.length) return g.if_all.map(chequear);
    throw new HttpError(400, 'Cada elemento de if_any debe ser una condición o {"if_all": [...]}.');
  });
  if (!all.length && !any.length) throw new HttpError(400, 'La regla necesita al menos una condición.');
  if (Object.keys(preguntas).length < 2) {
    throw new HttpError(400, 'Cada diagnóstico debe depender de al menos 2 preguntas distintas.');
  }

  let orden = Number(body.orden);
  if (!Number.isInteger(orden) || orden < 1) {
    orden = kb.rules.reduce(function (m, r) { return Math.max(m, r.orden || 0); }, 0) + 1;
  }
  return {
    id: id,
    orden: orden,
    falla_codigo: fallaCodigo,
    diagnostico: clean(body.diagnostico, 200) || kb.fallas[fallaCodigo].nombre,
    all: all,
    any: any
  };
}

function guardarReglaStmts(env, r) {
  const stmts = [
    env.DB.prepare(
      'INSERT INTO reglas (id, orden, falla_codigo, diagnostico) VALUES (?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET orden = excluded.orden, falla_codigo = excluded.falla_codigo, diagnostico = excluded.diagnostico'
    ).bind(r.id, r.orden, r.falla_codigo, r.diagnostico),
    env.DB.prepare('DELETE FROM regla_condiciones WHERE regla_id = ?').bind(r.id)
  ];
  r.all.forEach(function (t) {
    stmts.push(env.DB.prepare("INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES (?, 'all', 0, ?)").bind(r.id, t));
  });
  r.any.forEach(function (g, i) {
    g.forEach(function (t) {
      stmts.push(env.DB.prepare("INSERT INTO regla_condiciones (regla_id, bloque, grupo, hecho) VALUES (?, 'any', ?, ?)").bind(r.id, i + 1, t));
    });
  });
  return stmts;
}

function kbPublic(kb) {
  return {
    preguntas: kb.preguntas,
    fallas: Object.keys(kb.fallas).map(function (c) {
      return { codigo: c, nombre: kb.fallas[c].nombre, categoria: kb.fallas[c].categoria, recomendacion: kb.fallas[c].recomendacion };
    }),
    reglas: kb.rules.map(function (r) {
      return { id: r.id, orden: r.orden, falla_codigo: r.then, diagnostico: r.diagnostico, if_all: r.if_all || [], if_any: r.if_any || [] };
    }),
    post_reglas: kb.post_rules.map(function (p) {
      return { id: p.id, categoria: p.if_any[0].replace('categoria=', ''), accion: formatAction(p.then) };
    })
  };
}

/* =====================  Casos diagnosticados (transacciones)  ===================== */

async function crearCaso(request, env, kb) {
  const body = await readBody(request);
  const answers = validateAnswers(kb, body.answers);
  const res = diagnose(kb, answers);
  if (res.estado !== 'diagnostico') throw new HttpError(400, 'Aún no hay un diagnóstico final para guardar.');
  const titulo = clean(body.titulo, 120);

  const resp = Object.keys(answers)
    .sort(function (a, b) { return Number(a.slice(1)) - Number(b.slice(1)); })
    .map(function (id) {
      const q = kb.preguntasMap[id];
      const v = answers[id];
      let texto;
      if (q.tipo === 'si_no') texto = v ? 'Sí' : 'No';
      else texto = q.opciones.filter(function (o) { return o.valor === v; })[0].texto;
      return { p: id, t: q.texto, r: texto };
    });

  // Una sola transacción: el caso y todas sus respuestas se guardan juntos o no se guarda nada.
  const rs = await env.DB.batch([
    env.DB.prepare(
      'INSERT INTO diagnosticos (titulo, regla_id, falla_codigo, falla_nombre, categoria) VALUES (?, ?, ?, ?, ?)'
    ).bind(titulo || null, res.regla, res.codigo, res.nombre, res.categoria),
    env.DB.prepare(
      'INSERT INTO diagnostico_respuestas (diagnostico_id, orden, pregunta_id, pregunta_texto, respuesta) ' +
      "SELECT (SELECT MAX(id) FROM diagnosticos), CAST(key AS INTEGER) + 1, json_extract(value, '$.p'), json_extract(value, '$.t'), json_extract(value, '$.r') " +
      'FROM json_each(?)'
    ).bind(JSON.stringify(resp))
  ]);
  return json({ id: rs[0].meta.last_row_id, codigo: res.codigo, nombre: res.nombre, categoria: res.categoria }, 201);
}

async function listarCasos(url, env) {
  const where = [];
  const args = [];
  const categoria = url.searchParams.get('categoria');
  const estado = url.searchParams.get('estado');
  const falla = url.searchParams.get('falla');
  if (categoria) { where.push('categoria = ?'); args.push(categoria); }
  if (estado) { where.push('estado = ?'); args.push(estado); }
  if (falla) { where.push('falla_codigo = ?'); args.push(falla); }
  let limit = Number(url.searchParams.get('limit'));
  if (!Number.isInteger(limit) || limit < 1) limit = 50;
  limit = Math.min(limit, 200);
  const w = where.length ? ' WHERE ' + where.join(' AND ') : '';
  const rs = await env.DB.batch([
    env.DB.prepare(
      'SELECT id, creado_en, titulo, regla_id, falla_codigo, falla_nombre, categoria, estado FROM diagnosticos' +
      w + ' ORDER BY id DESC LIMIT ?'
    ).bind(...args, limit),
    env.DB.prepare('SELECT COUNT(*) AS total FROM diagnosticos' + w).bind(...args)
  ]);
  return json({ items: rs[0].results, total: rs[1].results[0].total });
}

async function estadisticas(env) {
  const rs = await env.DB.batch([
    env.DB.prepare('SELECT COUNT(*) AS total FROM diagnosticos'),
    env.DB.prepare('SELECT categoria, COUNT(*) AS total FROM diagnosticos GROUP BY categoria'),
    env.DB.prepare('SELECT estado, COUNT(*) AS total FROM diagnosticos GROUP BY estado'),
    env.DB.prepare(
      'SELECT falla_codigo, falla_nombre, COUNT(*) AS total FROM diagnosticos GROUP BY falla_codigo, falla_nombre ORDER BY total DESC, falla_codigo LIMIT 5'
    )
  ]);
  return json({
    total: rs[0].results[0].total,
    por_categoria: rs[1].results,
    por_estado: rs[2].results,
    top_fallas: rs[3].results
  });
}

async function detalleCaso(id, env) {
  const rs = await env.DB.batch([
    env.DB.prepare('SELECT * FROM diagnosticos WHERE id = ?').bind(id),
    env.DB.prepare(
      'SELECT orden, pregunta_id, pregunta_texto, respuesta FROM diagnostico_respuestas WHERE diagnostico_id = ? ORDER BY orden'
    ).bind(id)
  ]);
  if (!rs[0].results.length) throw new HttpError(404, 'Caso no encontrado');
  return json({ caso: rs[0].results[0], respuestas: rs[1].results });
}

async function actualizarCaso(id, request, env) {
  const body = await readBody(request);
  const sets = ["actualizado_en = datetime('now')"];
  const args = [];
  if (body.estado !== undefined) {
    if (ESTADOS.indexOf(body.estado) < 0) throw new HttpError(400, 'Estado inválido');
    sets.push('estado = ?');
    args.push(body.estado);
  }
  if (body.notas !== undefined) {
    sets.push('notas = ?');
    args.push(clean(body.notas, 1000) || null);
  }
  const r = await env.DB.prepare('UPDATE diagnosticos SET ' + sets.join(', ') + ' WHERE id = ?').bind(...args, id).run();
  if (!r.meta.changes) throw new HttpError(404, 'Caso no encontrado');
  return json({ ok: true });
}

async function borrarCaso(id, env) {
  const r = await env.DB.prepare('DELETE FROM diagnosticos WHERE id = ?').bind(id).run();
  if (!r.meta.changes) throw new HttpError(404, 'Caso no encontrado');
  return json({ ok: true });
}

/* =====================  Administración de la base de conocimiento  ===================== */

async function adminFallas(method, key, request, env, kb) {
  if (method === 'POST' || method === 'PUT') {
    const body = await readBody(request);
    const codigo = method === 'PUT' ? key : required(body.codigo, 'código', 20);
    if (!/^[A-Za-z0-9_-]{1,20}$/.test(codigo)) throw new HttpError(400, 'Código de falla inválido');
    const nombre = required(body.nombre, 'nombre', 200);
    const recomendacion = required(body.recomendacion, 'recomendación', 1000);
    const categoria = clean(body.categoria, 20);
    if (CATEGORIAS.indexOf(categoria) < 0) throw new HttpError(400, 'La categoría debe ser Seguridad u Operativa');
    if (method === 'POST') {
      if (kb.fallas[codigo]) throw new HttpError(409, 'Ya existe la falla ' + codigo);
      await env.DB.prepare('INSERT INTO fallas (codigo, nombre, categoria, recomendacion) VALUES (?, ?, ?, ?)')
        .bind(codigo, nombre, categoria, recomendacion).run();
      invalidate();
      return json({ ok: true }, 201);
    }
    if (!kb.fallas[codigo]) throw new HttpError(404, 'Falla no encontrada');
    await env.DB.prepare('UPDATE fallas SET nombre = ?, categoria = ?, recomendacion = ? WHERE codigo = ?')
      .bind(nombre, categoria, recomendacion, codigo).run();
    invalidate();
    return json({ ok: true });
  }
  if (method === 'DELETE') {
    if (!kb.fallas[key]) throw new HttpError(404, 'Falla no encontrada');
    const usada = kb.rules.filter(function (r) { return r.then === key; }).map(function (r) { return r.id; });
    if (usada.length) throw new HttpError(409, 'No se puede eliminar: la usan las reglas ' + usada.join(', '));
    await env.DB.prepare('DELETE FROM fallas WHERE codigo = ?').bind(key).run();
    invalidate();
    return json({ ok: true });
  }
  throw new HttpError(405, 'Método no permitido');
}

function parseOpciones(raw) {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) throw new HttpError(400, 'opciones debe ser una lista');
  const seen = {};
  const ops = raw.map(function (o) {
    const valor = clean(o && o.valor, 1);
    if (!/^[A-Z]$/.test(valor)) throw new HttpError(400, 'El valor de cada opción debe ser una letra mayúscula (A, B, C...)');
    if (seen[valor]) throw new HttpError(400, 'Opción repetida: ' + valor);
    seen[valor] = true;
    return { valor: valor, texto: required(o.texto, 'texto de la opción ' + valor, 300) };
  });
  if (ops.length === 1) throw new HttpError(400, 'Una pregunta con opciones necesita al menos 2.');
  return ops;
}

function reglasInvalidasPor(kb, qid, nuevaPregunta) {
  // Revisa si las reglas existentes siguen siendo válidas si la pregunta qid se modifica.
  const n = Number(qid.slice(1));
  const mapa = Object.assign({}, kb.preguntasMap);
  if (nuevaPregunta) mapa[qid] = nuevaPregunta;
  else delete mapa[qid];
  const fake = { preguntasMap: mapa };
  return kb.rules.filter(function (r) {
    return flatTokens(r, []).some(function (t) {
      const p = parseToken(t);
      return p && p.n === n && !tokenValido(fake, t);
    });
  }).map(function (r) { return r.id; });
}

async function adminPreguntas(method, key, request, env, kb) {
  if (method === 'POST' || method === 'PUT') {
    const body = await readBody(request);
    const id = method === 'PUT' ? key : required(body.id, 'id', 10);
    if (!/^q\d+$/.test(id)) throw new HttpError(400, 'El id de la pregunta debe ser qN (por ejemplo q30)');
    const nodo = required(body.nodo, 'nodo', 10);
    const texto = required(body.texto, 'texto', 300);
    const ops = parseOpciones(body.opciones);
    const tipo = ops.length ? 'opciones' : 'si_no';
    const nodoUsado = kb.preguntas.filter(function (q) { return q.nodo === nodo && q.id !== id; })[0];
    if (nodoUsado) throw new HttpError(409, 'El nodo ' + nodo + ' ya lo usa ' + nodoUsado.id);

    if (method === 'POST') {
      if (kb.preguntasMap[id]) throw new HttpError(409, 'Ya existe la pregunta ' + id);
      const stmts = [env.DB.prepare('INSERT INTO preguntas (id, nodo, texto, tipo) VALUES (?, ?, ?, ?)').bind(id, nodo, texto, tipo)];
      ops.forEach(function (o) {
        stmts.push(env.DB.prepare('INSERT INTO opciones (pregunta_id, valor, texto) VALUES (?, ?, ?)').bind(id, o.valor, o.texto));
      });
      await env.DB.batch(stmts);
      invalidate();
      return json({ ok: true }, 201);
    }
    if (!kb.preguntasMap[id]) throw new HttpError(404, 'Pregunta no encontrada');
    const rotas = reglasInvalidasPor(kb, id, { id: id, tipo: tipo, opciones: ops });
    if (rotas.length) throw new HttpError(409, 'Ese cambio dejaría inválidas las reglas: ' + rotas.join(', '));
    const stmts = [
      env.DB.prepare('UPDATE preguntas SET nodo = ?, texto = ?, tipo = ? WHERE id = ?').bind(nodo, texto, tipo, id),
      env.DB.prepare('DELETE FROM opciones WHERE pregunta_id = ?').bind(id)
    ];
    ops.forEach(function (o) {
      stmts.push(env.DB.prepare('INSERT INTO opciones (pregunta_id, valor, texto) VALUES (?, ?, ?)').bind(id, o.valor, o.texto));
    });
    await env.DB.batch(stmts);
    invalidate();
    return json({ ok: true });
  }
  if (method === 'DELETE') {
    if (!kb.preguntasMap[key]) throw new HttpError(404, 'Pregunta no encontrada');
    const usadas = reglasInvalidasPor(kb, key, null);
    if (usadas.length) throw new HttpError(409, 'No se puede eliminar: la usan las reglas ' + usadas.join(', '));
    await env.DB.prepare('DELETE FROM preguntas WHERE id = ?').bind(key).run();
    invalidate();
    return json({ ok: true });
  }
  throw new HttpError(405, 'Método no permitido');
}

async function adminReglas(method, key, request, env, kb) {
  if (method === 'POST' || method === 'PUT') {
    const body = await readBody(request);
    const r = validateRule(kb, body, method === 'PUT' ? key : null);
    const existe = kb.rules.some(function (x) { return x.id === r.id; });
    if (method === 'POST' && existe) throw new HttpError(409, 'Ya existe la regla ' + r.id);
    if (method === 'PUT' && !existe) throw new HttpError(404, 'Regla no encontrada');
    await env.DB.batch(guardarReglaStmts(env, r));
    invalidate();
    return json({ ok: true }, method === 'POST' ? 201 : 200);
  }
  if (method === 'DELETE') {
    if (!kb.rules.some(function (x) { return x.id === key; })) throw new HttpError(404, 'Regla no encontrada');
    await env.DB.prepare('DELETE FROM reglas WHERE id = ?').bind(key).run();
    invalidate();
    return json({ ok: true });
  }
  throw new HttpError(405, 'Método no permitido');
}

/* =====================  Enrutamiento  ===================== */

async function route(request, env) {
  const url = new URL(request.url);
  const p = url.pathname;
  const m = request.method;

  if (!p.startsWith('/api/')) {
    return new Response(HTML, { headers: { 'content-type': 'text/html;charset=utf-8' } });
  }
  if (!env.DB) throw new HttpError(500, 'Falta el binding DB (base de datos D1) en el Worker.');
  const kb = await loadKB(env);
  let mt;

  if (p === '/api/info' && m === 'GET') {
    return json({
      sistema: 'Sistema experto para la identificación y diagnóstico de riesgos de seguridad informática',
      base_de_datos: 'Cloudflare D1 (SQL)',
      preguntas: kb.preguntas.length,
      fallas: Object.keys(kb.fallas).length,
      reglas: kb.rules.length
    });
  }
  if (p === '/api/kb' && m === 'GET') return json(kbPublic(kb));
  if (p === '/api/admin/check' && m === 'GET') {
    requireAdmin(request, env);
    return json({ ok: true });
  }
  if (p === '/api/diagnose' && m === 'POST') {
    const body = await readBody(request);
    return json(diagnose(kb, validateAnswers(kb, body.answers)));
  }
  if (p === '/api/stats' && m === 'GET') return estadisticas(env);
  if (p === '/api/diagnoses') {
    if (m === 'GET') return listarCasos(url, env);
    if (m === 'POST') return crearCaso(request, env, kb);
    throw new HttpError(405, 'Método no permitido');
  }
  if ((mt = p.match(/^\/api\/diagnoses\/(\d+)$/))) {
    const id = Number(mt[1]);
    if (m === 'GET') return detalleCaso(id, env);
    requireAdmin(request, env);
    if (m === 'PATCH') return actualizarCaso(id, request, env);
    if (m === 'DELETE') return borrarCaso(id, env);
    throw new HttpError(405, 'Método no permitido');
  }
  if ((mt = p.match(/^\/api\/(fallas|preguntas|reglas)(?:\/([^/]+))?$/))) {
    requireAdmin(request, env);
    const key = mt[2] ? decodeURIComponent(mt[2]) : null;
    if ((m === 'PUT' || m === 'DELETE') && !key) throw new HttpError(400, 'Falta el identificador');
    if (mt[1] === 'fallas') return adminFallas(m, key, request, env, kb);
    if (mt[1] === 'preguntas') return adminPreguntas(m, key, request, env, kb);
    return adminReglas(m, key, request, env, kb);
  }
  throw new HttpError(404, 'Ruta no encontrada');
}

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      return json({ error: 'Error interno: ' + ((e && e.message) || e) }, 500);
    }
  }
};

/* =====================  Interfaz web  ===================== */

const HTML = String.raw`<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sistema experto de seguridad</title>
<style>
  :root { --bg:#f6f7f9; --card:#fff; --ink:#1b1f24; --muted:#5b6672; --line:#dde2e8; --accent:#1f5fbf; --sec:#b42318; --secbg:#fdecea; --op:#1a6b3c; --opbg:#e6f4ec; --warn:#8a5a00; --warnbg:#fff4d6; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#12151a; --card:#1b2027; --ink:#e8ecf1; --muted:#9aa6b2; --line:#2c3440; --accent:#6ea3ff; --sec:#ff9d92; --secbg:#3a1d1a; --op:#7fd6a2; --opbg:#16301f; --warn:#f2c46b; --warnbg:#3a2f12; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  header { padding:1.2rem 1rem .4rem; max-width:960px; margin:0 auto; }
  header h1 { font-size:1.25rem; margin:0 0 .2rem; }
  header p { margin:0; color:var(--muted); font-size:.9rem; }
  nav { max-width:960px; margin:.6rem auto 0; padding:0 1rem; display:flex; gap:.4rem; flex-wrap:wrap; }
  main { max-width:960px; margin:0 auto; padding:1rem; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:1.2rem; margin-bottom:1rem; overflow-x:auto; }
  .tag { font-size:.8rem; color:var(--muted); margin-bottom:.4rem; }
  h2 { font-size:1.15rem; margin:.1rem 0 1rem; }
  h3 { font-size:.95rem; margin:1rem 0 .2rem; }
  .btns { display:flex; gap:.6rem; flex-wrap:wrap; }
  .btns.col { flex-direction:column; }
  button, select, input, textarea { font:inherit; color:var(--ink); }
  button { padding:.55rem 1.1rem; border-radius:8px; border:1px solid var(--line); background:var(--card); cursor:pointer; text-align:left; }
  button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
  button.danger { color:var(--sec); border-color:var(--sec); }
  button.small { padding:.25rem .6rem; font-size:.85rem; }
  button:hover { border-color:var(--accent); }
  button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
  .tab { border-radius:8px 8px 0 0; border-bottom:2px solid transparent; background:transparent; }
  .tab.on { border-bottom-color:var(--accent); font-weight:600; background:var(--card); }
  input, select, textarea { width:100%; padding:.45rem .6rem; border:1px solid var(--line); border-radius:8px; background:var(--bg); }
  textarea { min-height:5rem; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.9rem; }
  label { display:block; font-size:.85rem; color:var(--muted); margin:.7rem 0 .2rem; }
  .badge { display:inline-block; padding:.1rem .6rem; border-radius:99px; font-size:.8rem; font-weight:600; }
  .badge.Seguridad { background:var(--secbg); color:var(--sec); }
  .badge.Operativa { background:var(--opbg); color:var(--op); }
  .badge.abierto { background:var(--warnbg); color:var(--warn); }
  .badge.en_atencion { background:var(--secbg); color:var(--sec); }
  .badge.cerrado { background:var(--opbg); color:var(--op); }
  ul, ol { margin:.3rem 0 .6rem 1.2rem; padding:0; }
  li { margin:.25rem 0; }
  .hist { color:var(--muted); font-size:.9rem; }
  .row { display:flex; gap:.6rem; margin-top:.8rem; flex-wrap:wrap; align-items:center; }
  table { width:100%; border-collapse:collapse; font-size:.9rem; margin-top:.8rem; }
  th, td { text-align:left; padding:.45rem .5rem; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-weight:600; font-size:.8rem; }
  tr.click { cursor:pointer; }
  tr.click:hover { background:var(--bg); }
  .stats { display:flex; gap:.8rem; flex-wrap:wrap; margin-bottom:1rem; }
  .stat { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:.7rem 1rem; min-width:8rem; }
  .stat b { display:block; font-size:1.4rem; }
  .stat span { color:var(--muted); font-size:.8rem; }
  .msg { padding:.6rem .9rem; border-radius:8px; margin:.6rem 0; font-size:.9rem; }
  .msg.ok { background:var(--opbg); color:var(--op); }
  .msg.err { background:var(--secbg); color:var(--sec); }
  .msg.info { background:var(--warnbg); color:var(--warn); }
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:0 1rem; }
  @media (max-width:640px) { .grid2 { grid-template-columns:1fr; } }
  code { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.85em; }
</style>
</head>
<body>
<header>
  <h1>Sistema experto de riesgos de seguridad informática</h1>
  <p>Motor de reglas como servicio en la nube, con base de datos D1.</p>
</header>
<nav id="nav"></nav>
<main id="app"></main>
<script>
(function () {
  var S = { tab: 'diag', steps: [], last: null, token: '', sub: 'fallas', edit: {}, sel: null, filtro: { categoria: '', estado: '' } };
  try { S.token = sessionStorage.getItem('adm') || ''; } catch (e) {}
  var app = document.getElementById('app');
  var nav = document.getElementById('nav');

  function h(tag, a, kids) {
    var e = document.createElement(tag);
    var val;
    a = a || {};
    for (var k in a) {
      if (k === 'class') e.className = a[k];
      else if (k === 'text') e.textContent = a[k];
      else if (k === 'value') val = a[k];
      else if (k.slice(0, 2) === 'on') e[k] = a[k];
      else e.setAttribute(k, a[k]);
    }
    (kids || []).forEach(function (c) {
      if (c !== null && c !== undefined) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    if (val !== undefined) e.value = val;
    return e;
  }

  function api(method, path, body) {
    var hd = { 'content-type': 'application/json' };
    if (S.token) hd['x-admin-token'] = S.token;
    return fetch(path, { method: method, headers: hd, body: body ? JSON.stringify(body) : undefined })
      .then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) { var er = new Error(j.error || ('HTTP ' + r.status)); er.status = r.status; throw er; }
          return j;
        });
      });
  }

  function fecha(s) {
    var d = new Date(String(s).replace(' ', 'T') + 'Z');
    return isNaN(d) ? s : d.toLocaleString('es-CO');
  }
  function msg(type, text) { return h('div', { class: 'msg ' + type, text: text }); }
  function field(label, node) { return h('div', {}, [h('label', { text: label }), node]); }
  function badge(cls, text) { return h('span', { class: 'badge ' + cls, text: text }); }
  function estadoTxt(e) { return e === 'en_atencion' ? 'en atención' : e; }
  function showErr(e) {
    app.innerHTML = '';
    app.appendChild(h('div', { class: 'card' }, [msg('err', e.message || String(e))]));
  }
  function loading() { app.innerHTML = ''; app.appendChild(h('div', { class: 'card', text: 'Cargando...' })); }

  function renderNav() {
    nav.innerHTML = '';
    [['diag', 'Diagnóstico'], ['hist', 'Historial de casos'], ['admin', 'Administración']].forEach(function (x) {
      nav.appendChild(h('button', { class: 'tab' + (S.tab === x[0] ? ' on' : ''), text: x[1], onclick: function () { setTab(x[0]); } }));
    });
  }
  function setTab(t) { S.tab = t; renderNav(); show(); }
  function show() {
    if (S.tab === 'diag') ask();
    else if (S.tab === 'hist') loadHist();
    else loadAdmin();
  }

  /* ---------------- Diagnóstico ---------------- */
  function answersObj() {
    var o = {};
    S.steps.forEach(function (s) { o[s.id] = s.value; });
    return o;
  }
  function ask() {
    loading();
    api('POST', '/api/diagnose', { answers: answersObj() }).then(renderDiag).catch(showErr);
  }
  function answer(q, value, label) {
    S.steps.push({ id: q.id, nodo: q.nodo, texto: q.texto, value: value, label: label });
    ask();
  }
  function historyBox() {
    if (!S.steps.length) return null;
    var ol = h('ol');
    S.steps.forEach(function (s) { ol.appendChild(h('li', { text: s.nodo + ' · ' + s.texto + ' → ' + s.label })); });
    return h('div', { class: 'card hist' }, [h('strong', { text: 'Respuestas dadas' }), ol]);
  }
  function controls() {
    var row = h('div', { class: 'row' });
    if (S.steps.length) row.appendChild(h('button', { text: 'Atrás', onclick: function () { S.steps.pop(); ask(); } }));
    row.appendChild(h('button', { text: 'Reiniciar', onclick: function () { S.steps = []; ask(); } }));
    return row;
  }
  function renderDiag(res) {
    app.innerHTML = '';
    if (res.estado === 'pregunta') {
      var q = res.pregunta;
      var btns = h('div', { class: q.tipo === 'opciones' ? 'btns col' : 'btns' });
      if (q.tipo === 'opciones') {
        q.opciones.forEach(function (o) {
          btns.appendChild(h('button', { text: o.texto, onclick: function () { answer(q, o.valor, o.texto); } }));
        });
      } else {
        btns.appendChild(h('button', { class: 'primary', text: 'Sí', onclick: function () { answer(q, true, 'Sí'); } }));
        btns.appendChild(h('button', { text: 'No', onclick: function () { answer(q, false, 'No'); } }));
      }
      app.appendChild(h('div', { class: 'card' }, [
        h('div', { class: 'tag', text: 'Nodo ' + q.nodo + ' · paso ' + (S.steps.length + 1) }),
        h('h2', { text: q.texto }), btns
      ]));
      var hb = historyBox();
      if (hb) app.appendChild(hb);
      app.appendChild(controls());
      return;
    }
    if (res.estado === 'diagnostico') {
      var d = h('div', { class: 'card' }, [
        h('div', { class: 'tag', text: 'Diagnóstico · regla ' + res.regla }),
        h('h2', { text: res.codigo + ' — ' + res.nombre }),
        badge(res.categoria, res.categoria),
        h('h3', { text: 'Recomendación' }),
        h('p', { text: res.recomendacion })
      ]);
      if (res.razones.length) {
        var ul = h('ul');
        res.razones.forEach(function (t) { ul.appendChild(h('li', { text: t })); });
        d.appendChild(h('h3', { text: 'Por qué se llegó a este diagnóstico' }));
        d.appendChild(ul);
      }
      if (res.acciones.length) {
        var ul2 = h('ul');
        res.acciones.forEach(function (a) { ul2.appendChild(h('li', { text: a.texto })); });
        d.appendChild(h('h3', { text: 'Acciones automáticas' }));
        d.appendChild(ul2);
      }
      app.appendChild(d);
      app.appendChild(saveBox());
      var hb2 = historyBox();
      if (hb2) app.appendChild(hb2);
      var row = h('div', { class: 'row' });
      row.appendChild(h('button', { text: 'Atrás', onclick: function () { S.steps.pop(); ask(); } }));
      row.appendChild(h('button', { class: 'primary', text: 'Nuevo diagnóstico', onclick: function () { S.steps = []; ask(); } }));
      app.appendChild(row);
      return;
    }
    app.appendChild(h('div', { class: 'card', text: res.mensaje || 'Sin diagnóstico.' }));
    app.appendChild(controls());
  }
  function saveBox() {
    var box = h('div', { class: 'card' });
    var titulo = h('input', { placeholder: 'Ej.: Servidor de correo - sede norte', maxlength: '120' });
    var out = h('div');
    var btn = h('button', { class: 'primary', text: 'Guardar caso' });
    btn.onclick = function () {
      btn.disabled = true;
      api('POST', '/api/diagnoses', { answers: answersObj(), titulo: titulo.value }).then(function (r) {
        box.innerHTML = '';
        box.appendChild(msg('ok', 'Caso #' + r.id + ' guardado en la base de datos (' + r.codigo + ' · ' + r.categoria + ').'));
        box.appendChild(h('button', { text: 'Ver historial', onclick: function () { S.sel = r.id; setTab('hist'); } }));
      }).catch(function (e) { btn.disabled = false; out.innerHTML = ''; out.appendChild(msg('err', e.message)); });
    };
    box.appendChild(h('h3', { text: 'Registrar este diagnóstico' }));
    box.appendChild(field('Título del caso (opcional)', titulo));
    box.appendChild(h('div', { class: 'row' }, [btn]));
    box.appendChild(out);
    return box;
  }

  /* ---------------- Historial ---------------- */
  function loadHist() {
    loading();
    var q = '?limit=100';
    if (S.filtro.categoria) q += '&categoria=' + encodeURIComponent(S.filtro.categoria);
    if (S.filtro.estado) q += '&estado=' + encodeURIComponent(S.filtro.estado);
    var jobs = [api('GET', '/api/stats'), api('GET', '/api/diagnoses' + q), S.sel ? api('GET', '/api/diagnoses/' + S.sel).catch(function () { S.sel = null; return null; }) : Promise.resolve(null)];
    Promise.all(jobs).then(renderHist).catch(showErr);
  }
  function statBox(n, label) { return h('div', { class: 'stat' }, [h('b', { text: String(n) }), h('span', { text: label })]); }
  function countOf(arr, key, val) {
    var f = arr.filter(function (x) { return x[key] === val; })[0];
    return f ? f.total : 0;
  }
  function renderHist(r) {
    var stats = r[0], list = r[1], det = r[2];
    app.innerHTML = '';
    app.appendChild(h('div', { class: 'stats' }, [
      statBox(stats.total, 'casos guardados'),
      statBox(countOf(stats.por_categoria, 'categoria', 'Seguridad'), 'de seguridad'),
      statBox(countOf(stats.por_categoria, 'categoria', 'Operativa'), 'operativos'),
      statBox(countOf(stats.por_estado, 'estado', 'abierto') + countOf(stats.por_estado, 'estado', 'en_atencion'), 'sin cerrar')
    ]));

    var cat = h('select', {}, [h('option', { value: '', text: 'Todas las categorías' }), h('option', { value: 'Seguridad', text: 'Seguridad' }), h('option', { value: 'Operativa', text: 'Operativa' })]);
    cat.value = S.filtro.categoria;
    var est = h('select', {}, [h('option', { value: '', text: 'Todos los estados' }), h('option', { value: 'abierto', text: 'Abierto' }), h('option', { value: 'en_atencion', text: 'En atención' }), h('option', { value: 'cerrado', text: 'Cerrado' })]);
    est.value = S.filtro.estado;
    cat.onchange = function () { S.filtro.categoria = cat.value; loadHist(); };
    est.onchange = function () { S.filtro.estado = est.value; loadHist(); };

    var card = h('div', { class: 'card' });
    card.appendChild(h('div', { class: 'grid2' }, [field('Categoría', cat), field('Estado', est)]));
    if (!list.items.length) {
      card.appendChild(msg('info', 'Aún no hay casos guardados. Haz un diagnóstico y usa “Guardar caso”.'));
    } else {
      var tb = h('table', {}, [h('thead', {}, [h('tr', {}, ['#', 'Fecha', 'Caso', 'Falla', 'Categoría', 'Estado'].map(function (t) { return h('th', { text: t }); }))])]);
      var body = h('tbody');
      list.items.forEach(function (c) {
        var tr = h('tr', { class: 'click', onclick: function () { S.sel = c.id; loadHist(); } }, [
          h('td', { text: String(c.id) }), h('td', { text: fecha(c.creado_en) }), h('td', { text: c.titulo || '—' }),
          h('td', { text: c.falla_codigo + ' ' + c.falla_nombre }),
          h('td', {}, [badge(c.categoria, c.categoria)]), h('td', {}, [badge(c.estado, estadoTxt(c.estado))])
        ]);
        body.appendChild(tr);
      });
      tb.appendChild(body);
      card.appendChild(tb);
      card.appendChild(h('p', { class: 'hist', text: 'Mostrando ' + list.items.length + ' de ' + list.total + ' casos.' }));
    }
    app.appendChild(card);
    if (det) app.appendChild(detailCard(det));
  }
  function detailCard(det) {
    var c = det.caso;
    var card = h('div', { class: 'card' }, [
      h('div', { class: 'tag', text: 'Caso #' + c.id + ' · ' + fecha(c.creado_en) + ' · regla ' + c.regla_id }),
      h('h2', { text: c.falla_codigo + ' — ' + c.falla_nombre }),
      h('div', {}, [badge(c.categoria, c.categoria), ' ', badge(c.estado, estadoTxt(c.estado))])
    ]);
    if (c.titulo) card.appendChild(h('p', { text: c.titulo }));
    var ol = h('ol');
    det.respuestas.forEach(function (x) { ol.appendChild(h('li', { text: x.pregunta_texto + ' → ' + x.respuesta })); });
    card.appendChild(h('h3', { text: 'Respuestas registradas' }));
    card.appendChild(ol);
    if (S.token) {
      var est = h('select', {}, [h('option', { value: 'abierto', text: 'Abierto' }), h('option', { value: 'en_atencion', text: 'En atención' }), h('option', { value: 'cerrado', text: 'Cerrado' })]);
      est.value = c.estado;
      var notas = h('textarea', { text: c.notas || '', maxlength: '1000' });
      var out = h('div');
      card.appendChild(h('h3', { text: 'Seguimiento' }));
      card.appendChild(field('Estado', est));
      card.appendChild(field('Notas', notas));
      card.appendChild(h('div', { class: 'row' }, [
        h('button', { class: 'primary', text: 'Guardar cambios', onclick: function () {
          api('PATCH', '/api/diagnoses/' + c.id, { estado: est.value, notas: notas.value }).then(loadHist)
            .catch(function (e) { out.innerHTML = ''; out.appendChild(msg('err', e.message)); });
        } }),
        h('button', { class: 'danger', text: 'Eliminar caso', onclick: function () {
          if (!confirm('¿Eliminar el caso #' + c.id + '?')) return;
          api('DELETE', '/api/diagnoses/' + c.id).then(function () { S.sel = null; loadHist(); })
            .catch(function (e) { out.innerHTML = ''; out.appendChild(msg('err', e.message)); });
        } })
      ]));
      card.appendChild(out);
    } else {
      card.appendChild(h('h3', { text: 'Seguimiento' }));
      card.appendChild(h('p', { text: 'Notas: ' + (c.notas || '—') }));
      card.appendChild(msg('info', 'Para cambiar el estado o eliminar casos, entra en Administración con el token.'));
    }
    card.appendChild(h('div', { class: 'row' }, [h('button', { text: 'Cerrar detalle', onclick: function () { S.sel = null; loadHist(); } })]));
    return card;
  }

  /* ---------------- Administración ---------------- */
  function loadAdmin() {
    if (!S.token) { renderLogin(''); return; }
    loading();
    api('GET', '/api/admin/check').then(function () { return api('GET', '/api/kb'); }).then(renderAdmin).catch(function (e) {
      if (e.status === 401 || e.status === 503) {
        S.token = '';
        try { sessionStorage.removeItem('adm'); } catch (x) {}
        renderLogin(e.message);
      } else showErr(e);
    });
  }
  function renderLogin(error) {
    app.innerHTML = '';
    var t = h('input', { type: 'password', placeholder: 'Token de administrador', autocomplete: 'off' });
    var go = function () {
      S.token = t.value.trim();
      try { sessionStorage.setItem('adm', S.token); } catch (e) {}
      loadAdmin();
    };
    t.onkeydown = function (ev) { if (ev.key === 'Enter') go(); };
    var card = h('div', { class: 'card' }, [h('h2', { text: 'Administración de la base de conocimiento' }),
      h('p', { text: 'Edita preguntas, fallas y reglas, y gestiona el seguimiento de los casos. Requiere el token de administrador.' })]);
    if (error) card.appendChild(msg('err', error));
    card.appendChild(field('Token', t));
    card.appendChild(h('div', { class: 'row' }, [h('button', { class: 'primary', text: 'Entrar', onclick: go })]));
    app.appendChild(card);
  }
  function renderAdmin(kb) {
    app.innerHTML = '';
    var top = h('div', { class: 'row' });
    [['fallas', 'Fallas'], ['reglas', 'Reglas'], ['preguntas', 'Preguntas']].forEach(function (x) {
      top.appendChild(h('button', { class: S.sub === x[0] ? 'primary' : '', text: x[1] + ' (' + kb[x[0]].length + ')', onclick: function () { S.sub = x[0]; S.edit = {}; renderAdmin(kb); } }));
    });
    top.appendChild(h('button', { text: 'Cerrar sesión', onclick: function () {
      S.token = ''; try { sessionStorage.removeItem('adm'); } catch (e) {}
      renderLogin('');
    } }));
    app.appendChild(top);
    if (S.sub === 'fallas') adminFallas(kb);
    else if (S.sub === 'reglas') adminReglas(kb);
    else adminPreguntas(kb);
  }
  function save(kind, isEdit, key, body, out) {
    var path = '/api/' + kind + (isEdit ? '/' + encodeURIComponent(key) : '');
    api(isEdit ? 'PUT' : 'POST', path, body).then(function () { S.edit = {}; loadAdmin(); })
      .catch(function (e) { out.innerHTML = ''; out.appendChild(msg('err', e.message)); });
  }
  function remove(kind, key, label, out) {
    if (!confirm('¿Eliminar ' + label + '?')) return;
    api('DELETE', '/api/' + kind + '/' + encodeURIComponent(key)).then(function () { S.edit = {}; loadAdmin(); })
      .catch(function (e) { out.innerHTML = ''; out.appendChild(msg('err', e.message)); });
  }
  function actions(onEdit, onDel) {
    return h('td', {}, [h('button', { class: 'small', text: 'Editar', onclick: onEdit }), ' ', h('button', { class: 'small danger', text: 'Eliminar', onclick: onDel })]);
  }

  function adminFallas(kb) {
    var e = S.edit.falla || null;
    var out = h('div');
    var codigo = h('input', { value: e ? e.codigo : '', placeholder: 'F-30' });
    if (e) codigo.setAttribute('readonly', 'readonly');
    var nombre = h('input', { value: e ? e.nombre : '' });
    var cat = h('select', {}, [h('option', { value: 'Seguridad', text: 'Seguridad' }), h('option', { value: 'Operativa', text: 'Operativa' })]);
    cat.value = e ? e.categoria : 'Seguridad';
    var rec = h('textarea', { text: e ? e.recomendacion : '' });
    var form = h('div', { class: 'card' }, [h('h2', { text: e ? 'Editar falla ' + e.codigo : 'Nueva falla' }),
      h('div', { class: 'grid2' }, [field('Código', codigo), field('Categoría', cat)]), field('Nombre', nombre), field('Recomendación', rec),
      h('div', { class: 'row' }, [
        h('button', { class: 'primary', text: 'Guardar', onclick: function () { save('fallas', !!e, codigo.value, { codigo: codigo.value, nombre: nombre.value, categoria: cat.value, recomendacion: rec.value }, out); } }),
        e ? h('button', { text: 'Cancelar', onclick: function () { S.edit = {}; renderAdmin(kb); } }) : null
      ]), out]);
    var body = h('tbody');
    kb.fallas.forEach(function (f) {
      body.appendChild(h('tr', {}, [h('td', { text: f.codigo }), h('td', { text: f.nombre }), h('td', {}, [badge(f.categoria, f.categoria)]),
        actions(function () { S.edit = { falla: f }; renderAdmin(kb); }, function () { remove('fallas', f.codigo, 'la falla ' + f.codigo, out); })]));
    });
    app.appendChild(h('div', { class: 'card' }, [h('table', {}, [h('thead', {}, [h('tr', {}, ['Código', 'Nombre', 'Categoría', ''].map(function (t) { return h('th', { text: t }); }))]), body])]));
    app.appendChild(form);
  }

  function resumenRegla(r) {
    var t = [];
    if (r.if_all.length) t.push('TODAS: ' + r.if_all.join(', '));
    if (r.if_any.length) t.push('ALGUNA: ' + r.if_any.map(function (g) { return typeof g === 'string' ? g : '(' + g.if_all.join(' Y ') + ')'; }).join(' O '));
    return t.join(' · ');
  }
  function adminReglas(kb) {
    var e = S.edit.regla || null;
    var out = h('div');
    var id = h('input', { value: e ? e.id : '', placeholder: 'R-30' });
    if (e) id.setAttribute('readonly', 'readonly');
    var orden = h('input', { type: 'number', value: e ? String(e.orden) : '' , placeholder: 'automático' });
    var falla = h('select', {}, kb.fallas.map(function (f) { return h('option', { value: f.codigo, text: f.codigo + ' — ' + f.nombre }); }));
    if (e) falla.value = e.falla_codigo;
    var cond = h('textarea', { text: e ? JSON.stringify({ if_all: e.if_all, if_any: e.if_any }, null, 1) : '{"if_all": ["q1_A", "q2"], "if_any": []}' });
    cond.style.minHeight = '8rem';
    var form = h('div', { class: 'card' }, [h('h2', { text: e ? 'Editar regla ' + e.id : 'Nueva regla' }),
      h('div', { class: 'grid2' }, [field('Id', id), field('Orden de evaluación', orden)]), field('THEN → falla', falla),
      field('Condiciones (JSON)', cond),
      h('p', { class: 'hist', text: 'if_all = condiciones unidas por AND. if_any = alternativas (OR); cada una puede ser {"if_all": [...]}. Usa qN (Sí), qN_no (No) o q1_A (opción). Cada diagnóstico debe depender de al menos 2 preguntas.' }),
      h('div', { class: 'row' }, [
        h('button', { class: 'primary', text: 'Guardar', onclick: function () {
          var c;
          try { c = JSON.parse(cond.value); } catch (x) { out.innerHTML = ''; out.appendChild(msg('err', 'El JSON de condiciones no es válido.')); return; }
          save('reglas', !!e, id.value, { id: id.value, orden: orden.value ? Number(orden.value) : undefined, falla_codigo: falla.value, if_all: c.if_all || [], if_any: c.if_any || [] }, out);
        } }),
        e ? h('button', { text: 'Cancelar', onclick: function () { S.edit = {}; renderAdmin(kb); } }) : null
      ]), out]);
    var body = h('tbody');
    kb.reglas.forEach(function (r) {
      body.appendChild(h('tr', {}, [h('td', { text: String(r.orden) }), h('td', { text: r.id }), h('td', { text: r.falla_codigo }), h('td', { text: resumenRegla(r) }),
        actions(function () { S.edit = { regla: r }; renderAdmin(kb); }, function () { remove('reglas', r.id, 'la regla ' + r.id, out); })]));
    });
    app.appendChild(h('div', { class: 'card' }, [h('table', {}, [h('thead', {}, [h('tr', {}, ['Orden', 'Regla', 'THEN', 'IF', ''].map(function (t) { return h('th', { text: t }); }))]), body])]));
    app.appendChild(form);
  }

  function adminPreguntas(kb) {
    var e = S.edit.pregunta || null;
    var out = h('div');
    var id = h('input', { value: e ? e.id : '', placeholder: 'q30' });
    if (e) id.setAttribute('readonly', 'readonly');
    var nodo = h('input', { value: e ? e.nodo : '', placeholder: 'N-30' });
    var texto = h('textarea', { text: e ? e.texto : '' });
    texto.style.minHeight = '3.5rem';
    var ops = h('textarea', { text: e ? e.opciones.map(function (o) { return o.valor + '|' + o.texto; }).join('\n') : '' });
    var form = h('div', { class: 'card' }, [h('h2', { text: e ? 'Editar pregunta ' + e.id : 'Nueva pregunta' }),
      h('div', { class: 'grid2' }, [field('Id', id), field('Nodo del árbol', nodo)]), field('Texto', texto),
      field('Opciones (solo si no es Sí/No): una por línea, formato LETRA|texto', ops),
      h('div', { class: 'row' }, [
        h('button', { class: 'primary', text: 'Guardar', onclick: function () {
          var lista = ops.value.split('\n').map(function (l) { return l.trim(); }).filter(Boolean).map(function (l) {
            var i = l.indexOf('|');
            return { valor: i < 0 ? l : l.slice(0, i).trim(), texto: i < 0 ? '' : l.slice(i + 1).trim() };
          });
          save('preguntas', !!e, id.value, { id: id.value, nodo: nodo.value, texto: texto.value, opciones: lista }, out);
        } }),
        e ? h('button', { text: 'Cancelar', onclick: function () { S.edit = {}; renderAdmin(kb); } }) : null
      ]), out]);
    var body = h('tbody');
    kb.preguntas.forEach(function (q) {
      body.appendChild(h('tr', {}, [h('td', { text: q.nodo }), h('td', { text: q.id }), h('td', { text: q.texto }), h('td', { text: q.tipo === 'opciones' ? 'opciones' : 'Sí/No' }),
        actions(function () { S.edit = { pregunta: q }; renderAdmin(kb); }, function () { remove('preguntas', q.id, 'la pregunta ' + q.id, out); })]));
    });
    app.appendChild(h('div', { class: 'card' }, [h('table', {}, [h('thead', {}, [h('tr', {}, ['Nodo', 'Id', 'Pregunta', 'Tipo', ''].map(function (t) { return h('th', { text: t }); }))]), body])]));
    app.appendChild(form);
  }

  renderNav();
  show();
})();
</script>
</body>
</html>`;

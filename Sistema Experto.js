
const CACHE_MS = 30000;
let cache = { kb: null, at: 0 };

async function loadKB(env) {
  const now = Date.now();
  if (cache.kb && now - cache.at < CACHE_MS) return cache.kb;
  const kb = await env.KB.get('rules', 'json');
  if (!kb) throw new Error("No se encontró la clave 'rules' en el KV (binding KB).");
  cache = { kb: kb, at: now };
  return kb;
}


function parseToken(t) {
  const m = /^q(\d+)(?:_(no|[A-Z]))?$/.exec(t);
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
  const opciones = Object.keys(kb.hechos)
    .filter(function (k) { return new RegExp('^' + id + '_[A-Z]$').test(k); })
    .map(function (k) {
      return {
        valor: k.split('_')[1],
        texto: kb.hechos[k].replace(/^El síntoma principal es /, '')
      };
    });
  return {
    id: id,
    nodo: (kb.nodos && kb.nodos[id]) || ('N-' + String(n).padStart(2, '0')),
    texto: kb.questions[id],
    tipo: opciones.length ? 'opciones' : 'si_no',
    opciones: opciones
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
      const falla = (kb.fallas && kb.fallas[rule.then]) || {};
      const razones = [];
      flatTokens(rule, []).forEach(function (t) {
        if (tokenValue(t, answers) === true && kb.hechos[t] && razones.indexOf(kb.hechos[t]) < 0) {
          razones.push(kb.hechos[t]);
        }
      });
      const categoria = falla.categoria || null;
      const acciones = (kb.post_rules || [])
        .filter(function (pr) {
          return (pr.if_any || []).indexOf('categoria=' + categoria) >= 0;
        })
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



const HTML = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sistema experto de seguridad</title>
<style>
  :root { --bg:#f6f7f9; --card:#fff; --ink:#1b1f24; --muted:#5b6672; --line:#dde2e8; --accent:#1f5fbf; --sec:#b42318; --secbg:#fdecea; --op:#1a6b3c; --opbg:#e6f4ec; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#12151a; --card:#1b2027; --ink:#e8ecf1; --muted:#9aa6b2; --line:#2c3440; --accent:#6ea3ff; --sec:#ff9d92; --secbg:#3a1d1a; --op:#7fd6a2; --opbg:#16301f; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  header { padding:1.2rem 1rem .4rem; max-width:720px; margin:0 auto; }
  header h1 { font-size:1.25rem; margin:0 0 .2rem; }
  header p { margin:0; color:var(--muted); font-size:.9rem; }
  main { max-width:720px; margin:0 auto; padding:1rem; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:1.2rem; margin-bottom:1rem; }
  .tag { font-size:.8rem; color:var(--muted); margin-bottom:.4rem; }
  h2 { font-size:1.15rem; margin:.1rem 0 1rem; }
  .btns { display:flex; gap:.6rem; flex-wrap:wrap; }
  .btns.col { flex-direction:column; }
  button { font:inherit; padding:.6rem 1.2rem; border-radius:8px; border:1px solid var(--line); background:var(--card); color:var(--ink); cursor:pointer; text-align:left; }
  button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
  button:hover { border-color:var(--accent); }
  button:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
  .badge { display:inline-block; padding:.1rem .6rem; border-radius:99px; font-size:.8rem; font-weight:600; }
  .badge.Seguridad { background:var(--secbg); color:var(--sec); }
  .badge.Operativa { background:var(--opbg); color:var(--op); }
  ul, ol { margin:.3rem 0 .6rem 1.2rem; padding:0; }
  li { margin:.25rem 0; }
  h3 { font-size:.95rem; margin:1rem 0 .2rem; }
  .hist { color:var(--muted); font-size:.9rem; }
  .row { display:flex; gap:.6rem; margin-top:.8rem; flex-wrap:wrap; }
</style>
</head>
<body>
<header>
  <h1>Sistema experto de riesgos de seguridad informática</h1>
  <p>Responde las preguntas y el motor de reglas (servicio en la nube) entregará el diagnóstico.</p>
</header>
<main id="app"></main>
<script>
var steps = [];
var app = document.getElementById('app');

function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function answersObj() {
  var o = {};
  steps.forEach(function (s) { o[s.id] = s.value; });
  return o;
}

function ask() {
  app.innerHTML = '';
  app.appendChild(el('div', 'card', 'Consultando el sistema experto...'));
  fetch('/api/diagnose', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ answers: answersObj() })
  })
    .then(function (r) { return r.json(); })
    .then(render)
    .catch(function () {
      app.innerHTML = '';
      app.appendChild(el('div', 'card', 'No se pudo contactar el servicio. Intenta de nuevo.'));
    });
}

function answer(q, value, label) {
  steps.push({ id: q.id, nodo: q.nodo, texto: q.texto, value: value, label: label });
  ask();
}

function history() {
  if (!steps.length) return null;
  var box = el('div', 'card hist');
  box.appendChild(el('strong', '', 'Respuestas dadas'));
  var ol = el('ol');
  steps.forEach(function (s) {
    ol.appendChild(el('li', '', s.nodo + ' · ' + s.texto + ' → ' + s.label));
  });
  box.appendChild(ol);
  return box;
}

function controls(withBack) {
  var row = el('div', 'row');
  if (withBack && steps.length) {
    var b = el('button', '', 'Atrás');
    b.onclick = function () { steps.pop(); ask(); };
    row.appendChild(b);
  }
  var r = el('button', '', 'Reiniciar');
  r.onclick = function () { steps = []; ask(); };
  row.appendChild(r);
  return row;
}

function render(res) {
  app.innerHTML = '';
  if (res.error) {
    app.appendChild(el('div', 'card', 'Error del servicio: ' + res.error));
    return;
  }
  if (res.estado === 'pregunta') {
    var q = res.pregunta;
    var card = el('div', 'card');
    card.appendChild(el('div', 'tag', 'Nodo ' + q.nodo + ' · paso ' + (steps.length + 1)));
    card.appendChild(el('h2', '', q.texto));
    var btns = el('div', q.tipo === 'opciones' ? 'btns col' : 'btns');
    if (q.tipo === 'opciones') {
      q.opciones.forEach(function (o) {
        var b = el('button', '', o.texto);
        b.onclick = function () { answer(q, o.valor, o.texto); };
        btns.appendChild(b);
      });
    } else {
      var yes = el('button', 'primary', 'Sí');
      yes.onclick = function () { answer(q, true, 'Sí'); };
      var no = el('button', '', 'No');
      no.onclick = function () { answer(q, false, 'No'); };
      btns.appendChild(yes);
      btns.appendChild(no);
    }
    card.appendChild(btns);
    app.appendChild(card);
    var h = history();
    if (h) app.appendChild(h);
    app.appendChild(controls(true));
    return;
  }
  if (res.estado === 'diagnostico') {
    var d = el('div', 'card');
    d.appendChild(el('div', 'tag', 'Diagnóstico · regla ' + res.regla));
    d.appendChild(el('h2', '', res.codigo + ' — ' + res.nombre));
    d.appendChild(el('span', 'badge ' + res.categoria, res.categoria));
    d.appendChild(el('h3', '', 'Recomendación'));
    d.appendChild(el('p', '', res.recomendacion));
    if (res.razones.length) {
      d.appendChild(el('h3', '', 'Por qué se llegó a este diagnóstico'));
      var ul = el('ul');
      res.razones.forEach(function (t) { ul.appendChild(el('li', '', t)); });
      d.appendChild(ul);
    }
    if (res.acciones.length) {
      d.appendChild(el('h3', '', 'Acciones automáticas'));
      var ul2 = el('ul');
      res.acciones.forEach(function (a) { ul2.appendChild(el('li', '', a.texto)); });
      d.appendChild(ul2);
    }
    app.appendChild(d);
    var h2 = history();
    if (h2) app.appendChild(h2);
    var row = el('div', 'row');
    var back = el('button', '', 'Atrás');
    back.onclick = function () { steps.pop(); ask(); };
    row.appendChild(back);
    var again = el('button', 'primary', 'Nuevo diagnóstico');
    again.onclick = function () { steps = []; ask(); };
    row.appendChild(again);
    app.appendChild(row);
    return;
  }
  var c = el('div', 'card', res.mensaje || 'Sin diagnóstico.');
  app.appendChild(c);
  app.appendChild(controls(true));
}

ask();
</script>
</body>
</html>`;


function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'content-type': 'application/json;charset=utf-8', 'cache-control': 'no-store' }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/diagnose') {
      let kb;
      try {
        kb = await loadKB(env);
      } catch (e) {
        return json({ error: String(e.message || e) }, 500);
      }

      if (request.method === 'GET') {
        return json({
          sistema: kb.sistema,
          preguntas: Object.keys(kb.questions).length,
          fallas: Object.keys(kb.fallas).length,
          reglas: kb.rules.length
        });
      }

      if (request.method === 'POST') {
        let body;
        try {
          body = await request.json();
        } catch (e) {
          return json({ error: 'JSON inválido' }, 400);
        }
        const answers = body && typeof body.answers === 'object' && body.answers ? body.answers : {};
        return json(diagnose(kb, answers));
      }

      return json({ error: 'Método no permitido' }, 405);
    }

    return new Response(HTML, {
      headers: { 'content-type': 'text/html;charset=utf-8' }
    });
  }
};
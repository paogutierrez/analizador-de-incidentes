const SEV = ["Crítico", "Alto", "Medio", "Bajo"],
  CAT = [
    "Fuerza bruta",
    "Inicios sospechosos",
    "Escalamiento",
    "Comandos y procesos",
    "Movimiento lateral",
    "Otras anomalías",
  ];
let D = [],
  F = [],
  INC = [],
  AIS = "",
  ch = [],
  tab = "carga",
  sevF = null,
  fname = "";
const $ = (s) => document.querySelector(s),
  esc = (s) =>
    String(s ?? "").replace(
      /[&<>"]/g,
      (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c],
    );
const cv = (n) =>
    getComputedStyle(document.documentElement)
      .getPropertyValue("--" + n)
      .trim(),
  SC = (s) => cv({ Crítico: "C", Alto: "A", Medio: "M", Bajo: "B" }[s]);
const hh = (t) => new Date(t).toTimeString().slice(0, 8),
  isExt = (ip) =>
    !!ip && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip),
  isIP = (d) => /^\d+\.\d+\.\d+\.\d+/.test(d || ""),
  by = (a, f) => {
    const m = {};
    a.forEach((r) => (m[f(r)] ??= []).push(r));
    return Object.values(m);
  },
  sv = (s) => SEV.indexOf(s);
/* Conocimiento técnico genérico (no son hallazgos): explicación y acciones por tipo de regla */
const K = {
  brute: [
    "Múltiples autenticaciones fallidas (4625) desde un mismo origen indican adivinación de credenciales.",
    "Bloquear la IP en perímetro|Restablecer credenciales de las cuentas afectadas y forzar MFA|Revisar bloqueo de cuentas y política de contraseñas",
  ],
  susp: [
    "Sesión iniciada desde una IP fuera del rango interno, tras intentos fallidos: patrón de uso de credenciales válidas obtenidas (T1078).",
    "Invalidar sesiones y credenciales de la cuenta|Restringir acceso remoto (RDP/VPN) a orígenes autorizados|Revisar toda la actividad de la cuenta posterior al acceso",
  ],
  priv: [
    "Asignación de privilegios especiales (4672) a una sesión originada externamente sugiere acceso con permisos elevados.",
    "Revisar pertenencia a grupos privilegiados|Rotar credenciales de cuentas privilegiadas|Aplicar mínimo privilegio y cuentas administrativas dedicadas",
  ],
  persist: [
    "Tarea programada/servicio instalado desde ruta de usuario o ProgramData es un mecanismo de persistencia habitual (T1053/T1543).",
    "Eliminar la tarea y el servicio|Aislar el host y preservar el binario para análisis|Buscar el mismo artefacto en otros hosts",
  ],
  web: [
    "Alto volumen de peticiones a rutas administrativas/de subida con errores 404/500 y ejecución de cmd.exe por el proceso web indican explotación o web shell (T1505.003).",
    "Aislar WEB-01 y revisar /uploads|Bloquear la IP origen|Parchear/validar la subida de archivos y revisar el WAF",
  ],
  enc: [
    "PowerShell con -EncodedCommand oculta el contenido ejecutado (T1059.001).",
    "Recuperar y decodificar el comando (ScriptBlock 4104)|Aislar el host|Habilitar Constrained Language Mode y logging de PowerShell",
  ],
  vss: [
    "Eliminar copias de sombra impide la recuperación y es típico de preparación de ransomware (T1490).",
    "Aislar el host de inmediato|Verificar la integridad de los backups offline|Activar el plan de respuesta a ransomware",
  ],
  stage: [
    "Compresión de archivos en rutas temporales/públicas es típica de staging previo a exfiltración (T1560).",
    "Localizar y preservar los archivos comprimidos|Identificar los datos incluidos y su clasificación|Evaluar notificación según normativa aplicable",
  ],
  recon: [
    "Comandos de enumeración de grupos locales, recursos compartidos y usuario son reconocimiento posterior al acceso (T1087/T1135).",
    "Revisar qué cuentas y equipos ejecutaron enumeración|Limitar la enumeración SMB/NetBIOS",
  ],
  odd: [
    "Ejecución desde rutas escribibles por el usuario es indicativa de software no autorizado (T1036).",
    "Obtener hash y analizar el binario|Aplicar lista blanca de aplicaciones",
  ],
  lat: [
    "Inicio de sesión de red (tipo 3) con una cuenta ya comprometida, desde otro servidor, seguido de acceso a recursos compartidos: movimiento lateral (T1021).",
    "Aislar los servidores implicados|Rotar credenciales de la cuenta|Segmentar la red y restringir SMB entre servidores",
  ],
  out: [
    "Conexión saliente a IP externa por PowerShell, posterior a staging, es compatible con exfiltración o C2 (T1041).",
    "Bloquear la IP/puerto de destino|Capturar tráfico y revisar volumen transferido|Revisar reglas de egress",
  ],
  exf: [
    "Múltiples POST HTTPS hacia un mismo destino externo con gran volumen indican exfiltración de datos (T1567/T1041).",
    "Bloquear el destino en proxy|Determinar los datos exfiltrados (Legal) y notificar según corresponda|Investigar la cuenta y el equipo origen",
  ],
  mass: [
    "Acceso a muchos archivos en poco tiempo es un patrón de recolección masiva (T1039).",
    "Verificar con el propietario de la cuenta si es actividad legítima|Revisar las ACL del recurso compartido",
  ],
  dq: [
    "Inconsistencias de nomenclatura en la fuente dificultan la correlación.",
    "Normalizar hostnames en el SIEM",
  ],
  sub: [
    "El SIEM marcó como informativos eventos que forman parte de actividad sospechosa.",
    "Ajustar reglas de severidad del SIEM",
  ],
};
function analyze() {
  F = [];
  const used = new Set(),
    add = (o) => {
      const s = new Set();
      o.rows = o.rows
        .filter((r) => !s.has(r.Log_ID) && s.add(r.Log_ID))
        .sort((a, b) => a.t - b.t);
      o.t0 = o.rows[0].t;
      o.t1 = o.rows.at(-1).t;
      o.id = "H" + String(F.length + 1).padStart(2, "0");
      o.exp = K[o.k][0];
      o.plan = K[o.k][1].split("|");
      F.push(o);
    };
  const R = (id, f = () => 1) => D.filter((r) => r.Event_ID == id && f(r));
  /* 1 Fuerza bruta */
  by(R("4625"), (r) => r.Source_IP).forEach((g) => {
    const ip = g[0].Source_IP,
      ex = isExt(ip);
    if (
      !(ex
        ? g.length >= 3
        : g.some(
            (r) => g.filter((x) => x.t >= r.t && x.t - r.t <= 6e5).length >= 5,
          ))
    )
      return;
    const us = [...new Set(g.map((r) => r.User))],
      last = g.at(-1).t,
      ok = R(
        "4624",
        (r) => r.Source_IP == ip && r.t >= g[0].t && r.t - last <= 18e5,
      ),
      sp = us.length >= 5;
    add({
      k: "brute",
      cat: "Fuerza bruta",
      title:
        (sp ? "Password spraying desde " : "Fuerza bruta RDP/logon desde ") +
        ip,
      sev: ok.length ? "Crítico" : ex ? "Alto" : "Medio",
      mitre: sp ? "T1110.003" : "T1110.001",
      rows: [...g, ...ok],
      act: [ip, ...ok.map((r) => r.User)],
      desc:
        `${g.length} fallos 4625 desde ${ip} contra ${us.length} cuenta(s) [${us.join(", ")}] en ${[...new Set(g.map((r) => r.Hostname))].join(", ")} entre ${hh(g[0].t)} y ${hh(last)}.` +
        (ok.length
          ? ` A las ${hh(ok[0].t)} hay un 4624 exitoso de ${ok[0].User} desde la misma IP.`
          : " Sin acceso exitoso posterior desde esa IP."),
      why:
        `${g.length} fallos${ex ? " desde IP externa" : ""}` +
        (ok.length
          ? `; seguido de logon exitoso (${ok[0].Log_ID}) → acceso confirmado`
          : "; sin acceso exitoso observado"),
    });
  });
  /* 2-3 Inicios sospechosos y escalamiento por IP externa */
  [
    ...new Set(
      D.filter((r) => r.Event_ID == "4624" && isExt(r.Source_IP)).map(
        (r) => r.Source_IP,
      ),
    ),
  ].forEach((ip) => {
    const ok = R("4624", (r) => r.Source_IP == ip),
      pr = R("4672", (r) => r.Source_IP == ip),
      us = [...new Set(ok.map((r) => r.User))];
    add({
      k: "susp",
      cat: "Inicios sospechosos",
      title: `Logon exitoso desde IP externa ${ip}`,
      sev: "Alto",
      mitre: "T1078",
      rows: ok,
      act: [ip, ...us],
      desc: `${ok.length} logon(s) 4624 de ${us.join(", ")} desde ${ip} (fuera del rango interno 10.10.x.x) en ${[...new Set(ok.map((r) => r.Hostname))].join(", ")}: ${ok.map((r) => hh(r.t) + " " + (r.Event_Description.match(/LogonType=\d+/) || [""])[0]).join("; ")}.`,
      why: "Origen no pertenece a la red interna; ver correlación con fuerza bruta",
    });
    if (pr.length)
      add({
        k: "priv",
        cat: "Escalamiento",
        title: `Privilegios especiales asignados a sesión externa (${pr[0].User})`,
        sev: "Crítico",
        mitre: "T1078.002",
        rows: pr,
        act: [ip, ...pr.map((r) => r.User)],
        desc: `${pr.length} evento(s) 4672 para ${[...new Set(pr.map((r) => r.User))].join(", ")} originados en ${ip}, en ${[...new Set(pr.map((r) => r.Hostname))].join(", ")} (${pr.map((r) => hh(r.t)).join(", ")}).`,
        why: "Privilegios elevados otorgados a una sesión cuyo origen es externo",
      });
  });
  /* Persistencia */
  R("4698")
    .concat(R("7045"))
    .filter((r) =>
      /ProgramData|\\Temp\\|Public|AppData/i.test(r.Process_CommandLine),
    )
    .forEach((r) => {
      const img = (r.Process_CommandLine.match(/ImagePath=([^;]+)/) || [])[1],
        ex = img
          ? R("4688", (x) =>
              x.Process_CommandLine.toLowerCase().includes(img.toLowerCase()),
            )
          : [];
      ex.forEach((x) => used.add(x.Log_ID));
      add({
        k: "persist",
        cat: "Escalamiento",
        title:
          "Persistencia: " +
          (r.Event_ID == "7045" ? "servicio instalado" : "tarea programada"),
        sev: "Alto",
        mitre: r.Event_ID == "7045" ? "T1543.003" : "T1053.005",
        rows: [r, ...ex],
        act: [r.User, r.Source_IP],
        desc:
          `${r.Event_Description} por ${r.User} en ${r.Hostname} a las ${hh(r.t)}: ${r.Process_CommandLine}.` +
          (ex.length
            ? ` El binario se ejecutó ${ex.length} veces (${ex.map((x) => hh(x.t)).join(", ")}).`
            : ""),
        why:
          "Ruta no estándar (ProgramData)" +
          (ex.length ? ` y ${ex.length} ejecuciones posteriores` : ""),
      });
    });
  /* Web */
  by(R("HTTP_ACCESS"), (r) => r.Source_IP).forEach((g) => {
    if (g.length < 10) return;
    const ip = g[0].Source_IP,
      sh = R(
        "4688",
        (r) =>
          /^IIS APPPOOL/i.test(r.User) &&
          /cmd\.exe|powershell/i.test(r.Process_CommandLine) &&
          r.Hostname == g[0].Hostname &&
          r.t >= g[0].t,
      );
    sh.forEach((r) => used.add(r.Log_ID));
    const c = (x) => g.filter((r) => r.Result == x).length;
    add({
      k: "web",
      cat: "Comandos y procesos",
      title: `Actividad web sospechosa / posible web shell desde ${ip}`,
      sev: sh.length ? "Crítico" : "Alto",
      mitre: "T1505.003",
      rows: [...g, ...sh],
      act: [ip],
      desc:
        `${g.length} peticiones HTTP desde ${ip} a ${g[0].Hostname} entre ${hh(g[0].t)} y ${hh(g.at(-1).t)} (200:${c("200")}, 404:${c("404")}, 500:${c("500")}) a rutas: ${[...new Set(g.map((r) => r.Process_CommandLine.split("?")[0]))].join(", ")}; usuario "-" (sin autenticar).` +
        (sh.length
          ? ` Después, ${sh[0].User} ejecutó «${sh[0].Process_CommandLine}» a las ${hh(sh[0].t)}.`
          : ""),
      why:
        `${g.length} peticiones con errores` +
        (sh.length
          ? "; el proceso web ejecutó cmd.exe → ejecución de comandos"
          : ""),
    });
  });
  /* Comandos */
  const P = [
    [
      /-EncodedCommand/i,
      "enc",
      "PowerShell con comando codificado",
      "Alto",
      "T1059.001",
    ],
    [
      /vssadmin.*delete\s+shadows/i,
      "vss",
      "Eliminación de copias de sombra (vssadmin)",
      "Crítico",
      "T1490",
    ],
    [
      /\b(tar|7z|rar|zip)(\.exe)?\b.*(\\Temp\\|\\Public\\)/i,
      "stage",
      "Compresión de archivos (posible staging)",
      "Alto",
      "T1560.001",
    ],
    [
      /Get-LocalGroupMember|Get-SmbShare|net(\.exe)?\s+view|\bwhoami\b/i,
      "recon",
      "Reconocimiento de sistema/red",
      "Medio",
      "T1087 / T1135",
    ],
    [
      /\\(ProgramData|Users\\Public|AppData)\\[^\s]*\.exe/i,
      "odd",
      "Ejecución desde ruta inusual",
      "Alto",
      "T1036",
    ],
  ];
  const cm = D.filter(
    (r) => /^(4688|4104)$/.test(r.Event_ID) && !used.has(r.Log_ID),
  )
    .map((r) => [
      r,
      P.find((p) =>
        p[0].test(r.Process_CommandLine + " " + r.Event_Description),
      ),
    ])
    .filter((x) => x[1]);
  by(cm, (x) => x[1][1] + x[0].Hostname + x[0].User).forEach((g) => {
    const p = g[0][1],
      rs = g.map((x) => x[0]),
      r = rs[0];
    add({
      k: p[1],
      cat: "Comandos y procesos",
      title: `${p[2]} (${r.User} en ${r.Hostname})`,
      sev: p[3],
      mitre: p[4],
      rows: rs,
      act: [r.User, r.Source_IP],
      desc: rs
        .map(
          (x) =>
            `${hh(x.t)} ${x.Log_ID}: ${x.Process_CommandLine || x.Event_Description}`,
        )
        .join(" | "),
      why: `Patrón de comando asociado a ${p[4]}`,
    });
  });
  /* Movimiento lateral */
  const comp = new Set(R("4624", (r) => isExt(r.Source_IP)).map((r) => r.User));
  R(
    "4624",
    (r) =>
      /LogonType=3/.test(r.Event_Description) &&
      !isExt(r.Source_IP) &&
      comp.has(r.User),
  ).forEach((r) => {
    const pre = R(
        "4625",
        (x) =>
          x.User == r.User &&
          x.Hostname == r.Hostname &&
          x.t < r.t &&
          r.t - x.t <= 6e5,
      ),
      po = D.filter(
        (x) =>
          /^(5145|5140|4663)$/.test(x.Event_ID) &&
          x.User == r.User &&
          x.Hostname == r.Hostname &&
          x.t >= r.t &&
          x.t - r.t <= 18e5,
      ),
      src =
        (r.Event_Description.match(/source=([\w-]+)/) || [])[1] || r.Source_IP;
    add({
      k: "lat",
      cat: "Movimiento lateral",
      title: `${src} → ${r.Hostname} con cuenta comprometida ${r.User}`,
      sev: "Crítico",
      mitre: "T1021.002",
      rows: [...pre, r, ...po],
      act: [r.User, r.Source_IP],
      desc: `${r.User}, que antes inició sesión desde IP externa, hace logon de red (tipo 3) en ${r.Hostname} a las ${hh(r.t)} (${pre.length} fallo previo) y luego accede a: ${po.map((x) => x.Event_Description + (x.Destination ? " " + x.Destination : "")).join("; ") || "sin accesos posteriores"}.`,
      why:
        "Cuenta con acceso externo previo salta a otro servidor y accede a datos" +
        (po.length ? " (Finance)" : ""),
    });
  });
  /* Salida a internet */
  const stg = D.filter(
    (r) =>
      /\b(tar|7z)\b/i.test(r.Process_CommandLine) &&
      /\\Temp\\|\\Public\\/.test(r.Process_CommandLine),
  );
  by(
    R("5156", (r) => isIP(r.Destination) && isExt(r.Destination.split(":")[0])),
    (r) => r.User + r.Destination,
  ).forEach((g) => {
    const r = g[0],
      pre = stg.filter(
        (x) => x.User == r.User && x.t < r.t && r.t - x.t <= 9e5,
      );
    add({
      k: "out",
      cat: "Movimiento lateral",
      title: `Conexión saliente a ${r.Destination} (${r.User})`,
      sev: pre.length ? "Crítico" : "Alto",
      mitre: "T1041",
      rows: [...g, ...pre],
      act: [r.User, r.Source_IP],
      desc:
        `${g.length} conexión(es) permitida(s) a ${r.Destination} desde ${r.Hostname} a las ${hh(r.t)}: ${r.Event_Description}.` +
        (pre.length
          ? ` ${Math.round((r.t - pre[0].t) / 6e4)} min antes se ejecutó «${pre[0].Process_CommandLine}».`
          : ""),
      why: "Destino externo" + (pre.length ? " tras staging de archivos" : ""),
    });
  });
  /* Exfiltración proxy */
  by(R("PROXY_ACCESS"), (r) => r.User + r.Destination).forEach((g) => {
    if (g.length < 5) return;
    const r = g[0],
      b = g.reduce(
        (s, x) =>
          s + +(x.Process_CommandLine.match(/bytes_out=(\d+)/) || [0, 0])[1],
        0,
      ),
      mb = b / 1048576,
      pre = stg.filter(
        (x) => x.User == r.User && x.t < r.t && r.t - x.t <= 36e5,
      );
    add({
      k: "exf",
      cat: "Otras anomalías",
      title: `Exfiltración probable: ${g.length} POST a ${r.Destination} (${mb.toFixed(0)} MB)`,
      sev: mb >= 100 ? "Crítico" : "Alto",
      mitre: "T1567",
      rows: [
        ...g,
        ...pre,
        ...R(
          "5140",
          (x) =>
            x.User == r.User &&
            x.t < r.t &&
            r.t - x.t <= 36e5 &&
            /Legal|Finance/.test(x.Destination),
        ),
      ],
      act: [r.User, r.Source_IP],
      desc:
        `${r.User} (${r.Hostname}) envió ${g.length} POST HTTPS a ${r.Destination} entre ${hh(g[0].t)} y ${hh(g.at(-1).t)}; total bytes_out=${b.toLocaleString("es")} (${mb.toFixed(1)} MB).` +
        (pre.length
          ? ` Precedido por «${pre[0].Process_CommandLine}» a las ${hh(pre[0].t)}.`
          : ""),
      why:
        `${mb.toFixed(0)} MB a destino externo` +
        (pre.length ? " tras compresión de datos" : ""),
    });
  });
  /* Acceso masivo */
  by(R("4663"), (r) => r.User + r.Hostname).forEach((g) => {
    if (g.length >= 10 && g.at(-1).t - g[0].t <= 9e5)
      add({
        k: "mass",
        cat: "Otras anomalías",
        title: `Acceso masivo a archivos (${g[0].User}, ${g.length} archivos)`,
        sev: "Alto",
        mitre: "T1039",
        rows: g,
        act: [g[0].User, g[0].Source_IP],
        desc: `${g.length} accesos 4663 a ${g[0].Process_CommandLine.split("\\")[0].replace("File access: ", "")} por ${g[0].User} en ${hh(g[0].t)}–${hh(g.at(-1).t)} (1 archivo cada ~${Math.round((g.at(-1).t - g[0].t) / (g.length - 1) / 1e3)} s).`,
        why: `${g.length} archivos en ${Math.round((g.at(-1).t - g[0].t) / 6e4)} min`,
      });
  });
  /* Calidad de datos / subclasificación (sin incidente) */
  const hv = by(D, (r) => r.Hostname.replace(/[-_]/g, "").toUpperCase()).filter(
    (g) => new Set(g.map((r) => r.Hostname)).size > 1,
  );
  hv.forEach((g) =>
    add({
      k: "dq",
      cat: "Otras anomalías",
      title: `Nomenclatura inconsistente de hosts: ${[...new Set(g.map((r) => r.Hostname))].join(" / ")}`,
      sev: "Bajo",
      mitre: "—",
      rows: g,
      act: [],
      desc: `El mismo equipo aparece con distintos nombres (${[...new Set(g.map((r) => r.Hostname + ": " + g.filter((x) => x.Hostname == r.Hostname).length))].join(", ")} eventos). Puede afectar la correlación.`,
      why: "Problema de calidad de datos, sin evidencia de ataque",
    }),
  );
  const inf = new Set(
    F.filter((f) => f.sev != "Bajo")
      .flatMap((f) => f.rows)
      .filter((r) => r.Severity == "Informational")
      .map((r) => r.Log_ID),
  );
  if (inf.size)
    add({
      k: "sub",
      cat: "Otras anomalías",
      title: `${inf.size} eventos de actividad sospechosa clasificados como Informational en el SIEM`,
      sev: "Bajo",
      mitre: "—",
      rows: D.filter((r) => inf.has(r.Log_ID)),
      act: [],
      desc: `Eventos incluidos en hallazgos Medio–Crítico pero con Severity=Informational en la exportación (p. ej. ${[...inf].slice(0, 5).join(", ")}).`,
      why: "Deficiencia de reglas de severidad del SIEM",
    });
  /* Correlación en incidentes (unión por IP/cuenta actora) */
  const par = {},
    fd = (x) => (par[x] === x ? x : (par[x] = fd(par[x])));
  F.forEach((f) => {
    f.act.forEach((a) => (par[a] ??= a));
    f.act.slice(1).forEach((a) => (par[fd(a)] = fd(f.act[0])));
  });
  const gr = {};
  F.filter((f) => f.act.length).forEach((f) =>
    (gr[fd(f.act[0])] ??= []).push(f),
  );
  INC = Object.values(gr)
    .map((fs) => {
      fs.sort((a, b) => sv(a.sev) - sv(b.sev) || a.t0 - b.t0);
      const rows = fs.flatMap((f) => f.rows);
      const ioc = new Set();
      rows.forEach((r) => {
        if (isExt(r.Source_IP)) ioc.add("IP " + r.Source_IP);
        if (isIP(r.Destination) && isExt(r.Destination.split(":")[0]))
          ioc.add("IP destino " + r.Destination);
        (r.Process_CommandLine.match(/[A-Za-z]:\\[^\s;]+/g) || [])
          .filter((p) => /ProgramData|Temp|Public/.test(p))
          .forEach((p) => ioc.add("Ruta " + p));
        if (/test\.aspx\?cmd=/.test(r.Process_CommandLine))
          ioc.add("URI /uploads/test.aspx?cmd=");
      });
      return {
        fs,
        sev: fs[0].sev,
        t0: Math.min(...fs.map((f) => f.t0)),
        t1: Math.max(...fs.map((f) => f.t1)),
        hosts: [...new Set(rows.map((r) => r.Hostname))],
        users: [...new Set(rows.map((r) => r.User).filter((u) => u != "-"))],
        ioc: [...ioc],
        mitre: [...new Set(fs.map((f) => f.mitre).filter((m) => m != "—"))],
        ev: new Set(rows.map((r) => r.Log_ID)).size,
      };
    })
    .sort((a, b) => a.t0 - b.t0);
  INC.forEach((c, i) => {
    c.id = "INC-" + (i + 1);
    c.title = c.fs[0].title;
    c.why = c.fs.filter((f) => f.sev == c.sev).map((f) => f.why);
  });
  F.forEach((f) => (f.inc = INC.find((c) => c.fs.includes(f))?.id || "—"));
  F.forEach((f) => {
    f.tac = TAC[f.k];
    f.st = "Nuevo";
    const c = INC.find((c) => c.fs.includes(f));
    f.score = Math.min(
      100,
      BASE[f.sev] +
        (c && c.fs.length > 1 ? 6 : 0) +
        (f.rows.length >= 10 ? 4 : 0),
    );
    f.conf =
      (c && c.fs.length > 1 && f.rows.length >= 2) || f.sev == "Bajo"
        ? "Alta"
        : "Media";
  });
  INC.forEach((c) => {
    c.score = Math.min(
      100,
      Math.max(...c.fs.map((f) => f.score)) + Math.min(6, c.fs.length),
    );
    const q = new Set();
    c.chain = c.fs
      .slice()
      .sort((a, b) => a.t0 - b.t0)
      .map((f) => f.tac)
      .filter((t) => !q.has(t) && q.add(t));
    c.narr = `Se correlacionaron ${c.fs.length} hallazgos y ${c.ev} eventos en ${c.hosts.length} host(s) por IP/cuenta compartida.`;
  });
  const e = [
      ...new Set(
        INC.flatMap((c) =>
          c.ioc
            .filter((x) => /^IP/.test(x))
            .map((x) => x.split(" ").pop().split(":")[0] + "|" + c.id),
        ),
      ),
    ].map((x) => x.split("|")),
    rel = [];
  e.forEach((a, i) =>
    e.slice(i + 1).forEach((b) => {
      if (
        a[1] != b[1] &&
        a[0].split(".").slice(0, 3).join(".") ==
          b[0].split(".").slice(0, 3).join(".")
      )
        rel.push(
          `${a[0]} (${a[1]}) y ${b[0]} (${b[1]}) comparten el rango /24; los logs no permiten atribuirlos a un mismo actor (requiere inteligencia de amenazas).`,
        );
    }),
  );
  INC.rel = rel;
}
/* UI */
const pill = (s) => `<span class="p ${s}">${s}</span>`;
const tbl = (rows, max = 60) =>
  `<div class="sc"><table class="t"><tr><th>Log_ID<th>Hora<th>Host<th>Evento<th>Usuario<th>IP origen<th>Detalle<th>Res.</tr>${rows
    .slice(0, max)
    .map(
      (r) =>
        `<tr><td>${r.Log_ID}<td>${r.Timestamp.slice(11)}<td>${esc(r.Hostname)}<td>${esc(r.Event_ID)}<td>${esc(r.User)}<td>${esc(r.Source_IP)}<td title="${esc(r.Process_CommandLine || r.Event_Description)}">${esc(r.Process_CommandLine || r.Event_Description)}<td>${esc(r.Result)}`,
    )
    .join(
      "",
    )}</table></div>${rows.length > max ? `<p class="mu">+${rows.length - max} eventos más (ver Excel)</p>` : ""}`;
function nav() {
  $("#nav").innerHTML = [
    ["carga", "1 Carga"],
    ["analisis", "2 Análisis"],
    ["dash", "3 Dashboard"],
    ["riesgos", "4 Riesgos"],
    ["informe", "5 Informes PDF"],
  ]
    .map(
      ([k, l]) =>
        `<button class="${tab == k ? "on" : ""}" ${k != "carga" && !D.length ? "disabled" : ""} onclick="go('${k}')">${l}</button>`,
    )
    .join("");
}
function go(t) {
  tab = t;
  ch.forEach((c) => c.destroy());
  ch = [];
  nav();
  ({
    carga: vCarga,
    analisis: vAnal,
    dash: vDash,
    riesgos: vRisk,
    informe: vInf,
  })[t]();
  scrollTo(0, 0);
}
function vCarga() {
  const flag = {};
  F.filter((f) => f.sev != "Bajo").forEach((f) =>
    f.rows.forEach((r) => {
      if (!flag[r.Log_ID] || sv(f.sev) < sv(flag[r.Log_ID]))
        flag[r.Log_ID] = f.sev;
    }),
  );
  const H = [
    "Log_ID",
    "Timestamp",
    "Hostname",
    "Event_ID",
    "User",
    "Source_IP",
    "Destination",
    "Event_Description",
    "Process_CommandLine",
    "Result",
    "Severity",
  ];
  $("#m").innerHTML =
    `<div class="hero"><h2>Detección y correlación de incidentes</h2><p>Importa la exportación del SIEM y obtén en minutos incidentes correlacionados, mapa de calor de riesgo, informe técnico e informe ejecutivo.</p></div><div class="cd"><div class="drop" id="dz"><h2>Importar logs del SIEM</h2><p class="mu">Arrastra el Excel exportado (.xlsx/.csv) o selecciónalo. El análisis se ejecuta en tu navegador.</p><label class="b">Seleccionar archivo<input type="file" id="fi" accept=".xlsx,.xls,.csv" hidden></label><p id="er" style="color:var(--C)"></p></div></div>` +
    (D.length
      ? `<div class="cd"><div class="row"><h2 style="margin:0">${esc(fname)} · ${D.length} eventos</h2><input type="text" id="q" placeholder="Filtrar (IP, usuario, host, comando…)" style="max-width:380px"><button class="b" onclick="go('analisis')">Ver análisis →</button></div><p class="mu">Franja de color = evento incluido en un hallazgo. Se muestran los primeros 200 coincidentes.</p><div class="sc" id="tb"></div></div>`
      : "");
  const dz = $("#dz");
  dz.ondragover = (e) => {
    e.preventDefault();
    dz.classList.add("h");
  };
  dz.ondragleave = () => dz.classList.remove("h");
  dz.ondrop = (e) => {
    e.preventDefault();
    ld(e.dataTransfer.files[0]);
  };
  $("#fi").onchange = (e) => ld(e.target.files[0]);
  if (D.length) {
    const draw = () => {
      const q = ($("#q").value || "").toLowerCase(),
        rs = D.filter(
          (r) =>
            !q ||
            H.map((h) => r[h])
              .join(" ")
              .toLowerCase()
              .includes(q),
        ).slice(0, 200);
      $("#tb").innerHTML =
        `<table class="t"><tr>${H.map((h) => `<th>${h}`).join("")}</tr>${rs.map((r) => `<tr style="box-shadow:inset 4px 0 0 ${flag[r.Log_ID] ? SC(flag[r.Log_ID]) : "transparent"}">${H.map((h) => `<td title="${esc(r[h])}">${esc(r[h])}`).join("")}</tr>`).join("")}</table>`;
    };
    $("#q").oninput = draw;
    draw();
  }
}
async function ld(f) {
  if (!f) return;
  try {
    const buf = await f.arrayBuffer(),
      wb = XLSX.read(buf, { type: "array" }),
      rs = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], {
        defval: "",
        raw: false,
      }),
      need = [
        "Log_ID",
        "Timestamp",
        "Hostname",
        "Event_ID",
        "User",
        "Source_IP",
        "Destination",
        "Event_Description",
        "Process_CommandLine",
        "Result",
        "Severity",
      ],
      miss = need.filter((k) => !(k in (rs[0] || {})));
    if (miss.length) throw Error("Faltan columnas: " + miss.join(", "));
    D = rs
      .map((r) => {
        for (const k in r) r[k] = String(r[k]).trim();
        r.t = new Date(r.Timestamp.replace(" ", "T")).getTime();
        return r;
      })
      .filter((r) => !isNaN(r.t))
      .sort((a, b) => a.t - b.t);
    fname = f.name;
    AIS = "";
    DROP = rs.length - D.length;
    HASH = "";
    try {
      HASH = [...new Uint8Array(await crypto.subtle.digest("SHA-256", buf))]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    } catch (e) {}
    analyze();
    nav();
    vCarga();
  } catch (e) {
    $("#er").textContent = "No se pudo leer el archivo: " + e.message;
  }
}
function fcard(f) {
  return `<div class="cd"><div class="row"><h3 style="margin:0">${f.id} · ${esc(f.title)}</h3>${pill(f.sev)}<span class="mu">${f.mitre} · ${f.inc} · ${hh(f.t0)}–${hh(f.t1)} · ${f.rows.length} eventos</span></div><p>${esc(f.desc)}</p><p class="mu"><b>Justificación:</b> ${esc(f.why)}.</p><details><summary>Evidencia (${f.rows.length} registros)</summary>${tbl(f.rows)}</details></div>`;
}
let aF = { sev: "", cat: "", st: "", q: "" };
function setSt(id, v) {
  F.find((f) => f.id == id).st = v;
  drawAl();
}
function vAnal() {
  $("#m").innerHTML =
    `<div class="cd"><h2>Centro de alertas</h2><p class="mu">${F.length} alertas generadas al correlacionar ${D.length} eventos, ordenadas por puntaje de riesgo (0-100). Actualiza el estado de cada alerta según avance la investigación; el estado se refleja en el informe técnico.</p><div class="row" id="fl"></div><div class="row" style="margin-top:8px"><input type="text" id="aq" placeholder="Buscar (IP, cuenta, host…)" style="max-width:300px"><select id="as" onchange="aF.st=this.value;drawAl()"><option value="">Todos los estados</option>${STS.map((x) => `<option>${x}`).join("")}</select><select id="ac" onchange="aF.cat=this.value;drawAl()"><option value="">Todas las categorías</option>${CAT.map((x) => `<option>${x}`).join("")}</select></div></div><div id="al"></div>`;
  $("#aq").oninput = (e) => {
    aF.q = e.target.value.toLowerCase();
    drawAl();
  };
  drawAl();
}
function drawAl() {
  $("#fl").innerHTML = ["", ...SEV]
    .map(
      (x) =>
        `<button class="b ${aF.sev == x ? "" : "s"}" onclick="aF.sev='${x}';drawAl()">${x || "Todas"} (${x ? F.filter((f) => f.sev == x).length : F.length})</button>`,
    )
    .join("");
  const L = F.filter(
    (f) =>
      (!aF.sev || f.sev == aF.sev) &&
      (!aF.cat || f.cat == aF.cat) &&
      (!aF.st || f.st == aF.st) &&
      (!aF.q || (f.title + f.desc + f.inc).toLowerCase().includes(aF.q)),
  ).sort((a, b) => b.score - a.score || a.t0 - b.t0);
  $("#al").innerHTML =
    L.map(
      (f) =>
        `<div class="cd" style="border-left:6px solid ${SC(f.sev)}"><div class="row"><div class="sco" style="background:conic-gradient(${SC(f.sev)} ${f.score * 3.6}deg,var(--bd) 0)"><span>${f.score}</span></div><div style="flex:1;min-width:240px"><div class="row">${pill(f.sev)}<b>${f.id}</b><span class="mu">${f.cat} · ${f.tac} · ${f.mitre} · ${f.inc} · confianza ${f.conf}</span></div><h3 style="margin:4px 0 0">${esc(f.title)}</h3></div><select onchange="setSt('${f.id}',this.value)">${STS.map((x) => `<option ${x == f.st ? "selected" : ""}>${x}`).join("")}</select></div><div class="g" style="margin-top:10px"><div><h3>🔎 Qué se observó</h3><p>${esc(f.desc)}</p></div><div><h3>⚖️ Por qué ${f.sev}</h3><p>${esc(f.why)}.</p><h3>🧠 Interpretación</h3><p>${esc(f.exp)}</p></div><div><h3>🛠️ Acciones</h3><ul>${f.plan.map((x) => `<li>${esc(x)}`).join("")}</ul></div></div><details><summary>Evidencia (${f.rows.length} registros) · ${hh(f.t0)}–${hh(f.t1)}</summary>${tbl(f.rows)}</details></div>`,
    ).join("") || '<div class="cd mu">Sin alertas con esos filtros.</div>';
}
function dashTop() {
  const e = exec(),
    n = new Set(
      F.filter((f) => f.sev != "Bajo").flatMap((f) =>
        f.rows.map((r) => r.Log_ID),
      ),
    ).size,
    top = INC.length ? Math.max(...INC.map((c) => c.score)) : 0,
    open = F.filter(
      (f) => ["Nuevo", "En investigación"].includes(f.st) && f.sev != "Bajo",
    ).length,
    acts = [
      ...new Set(
        INC.filter((c) => c.sev == "Crítico").flatMap((c) =>
          c.fs.filter((f) => f.sev == "Crítico").flatMap((f) => f.plan),
        ),
      ),
    ].slice(0, 4),
    tile = (v, l, x) =>
      `<div><b>${v}</b>${l}<span class="mu" style="display:block">${x}</span></div>`;
  return `<div class="bn" style="background:${SC(e.nivel)};color:${e.nivel == "Medio" ? "#111" : "#fff"}"><div class="sco" style="background:conic-gradient(#fff ${top * 3.6}deg,rgba(255,255,255,.3) 0)"><span style="color:var(--tx)">${top}</span></div><div style="flex:1;min-width:260px"><div style="font-size:13px;opacity:.9">RIESGO GLOBAL · puntaje máximo /100</div><div style="font-size:28px;font-weight:800">${e.nivel.toUpperCase()}</div><div>${esc(e.intro)}</div></div></div><div class="k">${tile(D.length, "Eventos analizados", "registros del SIEM")}${tile(n, "Eventos sospechosos", ((n / D.length) * 100).toFixed(1) + "% del total")}${tile(INC.length, "Incidentes", "independientes entre sí")}${tile(open, "Alertas por atender", "nuevas o en investigación")}</div><div class="cd"><h3>⚡ Qué hacer primero</h3><ol>${acts.map((x) => `<li>${esc(x)}`).join("")}</ol></div><h3>Incidentes <span class="mu">(clic para ver el detalle)</span></h3><div class="g">${INC.map((c) => `<div class="cd" style="border-top:5px solid ${SC(c.sev)};cursor:pointer" onclick="go('riesgos')"><div class="row">${pill(c.sev)}<b>${c.id}</b><span class="mu">${c.score}/100</span></div><h3>${esc(c.title)}</h3><p class="mu">${hh(c.t0)}–${hh(c.t1)} · ${c.hosts.join(", ")}</p><p style="font-size:12px">${c.chain.map(esc).join(" → ")}</p></div>`).join("")}</div>`;
}
function vDash() {
  const fl = sevF ? F.filter((f) => f.sev == sevF) : F,
    sc = SEV.map((s) => F.filter((f) => f.sev == s).length),
    mu = cv("mu");
  $("#m").innerHTML =
    `${dashTop()}<div class="cd"><h3>Mapa de calor por host <span class="mu">(peor criticidad observada)</span></h3><div class="heat">${heat()}</div></div><div class="g"><div class="cd"><h3>Hallazgos por criticidad <span class="mu">(clic para filtrar)</span></h3><div class="ct"><canvas id="c1"></canvas></div></div><div class="cd"><h3>Hallazgos por categoría</h3><div class="ct"><canvas id="c2"></canvas></div></div><div class="cd"><h3>Eventos sospechosos en el tiempo (10 min)</h3><div class="ct"><canvas id="c3"></canvas></div></div><div class="cd"><h3>Orígenes externos por eventos</h3><div class="ct"><canvas id="c4"></canvas></div></div></div>
 <div class="cd"><div class="row"><h2 style="margin:0">Hallazgos ${sevF ? "· " + sevF : ""}</h2>${sevF ? '<button class="b s" onclick="sevF=null;go(\'dash\')">Quitar filtro</button>' : ""}</div><div class="sc"><table class="t"><tr><th>ID<th>Criticidad<th>Categoría<th>Incidente<th>Hallazgo<th>Eventos</tr>${fl
   .slice()
   .sort((a, b) => sv(a.sev) - sv(b.sev))
   .map(
     (f) =>
       `<tr><td>${f.id}<td>${pill(f.sev)}<td>${f.cat}<td>${f.inc}<td>${esc(f.title)}<td>${f.rows.length}`,
   )
   .join("")}</table></div></div>`;
  Chart.defaults.color = mu;
  const o = { responsive: true, maintainAspectRatio: false };
  ch.push(
    new Chart($("#c1"), {
      type: "doughnut",
      data: {
        labels: SEV,
        datasets: [
          { data: sc, backgroundColor: SEV.map(SC), borderColor: cv("cd") },
        ],
      },
      options: {
        ...o,
        onClick: (e, a) => {
          if (a.length) {
            sevF = SEV[a[0].index];
            go("dash");
          }
        },
      },
    }),
  );
  ch.push(
    new Chart($("#c2"), {
      type: "bar",
      data: {
        labels: CAT,
        datasets: SEV.map((s) => ({
          label: s,
          data: CAT.map(
            (c) => F.filter((f) => f.cat == c && f.sev == s).length,
          ),
          backgroundColor: SC(s),
        })),
      },
      options: {
        ...o,
        indexAxis: "y",
        scales: {
          x: { stacked: true, ticks: { precision: 0 } },
          y: { stacked: true },
        },
      },
    }),
  );
  const b = {};
  F.filter((f) => f.sev != "Bajo").forEach((f) =>
    f.rows.forEach((r) => {
      const k = Math.floor(r.t / 6e5) * 6e5;
      (b[k] ??= {})[f.sev] = (b[k][f.sev] || 0) + 1;
    }),
  );
  const ks = Object.keys(b).sort();
  ch.push(
    new Chart($("#c3"), {
      type: "bar",
      data: {
        labels: ks.map((k) => hh(+k).slice(0, 5)),
        datasets: SEV.slice(0, 3).map((s) => ({
          label: s,
          data: ks.map((k) => b[k][s] || 0),
          backgroundColor: SC(s),
        })),
      },
      options: {
        ...o,
        scales: {
          x: { stacked: true },
          y: { stacked: true, ticks: { precision: 0 } },
        },
      },
    }),
  );
  const ips = {};
  D.filter((r) => isExt(r.Source_IP)).forEach(
    (r) => (ips[r.Source_IP] = (ips[r.Source_IP] || 0) + 1),
  );
  const ie = Object.entries(ips).sort((a, b) => b[1] - a[1]);
  ch.push(
    new Chart($("#c4"), {
      type: "bar",
      data: {
        labels: ie.map((e) => e[0]),
        datasets: [
          {
            label: "Eventos",
            data: ie.map((e) => e[1]),
            backgroundColor: cv("ac"),
          },
        ],
      },
      options: { ...o, plugins: { legend: { display: false } } },
    }),
  );
}
function vRisk() {
  $("#m").innerHTML =
    `<div class="cd"><h2>Clasificación de riesgos</h2><p><b>Conclusión:</b> los registros muestran <b>${INC.length} incidentes</b> distintos (agrupados por IP y cuenta actora). ${INC.rel.length ? "Observaciones de correlación (no concluyentes): " + esc(INC.rel.join(" ")) : "No se observan vínculos técnicos directos entre ellos en los logs."}</p><p class="mu">Criterio: Crítico = acceso/daño confirmado en los logs (acceso exitoso, ejecución de comandos, pérdida de recuperación o exfiltración); Alto = técnica de ataque observada sin impacto confirmado; Medio = actividad anómala; Bajo = calidad de datos/configuración.</p></div>` +
    INC.map(
      (c) =>
        `<div class="cd"><div class="row"><h2 style="margin:0">${c.id} · ${esc(c.title)}</h2>${pill(c.sev)}</div><p class="mu">${hh(c.t0)}–${hh(c.t1)} · ${c.ev} eventos · Hosts: ${c.hosts.join(", ")} · Cuentas: ${esc(c.users.join(", "))} · MITRE: ${c.mitre.join(", ")}</p><p><b>Puntaje de riesgo:</b> ${c.score}/100 · <b>Cadena de ataque:</b> ${c.chain.map(esc).join(" → ")}</p><p class="mu">${c.narr}</p><p><b>Justificación de ${c.sev}:</b> ${c.why.map(esc).join("; ")}.</p><h3>Cronología</h3><ul>${c.fs
          .slice()
          .sort((a, b) => a.t0 - b.t0)
          .map(
            (f) =>
              `<li>${hh(f.t0)} ${pill(f.sev)} ${esc(f.title)} <span class="mu">(${f.id}, ${f.rows.length} ev.)</span></li>`,
          )
          .join(
            "",
          )}</ul><h3>IOC</h3><p>${c.ioc.map(esc).join(" · ") || "—"}</p><h3>Plan de acción</h3><ul>${[...new Set(c.fs.flatMap((f) => f.plan))].map((x) => `<li>${esc(x)}`).join("")}</ul></div>`,
    ).join("") +
    `<div class="cd"><h3>Otros hallazgos (sin incidente asociado)</h3>${
      F.filter((f) => f.inc == "—")
        .map((f) => `<p>${pill(f.sev)} ${esc(f.title)} — ${esc(f.desc)}</p>`)
        .join("") || '<p class="mu">Ninguno.</p>'
    }</div>`;
}
const TAC = {
    brute: "Acceso a credenciales",
    susp: "Acceso inicial",
    priv: "Escalada de privilegios",
    persist: "Persistencia",
    web: "Acceso inicial / Ejecución",
    enc: "Ejecución",
    vss: "Impacto",
    stage: "Recolección",
    recon: "Descubrimiento",
    odd: "Ejecución",
    lat: "Movimiento lateral",
    out: "Exfiltración",
    exf: "Exfiltración",
    mass: "Recolección",
    dq: "Calidad de datos",
    sub: "Calidad de datos",
  },
  BASE = { Crítico: 88, Alto: 68, Medio: 45, Bajo: 15 },
  STS = [
    "Nuevo",
    "En investigación",
    "Contenido",
    "Falso positivo",
    "Resuelto",
  ];
let DROP = 0,
  HASH = "";
const CASE = {
    recepcion: new Date().toISOString().slice(0, 10),
    cambios: "Emisión inicial",
    incid: "",
    cliente: "",
    caso: "SOC-" + new Date().getFullYear() + "-001",
    version: "1.0",
    clase: "TLP:AMBER",
    analista: "",
    revisor: "",
    aprobador: "",
    contacto: "",
    dir: "",
  },
  AIX = { t: "" },
  GR = [0, 138, 116];
const CF = [
  ["recepcion", "Fecha de recepción de los logs"],
  ["cambios", "Descripción de cambios de esta versión"],
  ["incid", "Incidencias / cambios de alcance (opcional)"],
  ["cliente", "Cliente / organización"],
  ["caso", "Nº de caso"],
  ["version", "Versión"],
  ["clase", "Clasificación (TLP)"],
  ["analista", "Analista SOC L2 (autor)"],
  ["revisor", "Revisor técnico"],
  ["aprobador", "Aprobado por"],
  ["contacto", "Contacto técnico del cliente"],
  ["dir", "Destinatario directivo"],
];
const nm = (k) => CASE[k] || "(por completar)",
  rgb = (s) => {
    const h = SC(s).replace("#", "");
    return [0, 2, 4].map((i) => parseInt(h.substr(i, 2), 16));
  },
  has = (k) => F.some((f) => f.k == k),
  gk = (k) => F.filter((f) => f.k == k);
const PL = {
  brute:
    "Un atacante probó contraseñas de forma repetida sobre cuentas de la empresa",
  susp: "Alguien accedió a un sistema desde Internet usando credenciales de un empleado",
  priv: "La sesión externa obtuvo permisos de administración",
  persist:
    "Se instaló un programa no autorizado que se ejecuta solo para mantener el acceso",
  web: "Se atacó el sitio web y se llegaron a ejecutar comandos en el servidor",
  enc: "Se ejecutaron comandos ocultos (cifrados) en un equipo",
  vss: "Se borraron las copias de seguridad locales de un equipo, algo típico de la preparación de un ransomware",
  stage: "Se agruparon y comprimieron archivos para sacarlos de la red",
  recon: "Se exploró la red para ubicar equipos y carpetas compartidas",
  odd: "Se ejecutó un programa desde una ubicación sospechosa",
  lat: "El atacante saltó de un servidor a otro usando una cuenta comprometida",
  out: "Un servidor se comunicó con una dirección externa tras preparar archivos",
  exf: "Se enviaron grandes volúmenes de datos a un destino externo",
  mass: "Se abrió una gran cantidad de archivos en pocos minutos",
};
const GLO = [
  [
    "IOC",
    "Indicador de compromiso: dato (IP, archivo, comando) que evidencia actividad maliciosa.",
  ],
  ["SIEM", "Sistema que centraliza y correlaciona los registros de seguridad."],
  [
    "Password spraying",
    "Probar pocas contraseñas comunes contra muchas cuentas para evitar bloqueos.",
  ],
  ["RDP", "Protocolo de escritorio remoto de Windows (puerto 3389)."],
  [
    "Movimiento lateral",
    "Uso de una cuenta o equipo comprometido para llegar a otros sistemas.",
  ],
  ["Exfiltración", "Salida no autorizada de datos de la organización."],
  ["Staging", "Preparación (agrupar/comprimir) de datos antes de sacarlos."],
  [
    "Persistencia",
    "Mecanismo que permite al atacante conservar el acceso tras reinicios.",
  ],
  [
    "Web shell",
    "Script malicioso en un servidor web que permite ejecutar comandos remotos.",
  ],
  [
    "MITRE ATT&CK",
    "Catálogo público de técnicas de atacantes usado para clasificar la actividad.",
  ],
  ["TLP", "Traffic Light Protocol: nivel de difusión permitido del documento."],
];
const PRI = {
  Crítico: "Inmediata (0-24 h)",
  Alto: "Corto plazo (1-7 días)",
  Medio: "Medio plazo (30 días)",
  Bajo: "Mejora continua",
};
function summary() {
  return (
    AIS ||
    `Se analizaron ${D.length} eventos del SIEM (${D[0].Timestamp} a ${D.at(-1).Timestamp}). Se identificaron ${INC.length} incidentes: ${INC.map((c) => `${c.id} (${c.sev}): ${c.title}`).join("; ")}. ${INC.rel.join(" ")}`
  );
}
function parties() {
  const comp = new Set(
      D.filter((r) => r.Event_ID == "4624" && isExt(r.Source_IP)).map(
        (r) => r.User,
      ),
    ),
    tgt = new Set(
      F.filter((f) => f.k == "brute").flatMap((f) =>
        f.rows.filter((r) => r.Event_ID == "4625").map((r) => r.User),
      ),
    ),
    us = {};
  INC.forEach((c) =>
    c.fs.forEach((f) =>
      f.rows.forEach((r) => {
        if (r.User != "-") {
          const v = (us[r.User] ??= { inc: new Set(), h: new Set(), n: 0 });
          v.inc.add(c.id);
          v.h.add(r.Hostname);
          v.n++;
        }
      }),
    ),
  );
  return Object.entries(us).map(([u, v]) => [
    u,
    comp.has(u)
      ? "Cuenta comprometida (acceso desde IP externa confirmado)"
      : tgt.has(u)
        ? "Cuenta objetivo de fuerza bruta (sin acceso exitoso observado)"
        : "Cuenta asociada a actividad sospechosa; titular y legitimidad por confirmar",
    [...v.h].join(", "),
    [...v.inc].join(", "),
    v.n,
  ]);
}
function hosts() {
  return [...new Set(D.map((r) => r.Hostname))].sort().map((h) => {
    const fs = F.filter((f) => f.rows.some((r) => r.Hostname == h)).sort(
      (a, b) => sv(a.sev) - sv(b.sev),
    );
    return [
      h,
      fs[0]?.sev || "Sin hallazgos",
      [...new Set(fs.map((f) => f.inc).filter((i) => i != "—"))].join(", ") ||
        "—",
      D.filter((r) => r.Hostname == h).length,
    ];
  });
}
function heat() {
  return hosts()
    .map(
      ([h, s, i, n]) =>
        `<div class="${s == "Sin hallazgos" ? "ok" : s}">${esc(h)}<small>${s} · ${i} · ${n} ev.</small></div>`,
    )
    .join("");
}
function exec() {
  const nivel =
      INC.map((c) => c.sev).sort((a, b) => sv(a) - sv(b))[0] || "Bajo",
    fe = D[0].Timestamp.slice(0, 10),
    mb = gk("exf")
      .map((f) => (f.desc.match(/\(([\d.,]+) MB\)/) || [])[1])
      .filter(Boolean),
    sh = [
      ...new Set(
        F.flatMap((f) => f.rows).flatMap(
          (r) =>
            (
              r.Destination +
              " " +
              r.Process_CommandLine +
              " " +
              r.Event_Description
            ).match(/Finance|Legal/g) || [],
        ),
      ),
    ],
    comp = [
      ...new Set(
        D.filter((r) => r.Event_ID == "4624" && isExt(r.Source_IP)).map(
          (r) => r.User,
        ),
      ),
    ],
    imp = [];
  const intro =
    `Entre las ${hh(Math.min(...INC.map((c) => c.t0)))} y las ${hh(Math.max(...INC.map((c) => c.t1)))} del ${fe} se detectaron ${INC.length} incidentes de seguridad independientes en la infraestructura de ${CASE.cliente || "la organización"}. El nivel de riesgo global es ${nivel.toUpperCase()}.` +
    (comp.length
      ? " Se confirmó acceso no autorizado con credenciales de empleados."
      : "");
  if (comp.length)
    imp.push(
      `${comp.length} cuenta(s) con acceso desde Internet confirmado (${comp.join(", ")}); deben considerarse comprometidas hasta demostrar lo contrario.`,
    );
  if (sh.length)
    imp.push(`Se accedió a recursos de las áreas: ${sh.join(" y ")}.`);
  if (mb.length)
    imp.push(
      `Se registró el envío de unos ${mb.join(" MB y ")} MB hacia un destino externo. Los registros no permiten confirmar qué archivos exactos salieron.`,
    );
  if (has("vss"))
    imp.push(
      "Se eliminaron copias de seguridad locales en un equipo: ante un ransomware, la recuperación sería más difícil.",
    );
  if (has("persist"))
    imp.push(
      "Hay software no autorizado instalado en un servidor que se ejecuta automáticamente.",
    );
  if (has("web"))
    imp.push(
      "El sitio web mostró actividad de explotación y ejecución de comandos.",
    );
  if (
    !D.some((r) =>
      /encrypt|ransom|\.locked|\.crypt/i.test(
        r.Process_CommandLine + " " + r.Event_Description,
      ),
    )
  )
    imp.push(
      "En los registros analizados no se observan eventos de cifrado de archivos ni caída de servicios (no descarta que ocurran más adelante).",
    );
  const que = INC.map((c) => {
    const s = new Set(),
      a = [];
    c.fs
      .slice()
      .sort((x, y) => x.t0 - y.t0)
      .forEach((f) => {
        if (PL[f.k] && !s.has(f.k)) {
          s.add(f.k);
          a.push(PL[f.k]);
        }
      });
    return `${hh(c.t0)}–${hh(c.t1)} · Riesgo ${c.sev} · ${a.join(". ")}.`;
  });
  const dec = [
    "Autorizar la contención inmediata: aislar los sistemas afectados y bloquear las direcciones externas (puede interrumpir temporalmente servicios).",
    "Activar el comité de crisis y definir la comunicación interna y a terceros.",
    "Evaluar la notificación a la autoridad (IMY) y a los afectados si se confirman datos personales: el RGPD exige notificar en un máximo de 72 horas desde que se tiene conocimiento.",
    "Aprobar recursos para una investigación forense y el restablecimiento de credenciales de toda la organización.",
  ];
  return { nivel, intro, que, imp, dec };
}
function execHTML(e) {
  const li = (a) => `<ul>${a.map((x) => `<li>${esc(x)}`).join("")}</ul>`;
  return `<p>${pill(e.nivel)} <b>Riesgo global</b></p><p>${esc(AIX.t || e.intro)}</p><h3>¿Qué pasó?</h3>${li(e.que)}<h3>¿Qué significa para el negocio?</h3>${li(e.imp)}<h3>Decisiones que se requieren de la Dirección</h3>${li(e.dec)}`;
}
function vInf() {
  $("#m").innerHTML =
    `<div class="cd"><h2>Datos del caso y equipo de investigación</h2><p class="mu">Estos datos aparecen en la portada, el control del documento y las firmas de ambos informes.</p><div class="g">${CF.map(([k, l]) => `<label class="mu">${l}<input type="text" value="${esc(CASE[k])}" oninput="CASE['${k}']=this.value"></label>`).join("")}</div></div>
<div class="g"><div class="cd"><h2>📄 Informe técnico</h2><p class="mu">Estructura INCIBE-CERT: portada con clasificación TLP, control de versiones, índice enlazado, resumen con puntuación de riesgo, introducción, metodología, resultados con timeline, conclusiones, glosario y anexos (evidencias completas y cadena de custodia).</p><button class="b" id="bp">⬇ Descargar informe técnico (PDF)</button><h3 style="margin-top:14px">Resumen técnico</h3><div class="ai" id="sm">${esc(summary())}</div><button class="b s" id="ba" style="margin-top:8px">✨ Redactar con IA</button></div>
<div class="cd"><h2>📊 Informe ejecutivo</h2><p class="mu">Lenguaje claro para la Dirección: qué pasó, impacto en el negocio y decisiones requeridas.</p><button class="b" id="bx">⬇ Descargar informe ejecutivo (PDF)</button><div id="xv" style="margin-top:12px">${execHTML(exec())}</div><button class="b s" id="bxa">✨ Redactar introducción con IA</button></div></div>
<div class="cd"><h2>Partes involucradas</h2><p class="mu">Cuentas y hosts tomados de los registros. El nombre de la persona titular de cada cuenta debe confirmarlo el cliente.</p><div class="sc"><table class="t"><tr><th>Cuenta<th>Rol observado<th>Hosts<th>Incidentes<th>Eventos</tr>${parties()
      .map((r) => `<tr>${r.map((x) => `<td>${esc(x)}`).join("")}`)
      .join("")}</table></div></div>
<div class="cd"><h3>Pregunta a la IA sobre los hallazgos</h3><div class="row"><input type="text" id="qq" placeholder="Ej.: ¿Qué datos pudieron ser exfiltrados y qué evidencia lo respalda?" style="flex:1"><button class="b" id="bq">Preguntar</button></div><div class="ai hid" id="qa"></div></div>`;
  $("#bp").onclick = pdfTech;
  $("#bx").onclick = pdfExec;
  $("#ba").onclick = () =>
    ai(
      "Redacta el resumen técnico del informe (máx. 220 palabras): indica si fueron uno o varios incidentes, el impacto observado y las prioridades inmediatas.",
      $("#sm"),
      "s",
    );
  $("#bxa").onclick = () =>
    ai(
      "Redacta, para directivos sin conocimientos técnicos y sin jerga, un párrafo de 120 palabras: qué ocurrió, qué está en riesgo y qué se necesita decidir.",
      $("#xv"),
      "x",
    );
  $("#bq").onclick = () => {
    const q = $("#qq").value.trim();
    if (q) {
      $("#qa").classList.remove("hid");
      ai(q, $("#qa"), "");
    }
  };
}
async function ai(task, el, save) {
  let s = null;
  try {
    s = await claude.use("sample");
  } catch (e) {}
  if (!s) {
    el.textContent =
      "La IA no está disponible en esta vista; se usa el texto automático.";
    return;
  }
  const data = JSON.stringify({
    eventos: D.length,
    incidentes: INC.map((c) => ({
      id: c.id,
      criticidad: c.sev,
      hosts: c.hosts,
      cuentas: c.users,
      ioc: c.ioc,
      hallazgos: c.fs.map((f) => ({
        id: f.id,
        titulo: f.title,
        criticidad: f.sev,
        detalle: f.desc,
        log_ids: f.rows.map((r) => r.Log_ID).slice(0, 25),
      })),
    })),
    observaciones: INC.rel,
  });
  try {
    el.textContent = "Pensando…";
    const r = await s(
      `Eres analista SOC nivel 2. Usa ÚNICAMENTE los datos JSON de abajo; no inventes hechos, actores ni datos. Cita Log_ID/IDs de hallazgo cuando sea técnico. Si algo no está en los datos, di que no hay evidencia. Español, texto plano sin markdown.\n\nTAREA: ${task}\n\nDATOS: ${data}`,
      {
        modelTier: "default",
        cache: false,
        onText: ({ text }) => (el.textContent = text),
      },
    );
    const t = r.text.replace(/[*#`]/g, "");
    if (save == "s") AIS = t;
    if (save == "x") {
      AIX.t = t;
      el.textContent = t;
    }
  } catch (e) {
    el.textContent = "Error de IA: " + (e.message || e.code);
  }
}
/* PDF */
function mk() {
  const d = new jspdf.jsPDF({ unit: "pt", format: "a4" }),
    M = 48,
    mw = 499,
    st = { y: M },
    toc = [],
    cl = (s) =>
      String(s ?? "")
        .replace(/→/g, "->")
        .replace(/[–—]/g, "-")
        .replace(/[«»]/g, '"')
        .replace(/•/g, "-")
        .replace(/[^\x09\x20-\x7E\xA0-\xFF]/g, ""),
    np = () => {
      d.addPage();
      st.y = M + 14;
    };
  const tx = (s, z = 10, b = 0, c = [40, 40, 40], ind = 0, f = "helvetica") => {
    d.setFont(f, b ? "bold" : "normal");
    d.setFontSize(z);
    d.setTextColor(...c);
    d.splitTextToSize(cl(s), mw - ind).forEach((l) => {
      if (st.y + z + 4 > 790) np();
      d.text(l, M + ind, st.y);
      st.y += z * 1.35;
    });
  };
  const hd = (s, l = 1) => {
    if (st.y > 720) np();
    st.y += l == 1 ? 14 : 6;
    if (l == 1) toc.push([s, d.getNumberOfPages()]);
    tx(s, l == 1 ? 14 : 11, 1, l == 1 ? GR : [40, 40, 40]);
    if (l == 1) {
      d.setDrawColor(...GR);
      d.setLineWidth(1.2);
      d.line(M, st.y - 8, M + mw, st.y - 8);
    }
    st.y += 2;
  };
  const tb = (h, b, o = {}) => {
    d.autoTable({
      startY: st.y,
      head: [h.map(cl)],
      body: b.map((r) => r.map(cl)),
      margin: { left: M, right: M, top: M + 14, bottom: 40 },
      styles: { fontSize: 8, cellPadding: 3, textColor: [40, 40, 40] },
      headStyles: { fillColor: [29, 29, 27], textColor: 255 },
      alternateRowStyles: { fillColor: [245, 247, 248] },
      ...o,
    });
    st.y = d.lastAutoTable.finalY + 10;
  };
  return { d, st, tx, hd, tb, cl, M, mw, toc, np };
}
async function dlp(d, n) {
  let dl = null;
  try {
    dl = await claude.use("downloads");
  } catch (e) {}
  if (dl) {
    try {
      await dl.save({ filename: n, data: d.output("blob") });
    } catch (e) {}
  } else d.save(n);
}
function deco(P, title, from) {
  const { d, cl, M, mw } = P,
    n = d.getNumberOfPages();
  for (let i = from; i <= n; i++) {
    d.setPage(i);
    d.setFontSize(8);
    d.setTextColor(120);
    d.setDrawColor(200);
    d.line(M, 32, M + mw, 32);
    d.text(cl(`${title} · ${CASE.caso} · v${CASE.version}`), M, 26);
    d.text(cl(CASE.clase), M + mw, 26, { align: "right" });
    d.line(M, 806, M + mw, 806);
    d.text(cl(`${nm("cliente")} - Confidencial`), M, 820);
    d.text(`Página ${i} de ${n}`, M + mw, 820, { align: "right" });
  }
}
const IMP = {
    Impacto: 5,
    Exfiltración: 5,
    "Movimiento lateral": 4,
    "Escalada de privilegios": 4,
    Persistencia: 4,
    "Acceso inicial": 4,
    "Acceso inicial / Ejecución": 4,
    Recolección: 3,
    Ejecución: 3,
    "Acceso a credenciales": 3,
    Descubrimiento: 2,
    "Calidad de datos": 1,
  },
  PS = { Crítico: 5, Alto: 4, Medio: 3, Bajo: 2 },
  LVL = (v) =>
    v >= 20 ? "Crítico" : v >= 12 ? "Alto" : v >= 6 ? "Medio" : "Bajo";
const tlpc = (c) =>
    /RED/i.test(c)
      ? [255, 43, 43]
      : /AMBER/i.test(c)
        ? [255, 192, 0]
        : /GREEN/i.test(c)
          ? [51, 170, 0]
          : /CLEAR|WHITE/i.test(c)
            ? [255, 255, 255]
            : [150, 150, 150],
  rk = (c) => {
    const p = PS[c.sev],
      i = Math.max(...c.fs.map((f) => IMP[f.tac] || 1));
    return { p, i, v: p * i, l: LVL(p * i) };
  };
const eff = (p) =>
  /^(Bloquear|Aislar|Eliminar|Restablecer|Rotar|Invalidar)/.test(p)
    ? "Bajo"
    : /^(Revisar|Verificar|Obtener|Localizar|Identificar|Evaluar|Recuperar|Buscar|Capturar|Determinar|Investigar|Preservar)/.test(
          p,
        )
      ? "Medio"
      : "Alto";
const RULES = [
  [
    "Fuerza bruta",
    "4625",
    ">=3 fallos desde IP externa (>=5 en 10 min si es interna); >=5 cuentas distintas = password spraying",
  ],
  [
    "Inicio sospechoso",
    "4624",
    "Logon exitoso desde IP fuera de rangos privados (10.x, 172.16-31.x, 192.168.x)",
  ],
  [
    "Escalamiento",
    "4672, 4698, 7045",
    "Privilegios especiales en sesión externa; tareas o servicios en rutas no estándar y sus ejecuciones",
  ],
  [
    "Comandos y procesos",
    "4688, 4104, HTTP_ACCESS",
    "-EncodedCommand, vssadmin delete shadows, compresión en Temp/Public, enumeración, ejecución desde rutas inusuales, cmd.exe lanzado por IIS",
  ],
  [
    "Movimiento lateral",
    "4624 tipo 3, 5145, 5156",
    "Cuenta con acceso externo previo que inicia sesión en otro host y accede a recursos; salida a IP externa tras compresión",
  ],
  [
    "Otras anomalías",
    "PROXY_ACCESS, 4663",
    ">=5 POST al mismo destino externo; >=10 accesos a archivos en 15 min; hostnames inconsistentes; severidad SIEM subestimada",
  ],
];
const GL2 = GLO.concat([
  [
    "Cadena de custodia",
    "Registro documentado de quién recibió, custodió y analizó una evidencia, y cuándo.",
  ],
  [
    "Probabilidad",
    "Grado de certeza, según la evidencia, de que la actividad sea maliciosa (escala 1-5).",
  ],
  [
    "Impacto",
    "Gravedad potencial de la táctica observada sobre la organización (escala 1-5).",
  ],
  ["Timeline", "Línea temporal de eventos ordenados cronológicamente."],
]).sort((a, b) => a[0].localeCompare(b[0], "es"));
function matrix(P) {
  const { d, st, M } = P;
  if (st.y > 520) P.np();
  const x0 = M + 50,
    cs = 46,
    y0 = st.y;
  for (let p = 5; p >= 1; p--)
    for (let i = 1; i <= 5; i++) {
      const l = LVL(p * i),
        x = x0 + (i - 1) * cs,
        y = y0 + (5 - p) * cs;
      d.setFillColor(...rgb(l));
      d.rect(x, y, cs - 2, cs - 2, "F");
      const ids = INC.filter((c) => {
        const r = rk(c);
        return r.p == p && r.i == i;
      })
        .map((c) => c.id.replace("INC-", "I"))
        .join(" ");
      if (ids) {
        d.setTextColor(l == "Medio" ? 20 : 255);
        d.setFont("helvetica", "bold");
        d.setFontSize(8);
        d.splitTextToSize(ids, cs - 6).forEach((t, k) =>
          d.text(t, x + 3, y + 12 + k * 10),
        );
      }
    }
  d.setTextColor(60);
  d.setFont("helvetica", "normal");
  d.setFontSize(8);
  for (let k = 1; k <= 5; k++) {
    d.text(String(k), x0 + (k - 1) * cs + cs / 2 - 3, y0 + 5 * cs + 10);
    d.text(String(6 - k), x0 - 12, y0 + (k - 1) * cs + cs / 2);
  }
  d.text("Impacto (1-5)", x0 + 80, y0 + 5 * cs + 22);
  d.text("Probab.", M, y0 + 110);
  st.y = y0 + 5 * cs + 34;
}
async function pdfTech() {
  const P = mk(),
    { d, st, tx, hd, tb, cl, M, mw } = P,
    emi = new Date().toLocaleDateString("es"),
    sevo = INC.slice().sort((a, b) => sv(a.sev) - sv(b.sev)),
    e = exec(),
    n = new Set(
      F.filter((f) => f.sev != "Bajo").flatMap((f) =>
        f.rows.map((r) => r.Log_ID),
      ),
    ).size,
    hs = hosts(),
    bl = (a, z = 10) => a.forEach((x) => tx("•  " + x, z, 0, [40, 40, 40], 6));
  /* PORTADA */
  d.setFillColor(29, 29, 27);
  d.rect(0, 0, 595, 842, "F");
  d.setFillColor(...GR);
  d.rect(M, 110, 60, 5, "F");
  d.setTextColor(255);
  d.setFont("helvetica", "bold");
  d.setFontSize(30);
  d.text("Informe técnico de", M, 160);
  d.text(cl("análisis de incidentes"), M, 196);
  d.setFontSize(13);
  d.setFillColor(...tlpc(CASE.clase));
  d.rect(M, 222, 190, 24, "F");
  d.setTextColor(20);
  d.text(cl(`Clasificación: ${CASE.clase}`), M + 8, 239);
  d.setFont("helvetica", "normal");
  d.setTextColor(200, 205, 211);
  [
    ["Cliente", nm("cliente")],
    ["Nº de caso", CASE.caso],
    ["Versión", CASE.version],
    ["Autor / investigador", nm("analista")],
    ["Fecha de recepción de los logs", nm("recepcion")],
    ["Fecha de elaboración", emi],
  ].forEach(([k, v], i) => {
    d.setFontSize(9);
    d.setTextColor(140, 150, 160);
    d.text(cl(k.toUpperCase()), M, 290 + i * 38);
    d.setFontSize(13);
    d.setTextColor(235);
    d.text(cl(v), M, 306 + i * 38);
  });
  d.setFontSize(9);
  d.setTextColor(140, 150, 160);
  d.text(cl("Consultoría de ciberseguridad · Estocolmo, Suecia"), M, 760);
  /* CONTROL DE VERSIONES */
  d.addPage();
  st.y = M + 14;
  hd("Control del documento y de versiones");
  tb(
    ["Campo", "Valor"],
    [
      ["Título", "Informe técnico de análisis de incidentes"],
      ["Nº de caso", CASE.caso],
      ["Cliente", nm("cliente")],
      [
        "Clasificación",
        CASE.clase +
          " (Traffic Light Protocol: difusión según la norma de intercambio de información acordada)",
      ],
      ["Fuente de datos", `${fname} (${D.length} eventos)`],
      ["Recepción / elaboración", `${nm("recepcion")} / ${emi}`],
    ],
    { columnStyles: { 0: { fontStyle: "bold", cellWidth: 140 } } },
  );
  hd("Historial de cambios", 2);
  tb(
    ["Versión", "Fecha", "Autor", "Descripción de los cambios"],
    [[CASE.version, emi, nm("analista"), CASE.cambios || "Emisión inicial"]],
    { columnStyles: { 3: { cellWidth: 260 } } },
  );
  hd("Responsables", 2);
  tb(
    ["Rol", "Nombre"],
    [
      ["Autor (Analista SOC L2)", nm("analista")],
      ["Revisor técnico", nm("revisor")],
      ["Aprobado por", nm("aprobador")],
      ["Contacto técnico del cliente", nm("contacto")],
      ["Destinatario directivo", nm("dir")],
    ],
  );
  P.toc.length = 0;
  d.addPage();
  const tp = d.getNumberOfPages();
  d.addPage();
  st.y = M + 14;
  /* 1 RESUMEN EJECUTIVO */
  hd("1. Resumen ejecutivo");
  tx(
    `Objetivo: identificar indicadores de compromiso, correlacionar eventos y determinar si hubo uno o varios incidentes a partir de ${D.length} eventos del SIEM del cliente.`,
  );
  st.y += 4;
  tx(
    `Resultado de alto nivel: se identificaron ${INC.length} incidentes independientes (${SEV.map((s) => INC.filter((c) => c.sev == s).length + " " + s).join(", ")}) con ${n} eventos sospechosos (${((n / D.length) * 100).toFixed(1)}% del total). ` +
      e.intro.split(". ").slice(1).join(". "),
  );
  st.y += 4;
  tx("Hallazgos principales:", 10, 1);
  bl(e.que, 9);
  hd("1.1 Puntuación de riesgo general", 2);
  tx(
    `Riesgo general: ${e.nivel.toUpperCase()} (puntaje máximo ${Math.max(...INC.map((c) => c.score))}/100). Mecanismo: la criticidad de cada incidente se asigna con los criterios de la sección 3.5. De forma complementaria, se calcula RIESGO = PROBABILIDAD x IMPACTO (escala 1-25) y se ubica cada incidente en la matriz cualitativa 5x5. No aplica CVSS porque no se trata de un análisis de vulnerabilidades.`,
    9,
  );
  st.y += 4;
  tb(
    [
      "Incidente",
      "Criticidad",
      "Puntaje /100",
      "Probab.",
      "Impacto",
      "Riesgo P x I",
      "Nivel matriz",
    ],
    INC.map((c) => {
      const r = rk(c);
      return [
        `${c.id} ${c.title}`.slice(0, 70),
        c.sev,
        c.score,
        r.p,
        r.i,
        r.v,
        r.l,
      ];
    }),
    { columnStyles: { 0: { cellWidth: 190 } } },
  );
  matrix(P);
  /* 2 INTRODUCCIÓN */
  hd("2. Introducción");
  hd("2.1 Antecedentes", 2);
  tx(
    `${nm("cliente")} comunicó un posible incidente en su infraestructura y entregó una exportación de los registros de su SIEM (${fname}, ${D.length} eventos), recibida el ${nm("recepcion")}. Este informe documenta el análisis de dichos registros.`,
  );
  hd("2.2 Objetivo", 2);
  tx(
    "Buscar indicadores de compromiso (IOC), correlacionar los eventos y establecer si hubo uno o varios incidentes, clasificando su riesgo y proponiendo acciones de respuesta, con conclusiones sustentadas estrictamente en los registros proporcionados.",
  );
  hd("2.3 Alcance", 2);
  tb(
    ["Dimensión", "Detalle"],
    [
      ["Temporal", `${D[0].Timestamp} a ${D.at(-1).Timestamp}`],
      ["Espacial", `${hs.length} hosts: ${hs.map((h) => h[0]).join(", ")}`],
      [
        "Completitud",
        `${D.length} de ${D.length + DROP} filas analizadas (${DROP} descartadas por marca de tiempo inválida)`,
      ],
      [
        "Fuera de alcance",
        "Telemetría de red, EDR, volcados de memoria y acceso directo a los sistemas del cliente",
      ],
    ],
    { columnStyles: { 0: { fontStyle: "bold", cellWidth: 110 } } },
  );
  hd("2.4 Incidencias durante el análisis", 2);
  const inc = [];
  if (DROP) inc.push(`${DROP} filas descartadas por marca de tiempo inválida.`);
  F.filter((f) => f.k == "dq" || f.k == "sub").forEach((f) =>
    inc.push(f.title + "."),
  );
  inc.push(CASE.incid || "No se registraron cambios de alcance.");
  bl(inc, 9);
  hd("2.5 Equipo de investigación y partes involucradas", 2);
  tb(
    ["Rol", "Nombre"],
    [
      ["Analista SOC L2", nm("analista")],
      ["Revisor técnico", nm("revisor")],
      ["Contacto técnico del cliente", nm("contacto")],
      ["Destinatario directivo", nm("dir")],
    ],
  );
  /* 3 METODOLOGÍA */
  hd("3. Metodología");
  hd("3.1 Marco de referencia", 2);
  tx(
    "Fases de respuesta a incidentes de NIST SP 800-61 Rev. 2 (detección y análisis), clasificación de tácticas y técnicas con MITRE ATT&CK, tratamiento de la información según TLP y estructura de informe propuesta por INCIBE-CERT. No se certifica cumplimiento de estas normas.",
  );
  hd("3.2 Tratamiento de datos y reproducibilidad", 2);
  tx(
    `Los registros se importaron sin modificarlos y se ordenaron cronológicamente. El análisis es determinista: el mismo archivo produce los mismos hallazgos. Integridad del archivo recibido (SHA-256): ${HASH || "(no disponible)"}.`,
    9,
  );
  hd("3.3 Reglas de detección", 2);
  tb(["Categoría", "Event ID", "Criterio"], RULES, {
    columnStyles: { 2: { cellWidth: 300 } },
  });
  hd("3.4 Correlación", 2);
  tx(
    "Los hallazgos se agrupan en un mismo incidente cuando comparten IP o cuenta actora. Los vínculos que los registros no permiten probar se reportan solo como observaciones no concluyentes.",
    9,
  );
  hd("3.5 Mecanismo de puntuación y clasificación", 2);
  tb(
    ["Nivel", "Criterio", "Incidentes"],
    [
      [
        "Crítico",
        "Acceso o daño confirmado en los registros (acceso exitoso, ejecución de comandos, pérdida de recuperación, exfiltración)",
        INC.filter((c) => c.sev == "Crítico").length,
      ],
      [
        "Alto",
        "Técnica de ataque observada sin impacto confirmado",
        INC.filter((c) => c.sev == "Alto").length,
      ],
      [
        "Medio",
        "Actividad anómala a investigar",
        INC.filter((c) => c.sev == "Medio").length,
      ],
      [
        "Bajo",
        "Calidad de datos o configuración",
        INC.filter((c) => c.sev == "Bajo").length,
      ],
    ],
    { columnStyles: { 1: { cellWidth: 300 } } },
  );
  tx(
    "Puntaje 0-100: base por criticidad (Crítico 88, Alto 68, Medio 45, Bajo 15) + 6 si el hallazgo se correlaciona con otros + 4 si tiene 10 o más eventos; el incidente toma el máximo de sus hallazgos + 1 por hallazgo correlacionado (tope 6). Probabilidad (1-5) = certeza demostrada por la evidencia (Crítico 5, Alto 4, Medio 3, Bajo 2). Impacto (1-5) = mayor gravedad de las tácticas del incidente (Exfiltración e Impacto 5; Movimiento lateral, Escalada, Persistencia y Acceso inicial 4; Recolección, Ejecución y Acceso a credenciales 3; Descubrimiento 2). Matriz: >=20 Crítico, 12-19 Alto, 6-11 Medio, <=5 Bajo.",
    8,
    0,
    [90, 90, 90],
  );
  hd("3.6 Técnicas OSINT", 2);
  tx(
    "No se aplicaron técnicas OSINT ni consultas a fuentes externas; el análisis usa exclusivamente los registros aportados.",
    9,
  );
  /* 4 RESULTADOS */
  hd("4. Resultados obtenidos");
  hd("4.1 Línea temporal consolidada (timeline)", 2);
  tb(
    [
      "Fecha y hora",
      "Incidente",
      "Criticidad",
      "Estado",
      "Hallazgo",
      "Eventos",
    ],
    F.filter((f) => f.inc != "—")
      .sort((a, b) => a.t0 - b.t0)
      .map((f) => [
        `${new Date(f.t0).toLocaleDateString("sv")} ${hh(f.t0)}-${hh(f.t1)}`,
        f.inc,
        f.sev,
        f.st,
        f.title,
        f.rows.length,
      ]),
    { columnStyles: { 4: { cellWidth: 190 } } },
  );
  hd("4.2 Hallazgos por incidente", 2);
  INC.forEach((c) => {
    const r = rk(c);
    hd(`${c.id} - ${c.title}`, 2);
    tb(
      [
        "Criticidad",
        "Puntaje",
        "Riesgo PxI",
        "Ventana",
        "Hosts",
        "Cuentas",
        "MITRE",
      ],
      [
        [
          c.sev,
          c.score,
          `${r.v} (${r.l})`,
          `${hh(c.t0)}-${hh(c.t1)}`,
          c.hosts.join(", "),
          c.users.join(", "),
          c.mitre.join(", "),
        ],
      ],
    );
    tx("Cadena de ataque observada: " + c.chain.join(" > ") + ". " + c.narr, 9);
    tx("Justificación de la criticidad: " + c.why.join("; ") + ".", 9);
    c.fs
      .slice()
      .sort((a, b) => a.t0 - b.t0)
      .forEach((f) => {
        st.y += 4;
        tx(
          `[${f.sev}] ${f.id} - ${f.title} (${f.tac}, ${f.mitre}, confianza ${f.conf}, estado: ${f.st})`,
          10,
          1,
        );
        tx("Observación: " + f.desc, 9, 0, [60, 60, 60], 8);
        tx("Impacto / explicación técnica: " + f.exp, 9, 0, [60, 60, 60], 8);
        tb(
          [
            "Log_ID",
            "Hora",
            "Host",
            "Evento",
            "Usuario",
            "IP origen",
            "Detalle",
          ],
          f.rows
            .slice(0, 8)
            .map((x) => [
              x.Log_ID,
              x.Timestamp.slice(11),
              x.Hostname,
              x.Event_ID,
              x.User,
              x.Source_IP,
              (x.Process_CommandLine || x.Event_Description).slice(0, 70),
            ]),
          {
            styles: { fontSize: 7, cellPadding: 2, textColor: [40, 40, 40] },
            columnStyles: { 6: { cellWidth: 140 } },
          },
        );
        tx(
          `Extracto de ${Math.min(8, f.rows.length)} de ${f.rows.length} registros; evidencia completa en el Anexo A. Log_ID: ` +
            f.rows.map((x) => x.Log_ID).join(", "),
          7,
          0,
          [100, 100, 100],
          8,
        );
      });
  });
  hd("4.3 Indicadores de compromiso (IOC)", 2);
  tb(
    ["Tipo", "Valor", "Incidente"],
    INC.flatMap((c) =>
      c.ioc.map((x) => {
        const t = x.startsWith("IP destino") ? "IP destino" : x.split(" ")[0];
        return [t, x.slice(t.length + 1), c.id];
      }),
    ),
  );
  hd("4.4 Mapeo MITRE ATT&CK", 2);
  const mt = {};
  F.filter((f) => f.mitre != "—").forEach((f) => (mt[f.mitre] ??= []).push(f));
  tb(
    ["Técnica", "Hallazgos", "Incidentes"],
    Object.entries(mt).map(([k, v]) => [
      k,
      v.map((f) => f.id).join(", "),
      [...new Set(v.map((f) => f.inc))].join(", "),
    ]),
  );
  hd("4.5 Cuentas y hosts implicados", 2);
  tb(["Cuenta", "Rol observado", "Hosts", "Incidentes", "Eventos"], parties());
  tb(["Host", "Criticidad máxima", "Incidentes", "Eventos"], hs);
  /* 5 CONCLUSIONES */
  hd("5. Conclusiones y recomendaciones");
  hd("5.1 Conclusiones", 2);
  tx(
    `Los registros evidencian ${INC.length} incidentes independientes, no uno solo: cada uno tiene su propio origen, cuentas y hosts, sin vínculo técnico directo demostrable entre ellos. ${INC.rel.join(" ")}`,
    10,
  );
  st.y += 3;
  tx("Impacto observado en los registros:", 10, 1);
  bl(e.imp, 9);
  hd("5.2 Recomendaciones priorizadas", 2);
  const pa = [],
    seen = {};
  INC.forEach((c) => {
    c.fs.forEach((f) =>
      f.plan.forEach((p) => {
        const k = c.id + p;
        if (!seen[k] || sv(f.sev) < sv(seen[k][3])) {
          seen[k] = [PRI[f.sev], p, c.id, f.sev, eff(p)];
        }
      }),
    );
  });
  Object.values(seen).forEach((x) => pa.push(x));
  pa.sort((a, b) => sv(a[3]) - sv(b[3]));
  tb(
    ["Prioridad", "Acción", "Incidente", "Esfuerzo estimado"],
    pa.map((x) => [x[0], x[1], x[2], x[4]]),
    { columnStyles: { 1: { cellWidth: 270 } } },
  );
  tx(
    "El esfuerzo es una estimación orientativa (Bajo: acción puntual; Medio: requiere análisis o coordinación; Alto: proyecto o cambio de configuración).",
    8,
    0,
    [100, 100, 100],
  );
  hd("6. Glosario de términos");
  tb(["Término", "Definición"], GL2, {
    columnStyles: { 1: { cellWidth: 360 } },
  });
  /* ANEXOS */
  hd("7. Anexos");
  hd("Anexo A. Evidencias completas", 2);
  tx(
    "Todos los registros que sustentan los hallazgos (excepto los de calidad de datos), en orden cronológico.",
    9,
  );
  const ev = new Map();
  F.filter((f) => f.k != "dq" && f.k != "sub").forEach((f) =>
    f.rows.forEach((r) => ev.set(r.Log_ID, r)),
  );
  tb(
    [
      "Log_ID",
      "Fecha y hora",
      "Host",
      "Evento",
      "Usuario",
      "IP origen",
      "Destino",
      "Detalle",
      "Res.",
    ],
    [...ev.values()]
      .sort((a, b) => a.t - b.t)
      .map((r) => [
        r.Log_ID,
        r.Timestamp,
        r.Hostname,
        r.Event_ID,
        r.User,
        r.Source_IP,
        r.Destination,
        r.Process_CommandLine || r.Event_Description,
        r.Result,
      ]),
    {
      styles: { fontSize: 6, cellPadding: 1.5, textColor: [40, 40, 40] },
      columnStyles: { 7: { cellWidth: 130 } },
    },
  );
  hd("Anexo B. Cadena de custodia e integridad", 2);
  tb(
    ["Campo", "Valor"],
    [
      ["Archivo recibido", fname],
      ["Fecha de recepción", nm("recepcion")],
      ["Analista custodio", nm("analista")],
      ["Eventos", D.length],
      ["SHA-256", HASH || "(no disponible)"],
      [
        "Tratamiento",
        "Lectura local en el navegador; sin modificación ni envío a terceros",
      ],
    ],
    { columnStyles: { 0: { fontStyle: "bold", cellWidth: 120 } } },
  );
  hd("Anexo C. Referencias", 2);
  bl(
    [
      "INCIBE-CERT. La importancia de los informes técnicos (13/04/2023). incibe.es/incibe-cert/blog/importancia-los-informes-tecnicos",
      "MITRE ATT&CK. attack.mitre.org",
      "NIST SP 800-61 Rev. 2. Computer Security Incident Handling Guide",
      "FIRST. Traffic Light Protocol (TLP)",
    ],
    9,
  );
  d.setPage(tp);
  st.y = M + 14;
  tx("Índice", 14, 1, GR);
  st.y += 8;
  P.toc.forEach(([t, p]) => {
    d.setFontSize(10);
    d.setTextColor(40);
    d.text(cl(t), M, st.y);
    d.text(String(p), M + mw, st.y, { align: "right" });
    d.link(M, st.y - 11, mw, 15, { pageNumber: p });
    st.y += 18;
  });
  deco(P, "Informe técnico", 2);
  await dlp(d, `Informe_Tecnico_${CASE.caso}_v${CASE.version}.pdf`);
}
async function pdfExec() {
  const P = mk(),
    { d, st, tx, hd, tb, cl, M, mw } = P,
    e = exec();
  d.setFillColor(29, 29, 27);
  d.rect(0, 0, 595, 150, "F");
  d.setFillColor(...GR);
  d.rect(M, 50, 50, 4, "F");
  d.setTextColor(255);
  d.setFont("helvetica", "bold");
  d.setFontSize(24);
  d.text(cl("Informe ejecutivo de ciberseguridad"), M, 92);
  d.setFont("helvetica", "normal");
  d.setFontSize(11);
  d.setTextColor(200, 205, 211);
  d.text(
    cl(
      `${nm("cliente")}  |  Caso ${CASE.caso}  |  ${new Date().toLocaleDateString("es")}  |  ${CASE.clase}`,
    ),
    M,
    114,
  );
  d.text(cl(`Preparado por: ${nm("analista")}  |  Para: ${nm("dir")}`), M, 132);
  st.y = 185;
  d.setFillColor(...rgb(e.nivel));
  d.roundedRect(M, st.y - 14, mw, 44, 6, 6, "F");
  d.setTextColor(e.nivel == "Medio" ? 20 : 255);
  d.setFont("helvetica", "bold");
  d.setFontSize(16);
  d.text(
    cl(`Nivel de riesgo global: ${e.nivel.toUpperCase()}`),
    M + 14,
    st.y + 13,
  );
  st.y += 52;
  tx(AIX.t || e.intro, 11);
  hd("¿Qué pasó?", 2);
  e.que.forEach((x) => tx("•  " + x, 10, 0, [40, 40, 40], 6));
  hd("¿Qué significa para el negocio?", 2);
  e.imp.forEach((x) => tx("•  " + x, 10, 0, [40, 40, 40], 6));
  hd("Decisiones que se requieren de la Dirección", 2);
  e.dec.forEach((x, i) => tx(`${i + 1}.  ${x}`, 10, 0, [40, 40, 40], 6));
  hd("Plan en tres horizontes", 2);
  tb(
    ["Horizonte", "Qué se hará"],
    [
      [
        "0-24 horas",
        "Aislar sistemas afectados, bloquear direcciones externas, restablecer credenciales comprometidas, preservar evidencias.",
      ],
      [
        "1-7 días",
        "Investigación forense, eliminar software no autorizado, verificar copias de seguridad, evaluar notificaciones legales.",
      ],
      [
        "30 días",
        "Autenticación multifactor, segmentación de red, mejoras de monitoreo y simulacros de respuesta.",
      ],
    ],
    { columnStyles: { 0: { cellWidth: 90, fontStyle: "bold" } } },
  );
  hd("Términos clave", 2);
  tb(
    ["Término", "Significado"],
    GLO.filter(
      (g) =>
        ["Exfiltración", "Movimiento lateral", "Persistencia", "TLP"].includes(
          g[0],
        ) || g[0] == "IOC",
    ),
    { columnStyles: { 1: { cellWidth: 360 } } },
  );
  tx(
    "Este resumen se basa exclusivamente en los registros del SIEM analizados. El detalle técnico y las evidencias están en el Informe técnico del caso.",
    8,
    0,
    [110, 110, 110],
  );
  deco(P, "Informe ejecutivo", 2);
  await dlp(d, "Informe_Ejecutivo_SOC_L2.pdf");
}
nav();
vCarga();

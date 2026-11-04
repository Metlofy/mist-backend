// detectionEngine.mjs

function collectArtifactNames(report) {
  const names = [];
  for (const p of report.processes ?? []) names.push(p.name, p.path, p.windowTitle);
  for (const p of report.prefetch ?? []) names.push(p.fileName);
  for (const b of report.bam ?? []) names.push(b.path);
  for (const e of report.eventLog ?? []) names.push(e.summary, e.taskName);
  for (const s of report.shimCache ?? []) names.push(s.path);
  for (const a of report.amcache ?? []) names.push(a.path);
  for (const r of report.rpf ?? []) names.push(r.path);
  for (const m of report.modules ?? []) names.push(m.moduleName, m.path, m.ownerProcess);
  for (const r of report.memoryRegions ?? []) if (r.strings_found) names.push(r.strings_found);
  for (const k of report.runKeys ?? []) names.push(k.name, k.command, k.hive);
  for (const d of report.deletedFiles ?? []) names.push(d.originalPath ?? d.path);
  for (const u of report.userAssist ?? []) names.push(u.path);
  for (const s of report.services ?? []) names.push(s.name, s.displayName, s.binaryPath);
  for (const n of report.networkConnections ?? []) names.push(n.remoteAddress, n.processName);
  for (const d of report.dnsCache ?? []) names.push(d.entryName);
  for (const f of report.suspiciousFiles ?? []) names.push(f);
  for (const b of report.browserHits ?? []) names.push(b);
  if (report.clipboardText) names.push(report.clipboardText);
  for (const c of report.clipboardHistory ?? []) names.push(c);
  if (report.fivemDeep) {
    for (const h of report.fivemDeep.suspiciousLogHits ?? []) names.push(h.content, h.pattern);
    for (const d of report.fivemDeep.crashDumps ?? []) names.push(d.fileName);
    for (const f of report.fivemDeep.pluginAndModFiles ?? []) names.push(f.fileName, f.relativePath);
  }
  return names.filter(Boolean).map((n) => n.toLowerCase());
}

function collectArtifactHashes(report) {
  const hashes = [];
  for (const a of report.amcache ?? []) if (a.sha1) hashes.push(a.sha1);
  for (const m of report.modules ?? []) if (m.sha1) hashes.push(m.sha1);
  if (report.fivemDeep) {
    for (const f of report.fivemDeep.pluginAndModFiles ?? []) if (f.sha1) hashes.push(f.sha1);
  }
  return hashes.filter(Boolean).map((h) => h.toLowerCase());
}

// ---- Beyaz liste ------------------------------------------------------------
// Kural tipleri:
//   allow_hash : SHA-1 eşleşen artefakt, filename/regex/fuzzy eşleşmelerine GİRMEZ.
//                (Sadece SHA-1 taşıyan kayıtlarda çalışır: amcache, modüller, FiveM dosyaları.)
//   allow_path : yolu bu parçayı içeren artefakt, filename/regex/fuzzy eşleşmelerine girmez.
// "hash" ve "warning" kuralları beyaz listeden ETKİLENMEZ (kesin kötü / istemci kanıtı).
function normPath(s) {
  return String(s).toLowerCase().replace(/\//g, "\\");
}

// Tam yol -> sha1. Aynı anahtar farklı hash'lere gidiyorsa belirsiz sayılır ve atılır
// (aynı adlı kötü dosyanın meşru dosya gibi görünmesini engeller).
function collectHashByName(report) {
  const map = new Map();
  const ambiguous = new Set();
  const add = (sha, ...keys) => {
    if (!sha) return;
    const h = String(sha).toLowerCase();
    for (const k of keys) {
      if (!k) continue;
      const key = String(k).toLowerCase();
      if (map.has(key) && map.get(key) !== h) ambiguous.add(key);
      map.set(key, h);
    }
  };
  for (const a of report.amcache ?? []) add(a.sha1, a.path);
  for (const m of report.modules ?? []) add(m.sha1, m.path, m.path ? m.moduleName : null);
  if (report.fivemDeep) {
    for (const f of report.fivemDeep.pluginAndModFiles ?? []) add(f.sha1, f.relativePath, f.relativePath ? f.fileName : null);
  }
  for (const k of ambiguous) map.delete(k);
  return map;
}

// Dosya adı -> tam yol (sadece belirsiz olmayanlar). allow_path, yalnızca adı geçen
// kayıtların (ör. modül adı) tam yolu beyaz listedeyse o adı da dışarıda bırakır.
function collectFullPathByName(report) {
  const map = new Map();
  const ambiguous = new Set();
  const add = (name, full) => {
    if (!name || !full) return;
    const k = String(name).toLowerCase();
    const f = String(full).toLowerCase();
    if (map.has(k) && map.get(k) !== f) ambiguous.add(k);
    map.set(k, f);
  };
  for (const m of report.modules ?? []) add(m.moduleName, m.path);
  for (const f of report.fivemDeep?.pluginAndModFiles ?? []) add(f.fileName, f.relativePath);
  for (const k of ambiguous) map.delete(k);
  return map;
}

function applyWhitelist(allNames, hashByName, fullPathByName, rules) {
  const allowHashes = new Set();
  const allowPaths = [];
  for (const r of rules) {
    if (!r.enabled) continue;
    if (r.type === "allow_hash") allowHashes.add(String(r.match).toLowerCase().trim());
    else if (r.type === "allow_path") allowPaths.push({ frag: normPath(r.match.trim()), name: r.name });
  }
  if (allowHashes.size === 0 && allowPaths.length === 0) return { names: allNames, whitelisted: [] };

  const names = [];
  const whitelisted = [];
  const seen = new Set();
  for (const n of allNames) {
    let by = null;
    const sha = hashByName.get(n);
    if (sha && allowHashes.has(sha)) {
      by = `allow_hash:${sha.slice(0, 12)}`;
    } else {
      const np = normPath(n);
      const full = fullPathByName.get(n);
      const npFull = full ? normPath(full) : "";
      const hit = allowPaths.find((p) => np.includes(p.frag) || (npFull && npFull.includes(p.frag)));
      if (hit) by = `allow_path:${hit.name}`;
    }
    if (by) {
      if (!seen.has(n) && whitelisted.length < 100) { seen.add(n); whitelisted.push({ name: n, by }); }
    } else {
      names.push(n);
    }
  }
  return { names, whitelisted };
}

function compileRegex(pattern) {
  try { return new RegExp(pattern, "i"); } catch { return null; }
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Levenshtein distance for fuzzy matching
function levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix = Array.from(new Array(a.length + 1), () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost);
    }
  }
  return matrix[a.length][b.length];
}

function getBasename(path) {
  return path.split(/[\\/]/).pop();
}

function evidenceSource(report, value, type) {
  if (type === "hash") return "sha1";
  if (type === "warning") return "client_warning";
  const hit = String(value ?? "").toLowerCase();
  const has = (items, fields) => (items ?? []).some((item) => fields.some((field) => String(item?.[field] ?? "").toLowerCase() === hit));
  const checks = [
    ["processes", report.processes, ["name", "path", "windowTitle"]], ["prefetch", report.prefetch, ["fileName"]],
    ["bam", report.bam, ["path"]], ["eventLog", report.eventLog, ["summary", "taskName"]],
    ["shimCache", report.shimCache, ["path"]], ["amcache", report.amcache, ["path"]], ["rpf", report.rpf, ["path"]],
    ["modules", report.modules, ["moduleName", "path", "ownerProcess"]], ["memory", report.memoryRegions, ["strings_found"]],
    ["runKeys", report.runKeys, ["name", "command", "hive"]], ["deletedFiles", report.deletedFiles, ["originalPath", "path"]],
    ["userAssist", report.userAssist, ["path"]], ["services", report.services, ["name", "displayName", "binaryPath"]],
    ["network", report.networkConnections, ["remoteAddress", "processName"]], ["dns", report.dnsCache, ["entryName"]],
  ];
  for (const [source, items, fields] of checks) if (has(items, fields)) return source;
  if ((report.suspiciousFiles ?? []).some((x) => String(x).toLowerCase() === hit)) return "suspiciousFiles";
  if ((report.browserHits ?? []).some((x) => String(x).toLowerCase() === hit)) return "browserHits";
  if (report.fivemDeep) {
    if (has(report.fivemDeep.suspiciousLogHits, ["content", "pattern"])) return "fivemLogs";
    if (has(report.fivemDeep.crashDumps, ["fileName"])) return "crashDumps";
    if (has(report.fivemDeep.pluginAndModFiles, ["fileName", "relativePath"])) return "fivemFiles";
  }
  return "unknown";
}

export function runDetectionsDetailed(report, rules) {
  const detections = [];
  const { names, whitelisted } = applyWhitelist(collectArtifactNames(report), collectHashByName(report), collectFullPathByName(report), rules);
  const hashes = collectArtifactHashes(report);
  const warningCodes = new Set((report.warnings ?? []).map((w) => w.code));

  for (const rule of rules) {
    if (!rule.enabled) continue;

    if (rule.type === "filename") {
      const needle = rule.match.toLowerCase().trim();
      if (!needle) continue;

      const hit = names.find((n) => {
        const base = getBasename(n);
        // 1. Dosya adı tam eşleşme (örn: redengine.exe, eulen.dll)
        if (base === needle || base === needle + '.exe' || base === needle + '.dll') return true;
        // 2. Dosya adı içinde geçiyor mu (örn: redengine_v3, my_eulen_loader, ksdumper-v2)
        if (base.includes(needle)) return true;
        // 3. Klasör yolu veya tam ad içinde kelime olarak geçiyor mu
        if (n.includes('\\' + needle) || n.includes('/' + needle) || n.includes(needle + '\\') || n.includes(needle + '/')) return true;
        return false;
      });
      
      if (hit) {
        detections.push({ ruleId: rule.id, type: rule.type, name: rule.name, severity: rule.severity, evidence: hit, source: evidenceSource(report, hit, rule.type), note: rule.note });
      }
    }

    if (rule.type === "regex") {
      const re = compileRegex(rule.match);
      const hit = re ? names.find((n) => re.test(n)) : null;
      if (hit) {
        detections.push({ ruleId: rule.id, type: rule.type, name: rule.name, severity: rule.severity, evidence: hit, source: evidenceSource(report, hit, rule.type), note: rule.note });
      }
    }

    if (rule.type === "fuzzy") {
      const needle = rule.match.toLowerCase();
      const threshold = rule.match.length > 5 ? 2 : 1; // 1 or 2 typos allowed
      const hit = names.find((n) => {
         const base = getBasename(n).replace(/\.(exe|dll|sys|bin)$/, '');
         return Math.abs(base.length - needle.length) <= threshold && levenshtein(base, needle) <= threshold;
      });
      if (hit) {
        detections.push({ ruleId: rule.id, type: rule.type, name: rule.name, severity: rule.severity, evidence: hit, source: evidenceSource(report, hit, rule.type), note: rule.note });
      }
    }

    if (rule.type === "hash") {
      const needle = rule.match.toLowerCase().trim();
      if (hashes.includes(needle)) {
        detections.push({ ruleId: rule.id, type: rule.type, name: rule.name, severity: rule.severity, evidence: needle, source: "sha1", note: rule.note });
      }
    }

    if (rule.type === "warning" && warningCodes.has(rule.match)) {
      detections.push({ ruleId: rule.id, type: rule.type, name: rule.name, severity: rule.severity, evidence: rule.match, source: "client_warning", note: rule.note });
    }
  }

  return { detections, whitelisted };
}

// Geriye dönük uyumluluk: sadece tespit listesi
export function runDetections(report, rules) {
  return runDetectionsDetailed(report, rules).detections;
}

// ---- Karar mantığı --------------------------------------------------------
// Kanıt gücüne göre ağırlıklandırma:
//   - Güçlü kanıt: tam SHA-1 eşleşmesi; tek başına yüksek önem derecesinde yeterlidir.
//   - Dosya adı/regex/fuzzy ve warning eşleşmeleri tek başına kesin karar vermez;
//     cheating için farklı kaynak ve farklı kanıt birlikte aranır.

export function summarize(detections) {
  if (detections.length === 0) return "clean";
  const high = detections.filter((d) => d.severity === "high");
  if (high.some((d) => d.type === "hash")) return "cheating";
  // Dosya adı/regex/fuzzy gibi eşleşmeler yalnızca farklı kaynak ve kanıtlarla birleşince karar oluşturur.
  const corroborating = high.filter((d) => d.type !== "hash" && d.source && d.source !== "unknown");
  const hasIndependentPair = corroborating.some((a, i) => corroborating.slice(i + 1).some((b) =>
    a.source !== b.source && String(a.evidence).toLowerCase() !== String(b.evidence).toLowerCase()));
  if (hasIndependentPair) return "cheating";
  return "suspicious";
}

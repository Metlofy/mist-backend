// ruleImport.mjs
//
// Turns a plain text file (one signature per line) into fully-formed rule
// objects, the same shape db.mjs's addRule() expects - without staff having
// to type name/severity/type for every single entry by hand.
//
// LINE FORMAT
//   One entry per line. Two ways to write a line:
//
//     value
//       Bare value - everything else (type, severity, name, note) is
//       inferred automatically. This is the common case for a big pasted
//       hash list or filename list.
//
//     value,severity,name,note
//       CSV-style override - any of severity/name/note left blank falls
//       back to auto-generation for that field only. Commas inside `note`
//       are fine as long as you don't need commas in value/severity/name
//       (rare in practice for hashes/filenames/single words).
//
//   Blank lines and lines starting with # are ignored (comments).
//
// AUTO TYPE DETECTION
//   A 40-character hex string is treated as a SHA-1 hash (matches
//   AmcacheCollector/ModuleCollector's Sha1 fields). Anything else is
//   treated as a filename/substring match.
//
// AUTO SEVERITY
//   hash     -> "high"   (an exact binary match is about as strong as
//                          triage evidence gets - it's the same file, not
//                          just a similarly-named one)
//   filename -> "high" if the value contains a term commonly seen in
//                          cheat/injector tooling (see RISK_KEYWORDS below),
//                          otherwise "medium" - a bare filename/substring
//                          match is trivially evaded by renaming, so it
//                          doesn't earn "high" on name alone unless it's a
//                          recognizably cheat-related string.
//
// AUTO NAME / NOTE
//   Generated from the value and type so the rule list is still readable
//   without staff having typed anything - see buildName()/buildNote().
//
// DEDUPE
//   A rule is skipped if a rule with the same (type, match) already exists
//   - case-insensitively - either in the existing rule set or earlier in
//   the same import batch. This makes re-importing the same or an updated
//   list idempotent instead of piling up duplicates.

const HASH_RE = /^[a-f0-9]{40}$/i;

// Not exhaustive - a curated starting point. Real deployments should tune
// this list from what staff actually see flagged in practice.
const RISK_KEYWORDS = [
  "inject", "injector", "loader", "cheat", "hack", "aimbot", "wallhack",
  "esp", "trigger", "spoof", "hwid", "bypass", "manual map", "manualmap",
  "unlock all", "godmode", "cheat engine", "cheatengine", "extreme injector",
  "dll injector", "menu.dll", "colorbot",
];

function detectType(value) {
  return HASH_RE.test(value.trim()) ? "hash" : "filename";
}

function detectSeverity(type, value) {
  if (type === "hash") return "high";
  const lower = value.toLowerCase();
  return RISK_KEYWORDS.some((kw) => lower.includes(kw)) ? "high" : "medium";
}

function buildName(type, value) {
  if (type === "hash") {
    const short = value.length > 12 ? `${value.slice(0, 12)}…` : value;
    return `Bilinen Hash: ${short}`;
  }
  return `Bilinen Dosya: ${value}`;
}

function buildNote(type, value, sourceLabel) {
  const provenance = sourceLabel
    ? `Toplu içe aktarma ile eklendi (kaynak: ${sourceLabel}).`
    : "Toplu içe aktarma ile eklendi.";
  if (type === "hash") {
    return `${provenance} SHA-1 tam eşleşmesi - aynı ikili dosya, güçlü kanıt.`;
  }
  return `${provenance} Dosya adı/alt dizge eşleşmesi - yeniden adlandırmayla atlatılabilir, tek başına kesin kanıt değildir.`;
}

const VALID_SEVERITIES = new Set(["high", "medium", "low"]);

/**
 * @param {string} text - raw file contents.
 * @param {Array} existingRules - current rule set, for dedupe.
 * @param {string} [sourceLabel] - e.g. the uploaded file's name, for the
 *   auto-generated note's provenance line.
 * @returns {{ created: Array, skipped: Array<{line: number, value: string, reason: string}> }}
 */
export function parseRuleImport(text, existingRules, sourceLabel) {
  const seen = new Set(
    (existingRules ?? []).map((r) => `${r.type}::${r.match.toLowerCase()}`)
  );

  const created = [];
  const skipped = [];

  const lines = (text ?? "").split(/\r?\n/);

  lines.forEach((rawLine, idx) => {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) return;

    const parts = line.split(",").map((p) => p.trim());
    const value = parts[0];
    if (!value) {
      skipped.push({ line: idx + 1, value: rawLine, reason: "boş değer" });
      return;
    }

    const type = detectType(value);
    const key = `${type}::${value.toLowerCase()}`;
    if (seen.has(key)) {
      skipped.push({ line: idx + 1, value, reason: "zaten mevcut (aynı tip + eşleşme)" });
      return;
    }

    const severityOverride = parts[1];
    const nameOverride = parts[2];
    const noteOverride = parts.slice(3).join(",").trim(); // allow commas inside the note

    const severity =
      severityOverride && VALID_SEVERITIES.has(severityOverride.toLowerCase())
        ? severityOverride.toLowerCase()
        : detectSeverity(type, value);

    const name = nameOverride || buildName(type, value);
    const note = noteOverride || buildNote(type, value, sourceLabel);

    created.push({
      name,
      severity,
      type,
      match: value,
      note,
      enabled: true,
    });

    seen.add(key);
  });

  return { created, skipped };
}

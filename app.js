const input = document.querySelector("#input");
const output = document.querySelector("#output");
const formatBtn = document.querySelector("#formatBtn");
const copyBtn = document.querySelector("#copyBtn");
const downloadBtn = document.querySelector("#downloadBtn");
const clearBtn = document.querySelector("#clearBtn");
const chooseExampleBtn = document.querySelector("#chooseExampleBtn");
const closeExampleBtn = document.querySelector("#closeExampleBtn");
const randomExampleBtn = document.querySelector("#randomExampleBtn");
const examplePanel = document.querySelector("#examplePanel");
const exampleSearch = document.querySelector("#exampleSearch");
const exampleList = document.querySelector("#exampleList");
const exampleCount = document.querySelector("#exampleCount");
const indentSize = document.querySelector("#indentSize");
const themeMode = document.querySelector("#themeMode");
const compactBlankLines = document.querySelector("#compactBlankLines");
const statusBox = document.querySelector("#status");
const highlightedOutput = document.querySelector("#highlightedOutput");
const validationBadge = document.querySelector("#validationBadge");
const lintResultsPanel = document.querySelector("#lintResultsPanel");
const lintResultCount = document.querySelector("#lintResultCount");
const lintResults = document.querySelector("#lintResults");
const versionBadge = document.querySelector("[data-version-badge]");
const toast = document.querySelector("#toast");

const appConfig = window.YARALINT_CONFIG || {
  version: "1.0.8",
  build: "2026-05-19T17:15:35-05:00"
};
const sectionPattern = /^(meta|strings|events|match|outcome|condition|options):$/i;
const githubRawBase = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/";
const exampleCachePrefix = "yaraLFormatterExample:";
const examples = [
  { filename: "apt_cobaltstrike.yar", category: "APT", tags: ["apt", "cobalt strike", "beacon"] },
  { filename: "apt_apt28.yar", category: "APT", tags: ["apt28", "fancy bear", "malware"] },
  { filename: "apt_apt29_nobelium_may21.yar", category: "APT", tags: ["apt29", "nobelium", "backdoor"] },
  { filename: "apt_fin7.yar", category: "APT", tags: ["fin7", "crimeware", "backdoor"] },
  { filename: "apt_blackenergy.yar", category: "APT", tags: ["blackenergy", "ics", "malware"] },
  { filename: "gen_webshells.yar", category: "Webshells", tags: ["webshell", "php", "jsp"] },
  { filename: "gen_webshells_ext_vars.yar", category: "Webshells", tags: ["webshell", "external vars"] },
  { filename: "gen_mal_3cx_compromise_mar23.yar", category: "Malware", tags: ["3cx", "supply chain", "malware"] },
  { filename: "gen_mimikatz.yar", category: "Malware", tags: ["mimikatz", "credential theft"] },
  { filename: "gen_powershell_empire.yar", category: "Loaders", tags: ["powershell", "empire", "loader"] },
  { filename: "gen_xor_hunting.yar", category: "Loaders", tags: ["xor", "encoded", "hunting"] },
  { filename: "expl_log4j_cve_2021_44228.yar", category: "Exploits", tags: ["log4j", "cve", "exploit"] },
  { filename: "expl_proxyshell.yar", category: "Exploits", tags: ["exchange", "proxyshell", "webshell"] },
  { filename: "vuln_moveit_0day_jun23.yar", category: "Exploits", tags: ["moveit", "zero-day", "cve"] },
  { filename: "generic_anomalies.yar", category: "Generic", tags: ["anomaly", "hunting", "generic"] },
  { filename: "general_cloaking.yar", category: "Generic", tags: ["cloaking", "evasion"] }
].map((example) => ({
  ...example,
  url: `${githubRawBase}${example.filename}`,
  keywords: `${example.filename} ${example.category} ${example.tags.join(" ")}`.toLowerCase()
}));
let toastTimer;

function setStatus(message, type = "ok") {
  statusBox.textContent = message;
  statusBox.className = `status${type === "ok" ? "" : ` ${type}`}`;
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.remove("show");
  }, 2200);
}

function normalizeOperators(line) {
  if (line === "{") {
    return "{";
  }

  return line
    .replace(/\s+$/g, "")
    .replace(/\s*{\s*$/g, " {")
    .replace(/^\s*}\s*$/g, "}")
    .replace(/:\s*$/g, ":");
}

function countOutsideQuotes(line, character) {
  let count = 0;
  let quote = null;
  let escaped = false;

  for (const char of line) {
    if (escaped) {
      escaped = false;
      continue;
    }

    if (char === "\\") {
      escaped = true;
      continue;
    }

    if ((char === '"' || char === "'") && quote === null) {
      quote = char;
      continue;
    }

    if (char === quote) {
      quote = null;
      continue;
    }

    if (quote === null && char === character) {
      count += 1;
    }
  }

  return count;
}

function countLeadingClosingBraces(line) {
  const match = line.match(/^}+/);
  return match ? match[0].length : 0;
}

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function highlightLine(line) {
  return escapeHtml(line)
    .replace(/(#.*)$/gm, '<span class="token-comment">$1</span>')
    .replace(/("(?:\\.|[^"\\])*")/g, '<span class="token-string">$1</span>')
    .replace(/(^|\s)(\$[A-Za-z_][\w.]*)/g, '$1<span class="token-variable">$2</span>')
    .replace(/\b(rule|and|or|not|nocase|re|regex|any|all|of|them|in|over|match|outcome|condition|events|strings|meta|options)\b/g, '<span class="token-keyword">$1</span>')
    .replace(/(^\s*)(meta|strings|events|match|outcome|condition|options):/gim, '$1<span class="token-section">$2:</span>');
}

function highlightYaraL(source, fixedLines = new Set()) {
  return source.split("\n").map((line, index) => {
    const lineNumber = index + 1;
    const className = fixedLines.has(lineNumber) ? "code-line fixed-line" : "code-line";
    return `<span class="${className}" data-line="${lineNumber}">${highlightLine(line) || " "}</span>`;
  }).join("");
}

function updateHighlightedOutput(fixedLines = new Set()) {
  highlightedOutput.innerHTML = output.value.trim()
    ? highlightYaraL(output.value, fixedLines)
    : "";
}

function formatYaraL(source, options) {
  const indentUnit = " ".repeat(options.indentSize);
  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  const formatted = [];
  const warnings = [];
  let indentLevel = 0;
  let sectionIndentLevel = null;
  let previousWasBlank = false;

  lines.forEach((rawLine, index) => {
    const trimmed = rawLine.trim();

    if (trimmed === "") {
      if (!options.compactBlankLines || !previousWasBlank) {
        formatted.push("");
      }
      previousWasBlank = true;
      return;
    }

    previousWasBlank = false;

    let line = normalizeOperators(trimmed);
    const closes = countOutsideQuotes(line, "}");
    const opens = countOutsideQuotes(line, "{");
    const leadingCloses = countLeadingClosingBraces(line);

    if (leadingCloses > 0) {
      indentLevel = Math.max(indentLevel - leadingCloses, 0);
      if (sectionIndentLevel !== null && indentLevel <= sectionIndentLevel) {
        sectionIndentLevel = null;
      }
    }

    if (sectionPattern.test(line)) {
      formatted.push(`${indentUnit.repeat(indentLevel)}${line}`);
      sectionIndentLevel = indentLevel;
    } else {
      const bodyIndent = sectionIndentLevel !== null && !line.startsWith("}")
        ? sectionIndentLevel + 1 + Math.max(indentLevel - sectionIndentLevel, 0)
        : indentLevel;
      formatted.push(`${indentUnit.repeat(bodyIndent)}${line}`);
    }

    indentLevel += opens - (closes - leadingCloses);

    if (indentLevel < 0) {
      warnings.push(`Line ${index + 1}: closing brace without a matching opening brace.`);
      indentLevel = 0;
    }
  });

  if (indentLevel > 0) {
    warnings.push(`${indentLevel} opening brace${indentLevel === 1 ? "" : "s"} may be missing a closing brace.`);
  }

  return {
    text: formatted.join("\n").trimEnd() + "\n",
    warnings
  };
}

const yaraLintEngine = (() => {
  const validStringModifiers = new Set(["ascii", "wide", "nocase", "fullword", "private"]);

  function makeIssue({ severity = "INFO", line = null, message, original = "", corrected = "", fixed = false, recommendation = "" }) {
    return { severity, line, message, original, corrected, fixed, recommendation };
  }

  function isSupportedModifier(modifier) {
    return validStringModifiers.has(modifier) || /^(xor|base64|base64wide)(\(.+\))?$/.test(modifier);
  }

  function quoteYaraText(value) {
    return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  }

  function getAutoQuoteMessage(value) {
    if (/^[0-9]+$/.test(value)) {
      return "Auto-quoted accidental numeric text assignment.";
    }

    if (/@/.test(value) || /\bmailto:/i.test(value) || /\b[a-z0-9.-]+\.[a-z]{2,}\b/i.test(value)) {
      return "Auto-quoted invalid raw email/domain string assignment.";
    }

    return "Auto-quoted invalid text string assignment.";
  }

  function shouldAutoQuoteBareString(value) {
    if (!value || value.startsWith("$")) {
      return false;
    }

    if (/[{};]/.test(value) || /\b(and|or|not)\b/i.test(value)) {
      return false;
    }

    if (/(^|[^=!<>])([=!<>]=|contains|matches| at | in )/i.test(value)) {
      return false;
    }

    return true;
  }

  function splitBareValueAndModifiers(value) {
    const parts = value.split(/\s+/);

    if (parts.length === 1) {
      return { value, modifiers: "" };
    }

    let modifierStart = parts.length;

    while (modifierStart > 0 && isSupportedModifier(parts[modifierStart - 1])) {
      modifierStart -= 1;
    }

    if (modifierStart > 0 && modifierStart < parts.length) {
      return {
        value: parts.slice(0, modifierStart).join(" "),
        modifiers: parts.slice(modifierStart).join(" ")
      };
    }

    return { value, modifiers: "" };
  }

  function hasUnclosedHexValue(lines) {
    return lines.some((line) => {
      const trimmed = line.trim();
      return /^\$[A-Za-z_][\w]*\s*=\s*\{/.test(trimmed) && !/\}/.test(trimmed);
    });
  }

  function inferSectionIndent(lines) {
    const section = lines.find((line) => getSectionName(line));
    const match = section ? section.match(/^(\s*)/) : null;
    return match ? match[1] : "  ";
  }

  function inferChildIndent(lines, sectionName) {
    let insideSection = false;

    for (const line of lines) {
      const currentSection = getSectionName(line);

      if (currentSection) {
        insideSection = currentSection === sectionName;
        continue;
      }

      if (!insideSection || !line.trim() || line.trim().startsWith("}")) {
        continue;
      }

      const match = line.match(/^(\s+)/);

      if (match) {
        return match[1];
      }
    }

    return `${inferSectionIndent(lines)}  `;
  }

  function findFinalRuleClosingLine(lines) {
    for (let index = lines.length - 1; index >= 0; index -= 1) {
      if (lines[index].trim() === "}") {
        return index;
      }
    }

    return -1;
  }

  function getStringIdentifiers(lines, context) {
    const identifiers = [];

    lines.forEach((line, index) => {
      const lineNumber = index + 1;

      if (context.sectionsByLine.get(lineNumber) !== "strings") {
        return;
      }

      const parsed = parseStringDeclaration(line);

      if (parsed) {
        identifiers.push(parsed.id);
      }
    });

    return identifiers;
  }

  function shiftFixedLinesAfterInsert(state, insertIndex, count) {
    const shifted = new Set();

    state.fixedLines.forEach((lineNumber) => {
      shifted.add(lineNumber > insertIndex ? lineNumber + count : lineNumber);
    });

    state.fixedLines = shifted;
  }

  function markFixedRange(state, startIndex, count) {
    for (let offset = 0; offset < count; offset += 1) {
      state.fixedLines.add(startIndex + offset + 1);
    }
  }

  function getUniqueStringIdentifier(id, seen) {
    const base = id.replace(/_\d+$/, "");
    let counter = 2;
    let candidate = `${base}_${counter}`;

    while (seen.has(candidate)) {
      counter += 1;
      candidate = `${base}_${counter}`;
    }

    return candidate;
  }

  function lineWithoutComment(line) {
    let quote = null;
    let escaped = false;

    for (let index = 0; index < line.length; index += 1) {
      const char = line[index];

      if (escaped) {
        escaped = false;
        continue;
      }

      if (char === "\\") {
        escaped = true;
        continue;
      }

      if ((char === '"' || char === "'") && quote === null) {
        quote = char;
        continue;
      }

      if (char === quote) {
        quote = null;
        continue;
      }

      if (quote === null && char === "#") {
        return line.slice(0, index);
      }
    }

    return line;
  }

  function getSectionName(line) {
    const match = line.trim().match(/^(meta|strings|events|match|outcome|condition|options):$/i);
    return match ? match[1].toLowerCase() : null;
  }

  function buildContext(lines) {
    const sectionsByLine = new Map();
    let currentSection = null;

    lines.forEach((line, index) => {
      const sectionName = getSectionName(line);

      if (sectionName) {
        currentSection = sectionName;
      }

      sectionsByLine.set(index + 1, currentSection);
    });

    return { sectionsByLine };
  }

  function findClosingQuote(value, quoteChar) {
    let escaped = false;

    for (let index = 1; index < value.length; index += 1) {
      const char = value[index];

      if (escaped) {
        escaped = false;
        continue;
      }

      if (char === "\\") {
        escaped = true;
        continue;
      }

      if (char === quoteChar) {
        return index;
      }
    }

    return -1;
  }

  function splitValueAndModifiers(rawValue) {
    const value = rawValue.trim();

    if (!value) {
      return { kind: "missing", value: "", modifiers: "", validValueBoundary: false };
    }

    if (value.startsWith('"') || value.startsWith("'")) {
      const end = findClosingQuote(value, value[0]);
      return {
        kind: value[0] === '"' ? "text" : "singleText",
        value: end === -1 ? value : value.slice(0, end + 1),
        modifiers: end === -1 ? "" : value.slice(end + 1).trim(),
        validValueBoundary: end !== -1
      };
    }

    if (value.startsWith("/")) {
      const end = findClosingQuote(value, "/");
      return {
        kind: "regex",
        value: end === -1 ? value : value.slice(0, end + 1),
        modifiers: end === -1 ? "" : value.slice(end + 1).trim(),
        validValueBoundary: end !== -1
      };
    }

    if (value.startsWith("{")) {
      const end = value.lastIndexOf("}");
      return {
        kind: "hex",
        value: end === -1 ? value : value.slice(0, end + 1),
        modifiers: end === -1 ? "" : value.slice(end + 1).trim(),
        validValueBoundary: end !== -1
      };
    }

    const bare = splitBareValueAndModifiers(value);
    return {
      kind: "bare",
      value: bare.value,
      modifiers: bare.modifiers,
      validValueBoundary: true
    };
  }

  function parseStringDeclaration(line) {
    const match = lineWithoutComment(line).match(/^(\s*)(\$[A-Za-z_][\w]*)\s*=\s*(.+?)\s*$/);

    if (!match) {
      return null;
    }

    const parsed = splitValueAndModifiers(match[3]);
    return {
      indent: match[1],
      id: match[2],
      rawValue: match[3],
      ...parsed
    };
  }

  function parseMetaAssignment(line) {
    const match = lineWithoutComment(line).match(/^(\s*)([A-Za-z_][\w]*)\s*=\s*(.+?)\s*$/);

    if (!match) {
      return null;
    }

    return {
      indent: match[1],
      key: match[2],
      rawValue: match[3],
      ...splitValueAndModifiers(match[3])
    };
  }

  function rebuildStringDeclaration(parsed, value) {
    const modifiers = parsed.modifiers ? ` ${parsed.modifiers}` : "";
    return `${parsed.indent}${parsed.id} = ${value}${modifiers}`;
  }

  function rebuildMetaAssignment(parsed, value) {
    return `${parsed.indent}${parsed.key} = ${value}`;
  }

  function normalizeSingleQuotedValue(value) {
    const inner = value.slice(1, -1).replace(/"/g, '\\"');
    return `"${inner}"`;
  }

  function validateModifiers(modifiers) {
    if (!modifiers) {
      return [];
    }

    return modifiers.split(/\s+/).filter((modifier) => {
      if (validStringModifiers.has(modifier)) {
        return false;
      }

      return !/^(xor|base64|base64wide)(\(.+\))?$/.test(modifier);
    });
  }

  function validateHexString(hexValue) {
    if (!hexValue.startsWith("{") || !hexValue.endsWith("}")) {
      return ["Hex string must start with { and end with }."];
    }

    const body = hexValue.slice(1, -1).trim();

    if (!body) {
      return ["Hex string is empty."];
    }

    return body.split(/\s+/).filter((token) => {
      if (/^[0-9A-Fa-f?]{2}$/.test(token)) {
        return false;
      }

      if (/^\[\d+(-\d+)?\]$/.test(token)) {
        return false;
      }

      return !["(", ")", "|"].includes(token);
    }).map((token) => `Invalid hex token: ${token}`);
  }

  const validators = [
    {
      id: "duplicate-rule-identifiers",
      validate(state) {
        const seen = new Map();

        state.lines.forEach((line, index) => {
          const match = line.trim().match(/^rule\s+([A-Za-z_][\w]*)\b/);

          if (!match) {
            return;
          }

          if (seen.has(match[1])) {
            state.issues.push(makeIssue({
              severity: "ERROR",
              line: index + 1,
              message: `Duplicate rule identifier: ${match[1]}.`,
              original: line,
              recommendation: "Rename one of the rules so every rule identifier is unique."
            }));
            return;
          }

          seen.set(match[1], index + 1);
        });
      }
    },
    {
      id: "string-declarations",
      validate(state) {
        const seen = new Map();

        state.lines.forEach((line, index) => {
          const lineNumber = index + 1;
          const section = state.context.sectionsByLine.get(lineNumber);
          const trimmed = line.trim();

          if (/^rule\s+[A-Za-z_][\w]*\b/.test(trimmed)) {
            seen.clear();
          }

          if (section !== "strings" || !trimmed || trimmed.startsWith("#") || trimmed.startsWith("}") || getSectionName(line)) {
            return;
          }

          let currentLine = state.lines[index];
          let parsed = parseStringDeclaration(currentLine);

          if (!parsed) {
            state.issues.push(makeIssue({
              severity: "ERROR",
              line: lineNumber,
              message: "Invalid string declaration. Expected format like $id = \"text\", $id = /regex/, or $id = { 4D 5A }.",
              original: currentLine,
              recommendation: "Use a valid YARA string identifier and assignment syntax."
            }));
            return;
          }

          if (seen.has(parsed.id)) {
            if (state.allowFixes) {
              const originalId = parsed.id;
              const correctedId = getUniqueStringIdentifier(originalId, seen);
              parsed = { ...parsed, id: correctedId };
              const corrected = rebuildStringDeclaration(parsed, parsed.value);
              state.lines[index] = corrected;
              state.fixedLines.add(lineNumber);
              state.issues.push(makeIssue({
                severity: "FIXED",
                line: lineNumber,
                message: `Renamed duplicate string identifier ${originalId} to ${correctedId}.`,
                original: currentLine,
                corrected,
                fixed: true,
                recommendation: "Review direct condition references if this rule did not use any/all of them."
              }));
              currentLine = corrected;
              seen.set(correctedId, lineNumber);
            } else {
              state.issues.push(makeIssue({
                severity: "ERROR",
                line: lineNumber,
                message: `Duplicate string identifier: ${parsed.id}.`,
                original: currentLine,
                recommendation: "Rename the duplicate identifier and update condition references if needed."
              }));
              return;
            }
          } else {
            seen.set(parsed.id, lineNumber);
          }

          if (!parsed.validValueBoundary) {
            if (state.allowFixes && (parsed.kind === "text" || parsed.kind === "singleText")) {
              const correctedValue = parsed.kind === "text"
                ? `${parsed.value}"`
                : quoteYaraText(parsed.value.slice(1));
              const corrected = rebuildStringDeclaration(parsed, correctedValue);
              state.lines[index] = corrected;
              state.fixedLines.add(lineNumber);
              state.issues.push(makeIssue({
                severity: "FIXED",
                line: lineNumber,
                message: "Added missing closing quote to string assignment.",
                original: currentLine,
                corrected,
                fixed: true
              }));
              currentLine = corrected;
              parsed = parseStringDeclaration(currentLine);

              if (!parsed) {
                return;
              }
            } else {
              state.issues.push(makeIssue({
                severity: "ERROR",
                line: lineNumber,
                message: "Unterminated string, regex, or hex value.",
                original: currentLine,
                recommendation: "Close the string, regex, or hex value before formatting again."
              }));
              return;
            }
          }

          if (parsed.kind === "bare" && state.allowFixes && shouldAutoQuoteBareString(parsed.value)) {
            const corrected = rebuildStringDeclaration(parsed, quoteYaraText(parsed.value));
            state.lines[index] = corrected;
            state.fixedLines.add(lineNumber);
            state.issues.push(makeIssue({
              severity: "FIXED",
              line: lineNumber,
              message: getAutoQuoteMessage(parsed.value),
              original: currentLine,
              corrected,
              fixed: true
            }));
            currentLine = corrected;
          } else if (parsed.kind === "singleText" && parsed.validValueBoundary) {
            if (state.allowFixes) {
              const corrected = rebuildStringDeclaration(parsed, normalizeSingleQuotedValue(parsed.value));
              state.lines[index] = corrected;
              state.fixedLines.add(lineNumber);
              state.issues.push(makeIssue({
                severity: "FIXED",
                line: lineNumber,
                message: "Normalized single-quoted string to YARA-compatible double quotes.",
                original: currentLine,
                corrected,
                fixed: true
              }));
              currentLine = corrected;
            } else {
              state.issues.push(makeIssue({
                severity: "ERROR",
                line: lineNumber,
                message: "Single-quoted strings are not valid YARA string values.",
                original: currentLine,
                recommendation: "Use double quotes for text strings."
              }));
            }
          } else if (parsed.kind === "bare") {
            state.issues.push(makeIssue({
              severity: "ERROR",
              line: lineNumber,
              message: "String value must be quoted text, a regex, or a hex string.",
              original: currentLine,
              recommendation: "Wrap plain text string values in double quotes, or use /regex/ or { hex } syntax."
            }));
          }

          if (parsed.kind === "hex") {
            validateHexString(parsed.value).forEach((message) => {
              state.issues.push(makeIssue({
                severity: "ERROR",
                line: lineNumber,
                message,
                original: currentLine,
                recommendation: "Use two-character hex bytes, wildcards, jumps, or grouping tokens inside { }."
              }));
            });
          }

          validateModifiers(parsed.modifiers).forEach((modifier) => {
            state.issues.push(makeIssue({
              severity: "ERROR",
              line: lineNumber,
              message: `Invalid string modifier: ${modifier}.`,
              original: currentLine,
              recommendation: "Use supported YARA string modifiers such as ascii, wide, nocase, fullword, private, xor, base64, or base64wide."
            }));
          });
        });
      }
    },
    {
      id: "required-condition",
      validate(state) {
        if (state.lines.some((line) => /^condition:$/i.test(line.trim()))) {
          return;
        }

        const identifiers = getStringIdentifiers(state.lines, state.context);

        if (state.allowFixes && identifiers.length > 0) {
          const sectionIndent = inferSectionIndent(state.lines);
          const childIndent = inferChildIndent(state.lines, "strings");
          const insertion = [`${sectionIndent}condition:`, `${childIndent}any of them`];
          const finalBraceIndex = findFinalRuleClosingLine(state.lines);
          const insertIndex = finalBraceIndex === -1 ? state.lines.length : finalBraceIndex;
          const shouldAddBlankLine = insertIndex > 0 && state.lines[insertIndex - 1].trim() !== "";
          const linesToInsert = shouldAddBlankLine ? ["", ...insertion] : insertion;

          shiftFixedLinesAfterInsert(state, insertIndex, linesToInsert.length);
          state.lines.splice(insertIndex, 0, ...linesToInsert);
          markFixedRange(state, insertIndex, linesToInsert.length);
          state.context = buildContext(state.lines);
          state.issues.push(makeIssue({
            severity: "FIXED",
            line: insertIndex + 1,
            message: "Added missing condition block using any of them.",
            original: "(missing condition block)",
            corrected: insertion.join("\n"),
            fixed: true,
            recommendation: "Review the generated condition to confirm it matches the intended detection logic."
          }));
          return;
        }

        state.issues.push(makeIssue({
          severity: "ERROR",
          message: "Missing required condition: block.",
          original: "(missing condition block)",
          recommendation: identifiers.length > 0
            ? "Add a condition block, for example: condition: any of them."
            : "Add a condition block that expresses the rule logic."
        }));
      }
    },
    {
      id: "brace-balance",
      validate(state) {
        let balance = 0;

        state.lines.forEach((line, index) => {
          const opens = countOutsideQuotes(line, "{");
          const closes = countOutsideQuotes(line, "}");
          balance += opens - closes;

          if (balance < 0) {
            state.issues.push(makeIssue({
              severity: "ERROR",
              line: index + 1,
              message: "Closing brace appears before a matching opening brace.",
              original: line,
              recommendation: "Remove the extra closing brace or add the missing opening brace."
            }));
            balance = 0;
          }
        });

        if (balance === 1 && state.allowFixes && !hasUnclosedHexValue(state.lines)) {
          const insertIndex = state.lines.length;
          state.lines.push("}");
          markFixedRange(state, insertIndex, 1);
          state.context = buildContext(state.lines);
          state.issues.push(makeIssue({
            severity: "FIXED",
            line: insertIndex + 1,
            message: "Added missing closing rule brace.",
            original: "(missing closing brace)",
            corrected: "}",
            fixed: true
          }));
          return;
        }

        if (balance > 0) {
          state.issues.push(makeIssue({
            severity: "ERROR",
            message: `${balance} opening brace${balance === 1 ? "" : "s"} missing a closing brace.`,
            original: "(unbalanced braces)",
            recommendation: hasUnclosedHexValue(state.lines)
              ? "Review malformed hex strings before adding braces automatically."
              : "Add the missing closing brace manually so the rule boundary is clear."
          }));
        }
      }
    },
    {
      id: "meta-quote-normalization",
      validate(state) {
        state.lines.forEach((line, index) => {
          const lineNumber = index + 1;
          const section = state.context.sectionsByLine.get(lineNumber);

          if (section !== "meta" || line.trim().startsWith("}") || getSectionName(line)) {
            return;
          }

          const parsed = parseMetaAssignment(line);

          if (!parsed || parsed.kind !== "singleText" || !parsed.validValueBoundary) {
            return;
          }

          if (!state.allowFixes) {
            state.issues.push(makeIssue({
              severity: "ERROR",
              line: lineNumber,
              message: "Single-quoted meta value should be normalized to double quotes.",
              original: line,
              recommendation: "Use double quotes for meta text values."
            }));
            return;
          }

          const corrected = rebuildMetaAssignment(parsed, normalizeSingleQuotedValue(parsed.value));
          state.lines[index] = corrected;
          state.fixedLines.add(lineNumber);
          state.issues.push(makeIssue({
            severity: "FIXED",
            line: lineNumber,
            message: "Normalized meta value from single quotes to double quotes.",
            original: line,
            corrected,
            fixed: true
          }));
        });
      }
    }
  ];

  function runValidatorPass(lines, { allowFixes, fixedLines = new Set() } = {}) {
    const state = {
      lines,
      context: buildContext(lines),
      issues: [],
      fixedLines: new Set(fixedLines),
      allowFixes
    };

    validators.forEach((validator) => validator.validate(state));

    return state;
  }

  function lintAndFix(source) {
    const normalizedSource = source.replace(/\r\n?/g, "\n").replace(/\n$/, "");
    const lines = normalizedSource ? normalizedSource.split("\n") : [];
    const fixState = runValidatorPass(lines, { allowFixes: true });
    const fixedIssues = fixState.issues.filter((issue) => issue.fixed);
    const finalState = fixedIssues.length > 0
      ? runValidatorPass(fixState.lines, { allowFixes: false, fixedLines: fixState.fixedLines })
      : fixState;
    const validationIssues = fixedIssues.length > 0
      ? finalState.issues.filter((issue) => !issue.fixed)
      : finalState.issues;
    const issues = [...fixedIssues, ...validationIssues];
    const hasErrors = issues.some((issue) => issue.severity === "ERROR");
    const hasFixes = fixedIssues.length > 0;
    const status = hasErrors ? "INVALID" : hasFixes ? "FIXED" : "VALID";

    return {
      text: finalState.lines.join("\n").trimEnd() + "\n",
      issues,
      fixedLines: finalState.fixedLines,
      status
    };
  }

  return { lintAndFix };
})();

function setValidationBadge(status) {
  validationBadge.textContent = status;
  validationBadge.className = "validation-badge";

  if (status === "VALID") {
    validationBadge.classList.add("badge-valid");
  } else if (status === "FIXED") {
    validationBadge.classList.add("badge-fixed");
  } else if (status === "INVALID") {
    validationBadge.classList.add("badge-invalid");
  } else {
    validationBadge.classList.add("badge-info");
  }
}

function appendLintMeta(container, label, value) {
  if (!value) {
    return;
  }

  const row = document.createElement("div");
  row.className = "lint-meta";
  row.append(`${label}: `);
  const code = document.createElement("code");
  code.textContent = value;
  row.append(code);
  container.append(row);
}

function renderLintResults(result = null) {
  lintResults.innerHTML = "";

  if (!result) {
    lintResultCount.textContent = "No rule analyzed";
    lintResults.innerHTML = '<p class="lint-empty">Format a rule to see lint results.</p>';
    return;
  }

  const issues = result.issues;
  const fixedCount = issues.filter((issue) => issue.fixed).length;
  const errorCount = issues.filter((issue) => issue.severity === "ERROR").length;

  lintResultCount.textContent = `${issues.length} finding${issues.length === 1 ? "" : "s"} | ${fixedCount} fixed | ${errorCount} error${errorCount === 1 ? "" : "s"}`;
  lintResultsPanel.open = issues.length > 0;

  if (issues.length === 0) {
    lintResults.innerHTML = '<p class="lint-empty">No lint issues detected.</p>';
    return;
  }

  issues.forEach((issue) => {
    const item = document.createElement("article");
    item.className = "lint-item";

    const severity = document.createElement("span");
    severity.className = `lint-severity severity-${issue.severity.toLowerCase()}`;
    severity.textContent = issue.severity;

    const body = document.createElement("div");
    const message = document.createElement("div");
    message.className = "lint-message";
    message.textContent = `${issue.line ? `Line ${issue.line}: ` : ""}${issue.message}`;
    body.append(message);

    appendLintMeta(body, "Original", issue.original);
    appendLintMeta(body, "Corrected", issue.corrected);
    appendLintMeta(body, "Recommendation", issue.recommendation);

    if (issue.fixed) {
      const fixed = document.createElement("div");
      fixed.className = "lint-meta";
      fixed.textContent = "Auto-fix applied and highlighted in the output.";
      body.append(fixed);
    }

    item.append(severity, body);
    lintResults.append(item);
  });
}

function runFormatter() {
  const source = input.value;

  if (!source.trim()) {
    output.value = "";
    updateHighlightedOutput();
    setValidationBadge("READY");
    renderLintResults();
    setStatus("Paste a YARA-L rule to format.", "warning");
    return;
  }

  const formatted = formatYaraL(source, {
    indentSize: Number(indentSize.value),
    compactBlankLines: compactBlankLines.checked
  });
  const lintResult = yaraLintEngine.lintAndFix(formatted.text);

  output.value = lintResult.text;
  updateHighlightedOutput(lintResult.fixedLines);
  setValidationBadge(lintResult.status);
  renderLintResults(lintResult);

  if (lintResult.status === "INVALID") {
    setStatus("Formatted, but lint validation found errors that need review.", "error");
  } else if (lintResult.status === "FIXED") {
    const fixedCount = lintResult.issues.filter((issue) => issue.fixed).length;
    setStatus(`Auto-fixed ${fixedCount} issue${fixedCount === 1 ? "" : "s"}. Review Fix Summary before using the rule.`, "warning");
  } else {
    setStatus("Formatted and validated successfully.");
  }
}

async function copyOutput() {
  if (!output.value.trim()) {
    setStatus("There is no formatted output to copy.", "warning");
    return;
  }

  await navigator.clipboard.writeText(output.value);
  setStatus("Formatted rule copied to clipboard.");
  showToast("Copied formatted rule to clipboard.");
}

function downloadOutput() {
  if (!output.value.trim()) {
    setStatus("There is no formatted output to download.", "warning");
    return;
  }

  const blob = new Blob([output.value], { type: "text/plain" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "formatted-yara-l-rule.yaral";
  link.click();
  URL.revokeObjectURL(link.href);
  setStatus("Downloaded formatted-yara-l-rule.yaral.");
}

function clearEditors() {
  input.value = "";
  output.value = "";
  updateHighlightedOutput();
  setValidationBadge("READY");
  renderLintResults();
  setStatus("Editors cleared.");
  input.focus();
}

function getExampleCacheKey(example) {
  return `${exampleCachePrefix}${example.filename}`;
}

function getExampleSnippet(example) {
  return example.snippet || example.tags.join(" | ");
}

function renderExamples() {
  const query = exampleSearch.value.trim().toLowerCase();
  const matches = examples.filter((example) => !query || example.keywords.includes(query));
  const categories = [...new Set(matches.map((example) => example.category))];

  exampleCount.textContent = `${matches.length} of ${examples.length} examples`;
  exampleList.innerHTML = "";

  if (matches.length === 0) {
    exampleList.innerHTML = '<div class="example-count">No examples matched your search.</div>';
    return;
  }

  categories.forEach((category) => {
    const section = document.createElement("section");
    section.className = "example-category";
    section.innerHTML = `<div class="example-category-title">${category}</div>`;

    matches
      .filter((example) => example.category === category)
      .forEach((example) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "example-item";
        button.title = getExampleSnippet(example);
        button.innerHTML = `
          <span class="example-file">${example.filename}</span>
          <span class="example-tags">${example.tags.map((tag) => `<span class="example-tag">${tag}</span>`).join("")}</span>
          <span class="example-snippet">${getExampleSnippet(example)}</span>
        `;
        button.addEventListener("click", () => loadRemoteExample(example));
        section.appendChild(button);
      });

    exampleList.appendChild(section);
  });
}

async function loadRemoteExample(example) {
  const cacheKey = getExampleCacheKey(example);
  const cachedRule = localStorage.getItem(cacheKey);

  if (cachedRule) {
    input.value = cachedRule;
    runFormatter();
    closeExamplePanel();
    showToast(`Loaded ${example.filename} from cache.`);
    return;
  }

  exampleCount.textContent = `Loading ${example.filename}...`;

  try {
    const response = await fetch(example.url);

    if (!response.ok) {
      throw new Error(`GitHub returned ${response.status}`);
    }

    const ruleText = await response.text();
    localStorage.setItem(cacheKey, ruleText);
    input.value = ruleText;
    runFormatter();
    closeExamplePanel();
    showToast(`Loaded ${example.filename}.`);
  } catch (error) {
    exampleCount.textContent = `Could not load ${example.filename}. Check your connection or GitHub availability.`;
    setStatus(`Example load failed: ${error.message}`, "error");
  }
}

function openExamplePanel() {
  examplePanel.hidden = false;
  renderExamples();
  exampleSearch.focus();
}

function closeExamplePanel() {
  examplePanel.hidden = true;
}

function loadRandomExample() {
  const source = exampleSearch.value.trim()
    ? examples.filter((example) => example.keywords.includes(exampleSearch.value.trim().toLowerCase()))
    : examples;

  const randomExample = source[Math.floor(Math.random() * source.length)];

  if (randomExample) {
    loadRemoteExample(randomExample);
  }
}

function applyTheme() {
  const isDark = themeMode.value === "dark";
  document.body.classList.toggle("dark-mode", isDark);
  document.body.dataset.theme = themeMode.value;
  localStorage.setItem("yaraLFormatterTheme", themeMode.value);
  showToast(`${isDark ? "Dark" : "Light"} mode selected.`);
}

function initializeTheme() {
  const savedTheme = localStorage.getItem("yaraLFormatterTheme");

  if (savedTheme === "dark" || savedTheme === "light") {
    themeMode.value = savedTheme;
  }

  document.body.classList.toggle("dark-mode", themeMode.value === "dark");
  document.body.dataset.theme = themeMode.value;
}

function initializeVersionBadge() {
  document.documentElement.dataset.appVersion = appConfig.version;

  if (!versionBadge) {
    return;
  }

  versionBadge.textContent = `v${appConfig.version}`;
  versionBadge.title = `Build ${appConfig.build}`;
}

formatBtn.addEventListener("click", runFormatter);
copyBtn.addEventListener("click", copyOutput);
downloadBtn.addEventListener("click", downloadOutput);
clearBtn.addEventListener("click", clearEditors);
chooseExampleBtn.addEventListener("click", openExamplePanel);
closeExampleBtn.addEventListener("click", closeExamplePanel);
randomExampleBtn.addEventListener("click", loadRandomExample);
exampleSearch.addEventListener("input", renderExamples);
indentSize.addEventListener("change", runFormatter);
themeMode.addEventListener("change", applyTheme);
compactBlankLines.addEventListener("change", runFormatter);

input.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    runFormatter();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !examplePanel.hidden) {
    closeExamplePanel();
  }
});

initializeVersionBadge();
initializeTheme();
renderExamples();
setValidationBadge("READY");
renderLintResults();
setStatus("Ready.");

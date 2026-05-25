const input = document.querySelector("#input");
const output = document.querySelector("#output");
const formatBtn = document.querySelector("#formatBtn");
const copyBtn = document.querySelector("#copyBtn");
const downloadBtn = document.querySelector("#downloadBtn");
const clearBtn = document.querySelector("#clearBtn");
const chooseExampleBtn = document.querySelector("#chooseExampleBtn");
const googleSecOpsRulesBtn = document.querySelector("#googleSecOpsRulesBtn");
const closeExampleBtn = document.querySelector("#closeExampleBtn");
const closeGoogleSecOpsBtn = document.querySelector("#closeGoogleSecOpsBtn");
const randomExampleBtn = document.querySelector("#randomExampleBtn");
const examplePanel = document.querySelector("#examplePanel");
const googleSecOpsPanel = document.querySelector("#googleSecOpsPanel");
const exampleSearch = document.querySelector("#exampleSearch");
const googleSecOpsSearch = document.querySelector("#googleSecOpsSearch");
const exampleList = document.querySelector("#exampleList");
const exampleCount = document.querySelector("#exampleCount");
const googleSecOpsCategories = document.querySelector("#googleSecOpsCategories");
const googleSecOpsRules = document.querySelector("#googleSecOpsRules");
const googleSecOpsCount = document.querySelector("#googleSecOpsCount");
const googleSecOpsSourceNote = document.querySelector("#googleSecOpsSourceNote");
const indentSize = document.querySelector("#indentSize");
const themeMode = document.querySelector("#themeMode");
const compactBlankLines = document.querySelector("#compactBlankLines");
const statusBox = document.querySelector("#status");
const formattedOutput = document.querySelector("#formattedOutput");
const highlightedOutput = document.querySelector("#highlightedOutput");
const wrapTextBtn = document.querySelector("#wrapTextBtn");
const validationBadge = document.querySelector("#validationBadge");
const lintResultsPanel = document.querySelector("#lintResultsPanel");
const lintResultCount = document.querySelector("#lintResultCount");
const lintResults = document.querySelector("#lintResults");
const versionBadge = document.querySelector("[data-version-badge]");
const toast = document.querySelector("#toast");

const appConfig = window.YARALINT_CONFIG || {
  version: "1.1.9",
  build: "2026-05-25T06:13:55-05:00"
};
const sectionPattern = /^(meta|strings|events|match|outcome|condition|options):$/i;
const githubRawBase = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/";
const exampleCachePrefix = "yaraLFormatterExample:";
const googleSecOpsConfig = {
  owner: "chronicle",
  repo: "detection-rules",
  branch: "main",
  communityPath: "rules/community",
  apiBase: "https://api.github.com/repos/chronicle/detection-rules",
  htmlBase: "https://github.com/chronicle/detection-rules/blob",
  rawBase: "https://raw.githubusercontent.com/chronicle/detection-rules"
};
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
let googleSecOpsState = {
  manifest: null,
  activeCategory: ""
};

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

function splitCommentSegments(line, startsInsideBlockComment = false) {
  const segments = [];
  let buffer = "";
  let quote = null;
  let escaped = false;
  let insideBlockComment = startsInsideBlockComment;

  function pushSegment(type) {
    if (!buffer) {
      return;
    }

    const previous = segments[segments.length - 1];

    if (previous && previous.type === type) {
      previous.text += buffer;
    } else {
      segments.push({ type, text: buffer });
    }

    buffer = "";
  }

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const next = line[index + 1];

    if (insideBlockComment) {
      buffer += char;

      if (char === "*" && next === "/") {
        buffer += next;
        index += 1;
        pushSegment("comment");
        insideBlockComment = false;
      }

      continue;
    }

    if (escaped) {
      buffer += char;
      escaped = false;
      continue;
    }

    if (char === "\\") {
      buffer += char;
      escaped = true;
      continue;
    }

    if ((char === '"' || char === "'") && quote === null) {
      quote = char;
      buffer += char;
      continue;
    }

    if (char === quote) {
      quote = null;
      buffer += char;
      continue;
    }

    if (quote === null && char === "/" && next === "*") {
      pushSegment("code");
      buffer = "/*";
      index += 1;
      insideBlockComment = true;
      continue;
    }

    if (quote === null && char === "#") {
      pushSegment("code");
      buffer = line.slice(index);
      pushSegment("comment");
      return { segments, insideBlockComment: false };
    }

    if (quote === null && char === "/" && next === "/" && (index === 0 || /\s/.test(line[index - 1]))) {
      pushSegment("code");
      buffer = line.slice(index);
      pushSegment("comment");
      return { segments, insideBlockComment: false };
    }

    buffer += char;
  }

  pushSegment(insideBlockComment ? "comment" : "code");
  return { segments, insideBlockComment };
}

function getCodeOutsideComments(line, startsInsideBlockComment = false) {
  const result = splitCommentSegments(line, startsInsideBlockComment);
  return {
    code: result.segments
      .filter((segment) => segment.type === "code")
      .map((segment) => segment.text)
      .join(""),
    insideBlockComment: result.insideBlockComment,
    hasComment: result.segments.some((segment) => segment.type === "comment")
  };
}

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function highlightCodeSegment(line) {
  return escapeHtml(line)
    .replace(/("(?:\\.|[^"\\])*")/g, '<span class="token-string">$1</span>')
    .replace(/(^|\s)(\$[A-Za-z_][\w.]*)/g, '$1<span class="token-variable">$2</span>')
    .replace(/\b(rule|and|or|not|nocase|re|regex|any|all|of|them|in|over|match|outcome|condition|events|strings|meta|options)\b/g, '<span class="token-keyword">$1</span>')
    .replace(/(^\s*)(meta|strings|events|match|outcome|condition|options):/gim, '$1<span class="token-section">$2:</span>');
}

function highlightLine(line, commentState) {
  const result = splitCommentSegments(line, commentState.insideBlockComment);
  commentState.insideBlockComment = result.insideBlockComment;

  return result.segments.map((segment) => {
    if (segment.type === "comment") {
      return `<span class="token-comment">${escapeHtml(segment.text)}</span>`;
    }

    return highlightCodeSegment(segment.text);
  }).join("");
}

function highlightYaraL(source, fixedLines = new Set()) {
  const commentState = { insideBlockComment: false };

  return source.split("\n").map((line, index) => {
    const lineNumber = index + 1;
    const className = fixedLines.has(lineNumber) ? "code-line fixed-line" : "code-line";
    return `<span class="${className}" data-line="${lineNumber}">${highlightLine(line, commentState) || " "}</span>`;
  }).join("");
}

function updateHighlightedOutput(fixedLines = new Set()) {
  highlightedOutput.innerHTML = output.value.trim()
    ? highlightYaraL(output.value, fixedLines)
    : "";
}

function setWrapText(enabled) {
  formattedOutput.classList.toggle("wrap-text-enabled", enabled);
  wrapTextBtn.textContent = enabled ? "UNWRAP TEXT" : "WRAP TEXT";
  wrapTextBtn.setAttribute("aria-pressed", String(enabled));
}

function toggleWrapText() {
  setWrapText(!formattedOutput.classList.contains("wrap-text-enabled"));
}

function isHexStringStart(line) {
  return /^\$[A-Za-z_][\w]*\s*=\s*\{/.test(line);
}

function normalizeAssignmentSpacing(line, section) {
  if (section === "strings") {
    return line.replace(/^(\$[A-Za-z_][\w]*)\s*=\s*/, "$1 = ");
  }

  if (section === "meta") {
    return line.replace(/^([A-Za-z_][\w]*)\s*=\s*/, "$1 = ");
  }

  return line;
}

function formatYaraL(source, options) {
  const indentUnit = " ".repeat(options.indentSize);
  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  const formatted = [];
  const warnings = [];
  let indentLevel = 0;
  let sectionIndentLevel = null;
  let currentSection = null;
  let hexBlockBalance = 0;
  let insideBlockComment = false;
  let previousWasBlank = false;

  lines.forEach((rawLine, index) => {
    const trimmed = rawLine.trim();
    const commentInfo = getCodeOutsideComments(rawLine, insideBlockComment);
    const activeTrimmed = commentInfo.code.trim();
    const commentOnly = trimmed !== "" && commentInfo.hasComment && !activeTrimmed;

    if (trimmed === "") {
      if (!options.compactBlankLines || !previousWasBlank) {
        formatted.push("");
      }
      previousWasBlank = true;
      insideBlockComment = commentInfo.insideBlockComment;
      return;
    }

    previousWasBlank = false;

    if (commentOnly) {
      formatted.push(rawLine.replace(/\s+$/g, ""));
      insideBlockComment = commentInfo.insideBlockComment;
      return;
    }

    const insideHexBlock = currentSection === "strings" && hexBlockBalance > 0;
    let activeLine = insideHexBlock ? commentInfo.code.replace(/\s+$/g, "") : normalizeOperators(activeTrimmed);
    let line = insideHexBlock ? rawLine.replace(/\s+$/g, "") : normalizeOperators(trimmed);
    const startsHexBlock = currentSection === "strings" && isHexStringStart(activeLine);
    const isHexBlockLine = insideHexBlock || startsHexBlock;
    const hexDelta = isHexBlockLine
      ? countOutsideQuotes(activeLine, "{") - countOutsideQuotes(activeLine, "}")
      : 0;
    const closes = isHexBlockLine ? 0 : countOutsideQuotes(activeLine, "}");
    const opens = isHexBlockLine ? 0 : countOutsideQuotes(activeLine, "{");
    const leadingCloses = isHexBlockLine ? 0 : countLeadingClosingBraces(activeLine);

    if (leadingCloses > 0) {
      indentLevel = Math.max(indentLevel - leadingCloses, 0);
      if (sectionIndentLevel !== null && indentLevel <= sectionIndentLevel) {
        sectionIndentLevel = null;
      }
      currentSection = null;
    }

    if (!insideHexBlock && (currentSection === "meta" || currentSection === "strings") && !sectionPattern.test(activeLine) && !activeLine.startsWith("}")) {
      activeLine = normalizeAssignmentSpacing(activeLine, currentSection);
      line = normalizeAssignmentSpacing(line, currentSection);
    }

    if (insideHexBlock) {
      formatted.push(line);
    } else if (sectionPattern.test(activeLine)) {
      formatted.push(`${indentUnit.repeat(indentLevel)}${line}`);
      sectionIndentLevel = indentLevel;
      currentSection = activeLine.slice(0, -1).toLowerCase();
    } else {
      const bodyIndent = sectionIndentLevel !== null && !activeLine.startsWith("}")
        ? sectionIndentLevel + 1 + Math.max(indentLevel - sectionIndentLevel, 0)
        : indentLevel;
      formatted.push(`${indentUnit.repeat(bodyIndent)}${line}`);
    }

    indentLevel += opens - (closes - leadingCloses);

    if (indentLevel < 0) {
      warnings.push(`Line ${index + 1}: closing brace without a matching opening brace.`);
      indentLevel = 0;
    }

    if (isHexBlockLine) {
      hexBlockBalance = Math.max(hexBlockBalance + hexDelta, 0);
    }

    insideBlockComment = commentInfo.insideBlockComment;
  });

  if (indentLevel > 0) {
    warnings.push(`${indentLevel} opening brace${indentLevel === 1 ? "" : "s"} may be missing a closing brace.`);
  }

  return {
    text: formatted.join("\n").trimEnd() + "\n",
    warnings
  };
}

function normalizeForChangeComparison(value) {
  return value.replace(/\r\n?/g, "\n").replace(/\n+$/g, "");
}

function getFormatterFixSummary(source, formattedText) {
  const originalText = normalizeForChangeComparison(source);
  const normalizedFormatted = normalizeForChangeComparison(formattedText);

  if (originalText === normalizedFormatted) {
    return { issues: [], fixedLines: new Set() };
  }

  const originalLines = originalText.split("\n");
  const formattedLines = normalizedFormatted.split("\n");
  const maxLines = Math.max(originalLines.length, formattedLines.length);
  const fixedLines = new Set();

  for (let index = 0; index < maxLines; index += 1) {
    if ((originalLines[index] || "") !== (formattedLines[index] || "")) {
      fixedLines.add(index + 1);
    }
  }

  const changedCount = fixedLines.size;

  return {
    issues: [
      {
        severity: "FIXED",
        line: changedCount === 1 ? [...fixedLines][0] : null,
        message: `Applied formatter cleanup to ${changedCount} line${changedCount === 1 ? "" : "s"}.`,
        original: "Original indentation, spacing, or section alignment",
        corrected: "Normalized formatter output",
        fixed: true,
        recommendation: "Review the formatted output before copying or deploying the rule."
      }
    ],
    fixedLines
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

  function hasUnclosedHexValue(lines, context = buildContext(lines)) {
    let insideBlockComment = false;

    for (let index = 0; index < lines.length; index += 1) {
      const lineNumber = index + 1;
      const commentInfo = getCodeOutsideComments(lines[index], insideBlockComment);
      insideBlockComment = commentInfo.insideBlockComment;

      if (context.sectionsByLine.get(lineNumber) !== "strings") {
        continue;
      }

      const parsed = parseStringDeclaration(commentInfo.code);

      if (!parsed || parsed.kind !== "hex") {
        continue;
      }

      const block = collectHexBlock(lines, index, context, parsed);

      if (!block.complete) {
        return true;
      }

      index = block.endIndex;
    }

    return false;
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
    let insideBlockComment = false;

    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      const commentInfo = getCodeOutsideComments(line, insideBlockComment);
      insideBlockComment = commentInfo.insideBlockComment;

      if (context.sectionsByLine.get(lineNumber) !== "strings") {
        return;
      }

      const parsed = parseStringDeclaration(commentInfo.code);

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

  function lineWithoutComment(line) {
    return getCodeOutsideComments(line).code;
  }

  function getSectionName(line) {
    const match = line.trim().match(/^(meta|strings|events|match|outcome|condition|options):$/i);
    return match ? match[1].toLowerCase() : null;
  }

  function getRuleDeclarationName(line) {
    const match = line.trim().match(/^(?:(?:private|global)\s+)*rule\s+([A-Za-z_][\w]*)\b/);
    return match ? match[1] : null;
  }

  function buildContext(lines) {
    const sectionsByLine = new Map();
    let currentSection = null;
    let insideBlockComment = false;

    lines.forEach((line, index) => {
      const commentInfo = getCodeOutsideComments(line, insideBlockComment);
      const sectionName = getSectionName(commentInfo.code);
      insideBlockComment = commentInfo.insideBlockComment;

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

  function stripHexBlockComments(value) {
    return value.replace(/\/\*[\s\S]*?\*\//g, " ");
  }

  function collectHexBlock(lines, startIndex, context, parsed) {
    const parts = [];
    let balance = 0;
    let sawOpeningBrace = false;
    let insideBlockComment = false;

    for (let index = startIndex; index < lines.length; index += 1) {
      const lineNumber = index + 1;
      const commentInfo = getCodeOutsideComments(lines[index], insideBlockComment);
      insideBlockComment = commentInfo.insideBlockComment;
      const section = context.sectionsByLine.get(lineNumber);
      const sectionName = getSectionName(commentInfo.code);

      if (index > startIndex && sectionName) {
        return {
          complete: false,
          value: parts.join("\n"),
          endIndex: index - 1,
          message: `Hex string block is missing a closing } before the ${sectionName}: section.`
        };
      }

      if (index > startIndex && section !== "strings") {
        return {
          complete: false,
          value: parts.join("\n"),
          endIndex: index - 1,
          message: "Hex string block is missing a closing } before the strings section ends."
        };
      }

      const fragment = index === startIndex
        ? parsed.rawValue.trim()
        : commentInfo.code.trim();
      let closingIndex = -1;

      for (let charIndex = 0; charIndex < fragment.length; charIndex += 1) {
        const char = fragment[charIndex];

        if (char === "{") {
          balance += 1;
          sawOpeningBrace = true;
        } else if (char === "}") {
          balance -= 1;

          if (balance === 0 && sawOpeningBrace) {
            closingIndex = charIndex;
            break;
          }
        }
      }

      if (closingIndex !== -1) {
        parts.push(fragment.slice(0, closingIndex + 1));

        return {
          complete: true,
          value: parts.join("\n"),
          modifiers: fragment.slice(closingIndex + 1).trim(),
          endIndex: index,
          startLine: startIndex + 1,
          endLine: lineNumber
        };
      }

      parts.push(fragment);
    }

    return {
      complete: false,
      value: parts.join("\n"),
      endIndex: lines.length - 1,
      message: "Hex string block is missing a closing } before the end of the rule."
    };
  }

  function getHexBlockLineNumbers(lines, context) {
    const lineNumbers = new Set();
    let insideBlockComment = false;

    for (let index = 0; index < lines.length; index += 1) {
      const lineNumber = index + 1;
      const commentInfo = getCodeOutsideComments(lines[index], insideBlockComment);
      insideBlockComment = commentInfo.insideBlockComment;

      if (context.sectionsByLine.get(lineNumber) !== "strings") {
        continue;
      }

      const parsed = parseStringDeclaration(commentInfo.code);

      if (!parsed || parsed.kind !== "hex") {
        continue;
      }

      const block = collectHexBlock(lines, index, context, parsed);
      const endIndex = Math.max(block.endIndex, index);

      for (let hexIndex = index; hexIndex <= endIndex; hexIndex += 1) {
        lineNumbers.add(hexIndex + 1);
      }

      index = endIndex;
    }

    return lineNumbers;
  }

  function validateHexString(hexValue) {
    if (!hexValue.startsWith("{") || !hexValue.endsWith("}")) {
      return ["Hex string must start with { and end with }."];
    }

    const body = stripHexBlockComments(hexValue.slice(1, -1)).trim();

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

  function getUnclosedQuote(line) {
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
      }
    }

    return quote;
  }

  function insertBeforeTrailingWhitespace(line, text) {
    const match = line.match(/\s*$/);
    const insertIndex = match ? line.length - match[0].length : line.length;
    return `${line.slice(0, insertIndex)}${text}${line.slice(insertIndex)}`;
  }

  function parseOutcomeAssignment(line) {
    const match = line.match(/^(\s*\$[A-Za-z_][\w.]*)\s*=\s*(.*)$/);

    if (!match || !match[2].trim()) {
      return null;
    }

    return {
      id: match[1].trim(),
      value: match[2]
    };
  }

  const validators = [
    {
      id: "duplicate-rule-identifiers",
      validate(state) {
        const seen = new Map();
        let insideBlockComment = false;

        state.lines.forEach((line, index) => {
          const commentInfo = getCodeOutsideComments(line, insideBlockComment);
          insideBlockComment = commentInfo.insideBlockComment;
          const ruleName = getRuleDeclarationName(commentInfo.code);

          if (!ruleName) {
            return;
          }

          if (seen.has(ruleName)) {
            state.issues.push(makeIssue({
              severity: "ERROR",
              line: index + 1,
              message: `Duplicate rule identifier: ${ruleName}.`,
              original: line,
              recommendation: "Rename one of the rules so every rule identifier is unique."
            }));
            return;
          }

          seen.set(ruleName, index + 1);
        });
      }
    },
    {
      id: "string-declarations",
      validate(state) {
        let seen = new Map();
        let insideBlockComment = false;

        for (let index = 0; index < state.lines.length; index += 1) {
          const line = state.lines[index];
          const lineNumber = index + 1;
          const commentInfo = getCodeOutsideComments(line, insideBlockComment);
          insideBlockComment = commentInfo.insideBlockComment;
          const section = state.context.sectionsByLine.get(lineNumber);
          const activeLine = commentInfo.code;
          const trimmed = activeLine.trim();
          const ruleName = getRuleDeclarationName(activeLine);

          if (ruleName) {
            seen = new Map();
          }

          if (section !== "strings" || !trimmed || trimmed.startsWith("}") || getSectionName(activeLine)) {
            continue;
          }

          let currentLine = state.lines[index];
          let parsed = parseStringDeclaration(activeLine);

          if (!parsed) {
            state.issues.push(makeIssue({
              severity: "ERROR",
              line: lineNumber,
              message: "Invalid string declaration. Expected format like $id = \"text\", $id = /regex/, or $id = { 4D 5A }.",
              original: currentLine,
              recommendation: "Use a valid YARA string identifier and assignment syntax."
            }));
            continue;
          }

          if (seen.has(parsed.id)) {
            state.issues.push(makeIssue({
              severity: "WARNING",
              line: lineNumber,
              message: `Duplicate string identifier preserved: ${parsed.id}.`,
              original: currentLine,
              recommendation: "YARALint does not rename user-defined string identifiers because conditions may intentionally reference them."
            }));
          } else {
            seen.set(parsed.id, lineNumber);
          }

          if (parsed.kind === "hex") {
            const block = collectHexBlock(state.lines, index, state.context, parsed);

            if (!block.complete) {
              state.issues.push(makeIssue({
                severity: "ERROR",
                line: lineNumber,
                message: block.message,
                original: currentLine,
                recommendation: "Close the multi-line hex string with } before starting another section."
              }));
              index = Math.max(block.endIndex, index);
              continue;
            }

            validateHexString(block.value).forEach((message) => {
              state.issues.push(makeIssue({
                severity: "ERROR",
                line: lineNumber,
                message,
                original: currentLine,
                recommendation: "Use two-character hex bytes, wildcards, jumps, or grouping tokens inside { }."
              }));
            });

            validateModifiers(block.modifiers || parsed.modifiers).forEach((modifier) => {
              state.issues.push(makeIssue({
                severity: "ERROR",
                line: lineNumber,
                message: `Invalid string modifier: ${modifier}.`,
                original: currentLine,
                recommendation: "Use supported YARA string modifiers such as ascii, wide, nocase, fullword, private, xor, base64, or base64wide."
              }));
            });

            index = block.endIndex;
            continue;
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
                continue;
              }
            } else {
              state.issues.push(makeIssue({
                severity: "ERROR",
                line: lineNumber,
                message: "Unterminated string, regex, or hex value.",
                original: currentLine,
                recommendation: "Close the string, regex, or hex value before formatting again."
              }));
              continue;
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

          validateModifiers(parsed.modifiers).forEach((modifier) => {
            state.issues.push(makeIssue({
              severity: "ERROR",
              line: lineNumber,
              message: `Invalid string modifier: ${modifier}.`,
              original: currentLine,
              recommendation: "Use supported YARA string modifiers such as ascii, wide, nocase, fullword, private, xor, base64, or base64wide."
            }));
          });
        }
      }
    },
    {
      id: "required-condition",
      validate(state) {
        if ([...state.context.sectionsByLine.values()].includes("condition")) {
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
      id: "outcome-assignment-syntax",
      validate(state) {
        let insideBlockComment = false;

        state.lines.forEach((line, index) => {
          const lineNumber = index + 1;
          const commentInfo = getCodeOutsideComments(line, insideBlockComment);
          insideBlockComment = commentInfo.insideBlockComment;
          const section = state.context.sectionsByLine.get(lineNumber);
          const activeLine = commentInfo.code;
          const trimmed = activeLine.trim();

          if (section !== "outcome" || !trimmed || trimmed.startsWith("}") || getSectionName(activeLine)) {
            return;
          }

          const assignment = parseOutcomeAssignment(activeLine);

          if (!assignment) {
            return;
          }

          let corrected = activeLine;
          let changed = false;
          const original = state.lines[index];
          const unclosedQuote = getUnclosedQuote(corrected);

          if (unclosedQuote) {
            if (!state.allowFixes) {
              state.issues.push(makeIssue({
                severity: "ERROR",
                line: lineNumber,
                message: "Unterminated quote in outcome assignment.",
                original,
                recommendation: "Close the quoted outcome value before deploying the rule."
              }));
              return;
            }

            corrected = insertBeforeTrailingWhitespace(corrected, unclosedQuote);
            changed = true;
            state.issues.push(makeIssue({
              severity: "FIXED",
              line: lineNumber,
              message: "Added missing closing quote to outcome assignment.",
              original,
              corrected,
              fixed: true
            }));
          }

          const opens = countOutsideQuotes(corrected, "(");
          const closes = countOutsideQuotes(corrected, ")");
          const missingParens = opens - closes;

          if (missingParens > 0 && !/\b(and|or)\s*$/i.test(corrected.trim())) {
            if (!state.allowFixes) {
              state.issues.push(makeIssue({
                severity: "ERROR",
                line: lineNumber,
                message: "Unbalanced parentheses in outcome assignment.",
                original: changed ? corrected : original,
                recommendation: "Close the outcome function call before deploying the rule."
              }));
              return;
            }

            corrected = insertBeforeTrailingWhitespace(corrected, ")".repeat(missingParens));
            changed = true;
            state.issues.push(makeIssue({
              severity: "FIXED",
              line: lineNumber,
              message: `Added ${missingParens} missing closing parenthesis${missingParens === 1 ? "" : "es"} to outcome assignment.`,
              original,
              corrected,
              fixed: true
            }));
          }

          if (changed) {
            state.lines[index] = corrected;
            state.fixedLines.add(lineNumber);
          }
        });
      }
    },
    {
      id: "brace-balance",
      validate(state) {
        let balance = 0;
        const hexBlockLines = getHexBlockLineNumbers(state.lines, state.context);
        const hasOpenHexBlock = hasUnclosedHexValue(state.lines, state.context);
        let insideBlockComment = false;

        state.lines.forEach((line, index) => {
          const commentInfo = getCodeOutsideComments(line, insideBlockComment);
          insideBlockComment = commentInfo.insideBlockComment;
          const activeLine = commentInfo.code;

          if (hexBlockLines.has(index + 1)) {
            return;
          }

          const opens = countOutsideQuotes(activeLine, "{");
          const closes = countOutsideQuotes(activeLine, "}");
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

        if (balance === 1 && state.allowFixes && !hasOpenHexBlock) {
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
          if (hasOpenHexBlock) {
            return;
          }

          state.issues.push(makeIssue({
            severity: "ERROR",
            message: `${balance} opening brace${balance === 1 ? "" : "s"} missing a closing brace.`,
            original: "(unbalanced braces)",
            recommendation: "Add the missing closing brace manually so the rule boundary is clear."
          }));
        }
      }
    },
    {
      id: "meta-quote-normalization",
      validate(state) {
        let insideBlockComment = false;

        state.lines.forEach((line, index) => {
          const lineNumber = index + 1;
          const commentInfo = getCodeOutsideComments(line, insideBlockComment);
          insideBlockComment = commentInfo.insideBlockComment;
          const activeLine = commentInfo.code;
          const section = state.context.sectionsByLine.get(lineNumber);

          if (section !== "meta" || !activeLine.trim() || activeLine.trim().startsWith("}") || getSectionName(activeLine)) {
            return;
          }

          const parsed = parseMetaAssignment(activeLine);

          if (!parsed) {
            return;
          }

          if (!parsed.validValueBoundary) {
            if (state.allowFixes && (parsed.kind === "text" || parsed.kind === "singleText")) {
              const correctedValue = parsed.kind === "text"
                ? `${parsed.value}"`
                : quoteYaraText(parsed.value.slice(1));
              const corrected = rebuildMetaAssignment(parsed, correctedValue);
              state.lines[index] = corrected;
              state.fixedLines.add(lineNumber);
              state.issues.push(makeIssue({
                severity: "FIXED",
                line: lineNumber,
                message: "Added missing closing quote to meta assignment.",
                original: line,
                corrected,
                fixed: true
              }));
              return;
            }

            state.issues.push(makeIssue({
              severity: "ERROR",
              line: lineNumber,
              message: "Unterminated meta value.",
              original: line,
              recommendation: "Close the meta string value with a matching quote."
            }));
            return;
          }

          if (parsed.kind === "singleText") {
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
          }
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
  const formatterFixSummary = getFormatterFixSummary(source, formatted.text);
  const lintResult = yaraLintEngine.lintAndFix(formatted.text);
  const issues = [...formatterFixSummary.issues, ...lintResult.issues];
  const fixedLines = new Set([...formatterFixSummary.fixedLines, ...lintResult.fixedLines]);
  const hasErrors = issues.some((issue) => issue.severity === "ERROR");
  const hasFixes = issues.some((issue) => issue.fixed);
  const result = {
    ...lintResult,
    issues,
    fixedLines,
    status: hasErrors ? "INVALID" : hasFixes ? "FIXED" : lintResult.status
  };

  output.value = result.text;
  updateHighlightedOutput(result.fixedLines);
  setValidationBadge(result.status);
  renderLintResults(result);

  if (result.status === "INVALID") {
    setStatus("Formatted, but lint validation found errors that need review.", "error");
  } else if (result.status === "FIXED") {
    const fixedCount = result.issues.filter((issue) => issue.fixed).length;
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
  googleSecOpsSourceNote.hidden = true;
  googleSecOpsSourceNote.textContent = "";
  updateHighlightedOutput();
  setValidationBadge("READY");
  renderLintResults();
  setStatus("Editors cleared.");
  input.focus();
}

function isGoogleSecOpsRuleFile(path) {
  return new RegExp(`^${googleSecOpsConfig.communityPath}/[^/]+/.+\\.(yaral|yara|yar)$`, "i").test(path);
}

function getGoogleSecOpsRawUrl(path, commitSha = googleSecOpsConfig.branch) {
  return `${googleSecOpsConfig.rawBase}/${commitSha}/${path}`;
}

function getGoogleSecOpsSourceUrl(path, commitSha = googleSecOpsConfig.branch) {
  return `${googleSecOpsConfig.htmlBase}/${commitSha}/${path}`;
}

function buildGoogleSecOpsManifest(treeItems, metadata = {}) {
  const commitSha = metadata.commitSha || googleSecOpsConfig.branch;
  const lastSyncedAt = metadata.lastSyncedAt || new Date().toISOString();
  const rules = treeItems
    .filter((item) => item.type === "blob" && isGoogleSecOpsRuleFile(item.path))
    .map((item) => {
      const parts = item.path.split("/");
      const category = parts[2];
      const fileName = parts[parts.length - 1];
      const relativePath = parts.slice(2).join("/");
      const folderPath = parts.slice(2, -1).join("/");

      return {
        category,
        fileName,
        folderPath,
        relativePath,
        repoPath: item.path,
        rawUrl: getGoogleSecOpsRawUrl(item.path, commitSha),
        sourceUrl: getGoogleSecOpsSourceUrl(item.path, commitSha),
        commitSha,
        lastSyncedAt,
        sha: item.sha || "",
        size: item.size || 0,
        keywords: `${category} ${folderPath} ${fileName} ${item.path}`.toLowerCase()
      };
    })
    .sort((a, b) => a.relativePath.localeCompare(b.relativePath));

  const categories = [...new Set(rules.map((rule) => rule.category))]
    .sort((a, b) => a.localeCompare(b))
    .map((category) => ({
      name: category,
      rules: rules.filter((rule) => rule.category === category)
    }));

  return {
    source: "Google SecOps public community examples",
    commitSha,
    lastSyncedAt,
    categories,
    rules
  };
}

async function fetchGoogleSecOpsManifest() {
  const branchResponse = await fetch(`${googleSecOpsConfig.apiBase}/branches/${googleSecOpsConfig.branch}`);
  let commitSha = googleSecOpsConfig.branch;

  if (branchResponse.ok) {
    const branchData = await branchResponse.json();
    commitSha = branchData.commit?.sha || commitSha;
  }

  const treeResponse = await fetch(`${googleSecOpsConfig.apiBase}/git/trees/${googleSecOpsConfig.branch}?recursive=1`);

  if (!treeResponse.ok) {
    throw new Error(`GitHub returned ${treeResponse.status}`);
  }

  const treeData = await treeResponse.json();

  if (treeData.truncated) {
    throw new Error("GitHub returned a truncated repository tree.");
  }

  return buildGoogleSecOpsManifest(treeData.tree || [], {
    commitSha,
    lastSyncedAt: new Date().toISOString()
  });
}

async function getGoogleSecOpsManifest() {
  googleSecOpsState.manifest = await fetchGoogleSecOpsManifest();
  return googleSecOpsState.manifest;
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
    googleSecOpsSourceNote.hidden = true;
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
    googleSecOpsSourceNote.hidden = true;
    runFormatter();
    closeExamplePanel();
    showToast(`Loaded ${example.filename}.`);
  } catch (error) {
    exampleCount.textContent = `Could not load ${example.filename}. Check your connection or GitHub availability.`;
    setStatus(`Example load failed: ${error.message}`, "error");
  }
}

function getFilteredGoogleSecOpsRules() {
  const manifest = googleSecOpsState.manifest;
  const query = googleSecOpsSearch.value.trim().toLowerCase();

  if (!manifest) {
    return [];
  }

  return manifest.rules.filter((rule) => !query || rule.keywords.includes(query));
}

function setActiveGoogleSecOpsCategory(category) {
  googleSecOpsState.activeCategory = category;
  renderGoogleSecOpsRules();
}

function renderGoogleSecOpsRules() {
  const manifest = googleSecOpsState.manifest;

  if (!manifest) {
    googleSecOpsCategories.innerHTML = "";
    googleSecOpsRules.innerHTML = "";
    return;
  }

  const matches = getFilteredGoogleSecOpsRules();
  const categories = manifest.categories
    .map((category) => ({
      ...category,
      rules: matches.filter((rule) => rule.category === category.name)
    }))
    .filter((category) => category.rules.length > 0);

  if (!categories.some((category) => category.name === googleSecOpsState.activeCategory)) {
    googleSecOpsState.activeCategory = categories[0]?.name || "";
  }

  googleSecOpsCount.textContent = `${matches.length} of ${manifest.rules.length} Google SecOps public community examples`;
  googleSecOpsCategories.innerHTML = "";
  googleSecOpsRules.innerHTML = "";

  if (matches.length === 0) {
    googleSecOpsRules.innerHTML = '<div class="example-count">No Google SecOps community rules matched your search.</div>';
    return;
  }

  categories.forEach((category) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `secops-category${category.name === googleSecOpsState.activeCategory ? " active" : ""}`;
    button.textContent = `${category.name} (${category.rules.length})`;
    button.addEventListener("mouseenter", () => setActiveGoogleSecOpsCategory(category.name));
    button.addEventListener("focus", () => setActiveGoogleSecOpsCategory(category.name));
    button.addEventListener("click", () => setActiveGoogleSecOpsCategory(category.name));
    googleSecOpsCategories.appendChild(button);
  });

  const activeRules = categories.find((category) => category.name === googleSecOpsState.activeCategory)?.rules || [];

  activeRules.forEach((rule) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "secops-rule-item";
    button.title = `${rule.repoPath}\nSource: Google SecOps public community examples.`;
    button.innerHTML = `
      <span class="example-file">${rule.fileName}</span>
      <span class="example-snippet">${rule.relativePath}</span>
    `;
    button.addEventListener("click", () => loadGoogleSecOpsRule(rule));
    googleSecOpsRules.appendChild(button);
  });
}

async function renderGoogleSecOpsPanel() {
  googleSecOpsCount.textContent = "Loading Google SecOps public community examples...";
  googleSecOpsCategories.innerHTML = "";
  googleSecOpsRules.innerHTML = "";

  try {
    await getGoogleSecOpsManifest();
    renderGoogleSecOpsRules();
  } catch (error) {
    googleSecOpsCount.textContent = "Could not load Google SecOps community rules.";
    googleSecOpsRules.innerHTML = '<div class="example-count">GitHub rule discovery failed. Check your connection or try again later.</div>';
    setStatus(`Google SecOps rules load failed: ${error.message}`, "error");
  }
}

async function loadGoogleSecOpsRule(rule) {
  googleSecOpsCount.textContent = `Loading ${rule.relativePath}...`;

  try {
    const response = await fetch(rule.rawUrl);

    if (!response.ok) {
      throw new Error(`GitHub returned ${response.status}`);
    }

    input.value = await response.text();
    googleSecOpsSourceNote.textContent = `Loaded from Google SecOps Community Rules: ${rule.relativePath}`;
    googleSecOpsSourceNote.title = `Source: Google SecOps public community examples. Commit: ${rule.commitSha}`;
    googleSecOpsSourceNote.hidden = false;
    closeGoogleSecOpsPanel();
    showToast(`Loaded ${rule.fileName}.`);
    setStatus("Loaded public community example. Review and test before production use.", "warning");
    input.focus();
  } catch (error) {
    googleSecOpsCount.textContent = `Could not load ${rule.relativePath}.`;
    setStatus(`Google SecOps rule load failed: ${error.message}`, "error");
  }
}

function openExamplePanel() {
  examplePanel.hidden = false;
  closeGoogleSecOpsPanel();
  renderExamples();
  exampleSearch.focus();
}

function closeExamplePanel() {
  examplePanel.hidden = true;
}

function openGoogleSecOpsPanel() {
  googleSecOpsPanel.hidden = false;
  closeExamplePanel();
  renderGoogleSecOpsPanel();
  googleSecOpsSearch.focus();
}

function closeGoogleSecOpsPanel() {
  googleSecOpsPanel.hidden = true;
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
wrapTextBtn.addEventListener("click", toggleWrapText);
chooseExampleBtn.addEventListener("click", openExamplePanel);
googleSecOpsRulesBtn.addEventListener("click", openGoogleSecOpsPanel);
closeExampleBtn.addEventListener("click", closeExamplePanel);
closeGoogleSecOpsBtn.addEventListener("click", closeGoogleSecOpsPanel);
randomExampleBtn.addEventListener("click", loadRandomExample);
exampleSearch.addEventListener("input", renderExamples);
googleSecOpsSearch.addEventListener("input", renderGoogleSecOpsRules);
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

  if (event.key === "Escape" && !googleSecOpsPanel.hidden) {
    closeGoogleSecOpsPanel();
  }
});

window.YARALINT_TESTS = {
  ...(window.YARALINT_TESTS || {}),
  buildGoogleSecOpsManifest,
  isGoogleSecOpsRuleFile
};

initializeVersionBadge();
initializeTheme();
renderExamples();
setValidationBadge("READY");
renderLintResults();
setStatus("Ready.");

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
const toast = document.querySelector("#toast");

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

function highlightYaraL(source) {
  return escapeHtml(source)
    .replace(/(#.*)$/gm, '<span class="token-comment">$1</span>')
    .replace(/("(?:\\.|[^"\\])*")/g, '<span class="token-string">$1</span>')
    .replace(/(^|\s)(\$[A-Za-z_][\w.]*)/g, '$1<span class="token-variable">$2</span>')
    .replace(/\b(rule|and|or|not|nocase|re|regex|any|all|of|them|in|over|match|outcome|condition|events|strings|meta|options)\b/g, '<span class="token-keyword">$1</span>')
    .replace(/(^\s*)(meta|strings|events|match|outcome|condition|options):/gim, '$1<span class="token-section">$2:</span>');
}

function updateHighlightedOutput() {
  highlightedOutput.innerHTML = output.value.trim()
    ? highlightYaraL(output.value)
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

function runFormatter() {
  const source = input.value;

  if (!source.trim()) {
    output.value = "";
    updateHighlightedOutput();
    setStatus("Paste a YARA-L rule to format.", "warning");
    return;
  }

  const result = formatYaraL(source, {
    indentSize: Number(indentSize.value),
    compactBlankLines: compactBlankLines.checked
  });

  output.value = result.text;
  updateHighlightedOutput();

  if (result.warnings.length > 0) {
    setStatus(`Formatted with warnings: ${result.warnings.join(" ")}`, "warning");
  } else {
    setStatus("Formatted successfully.");
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

initializeTheme();
renderExamples();
setStatus("Ready.");

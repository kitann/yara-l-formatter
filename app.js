const input = document.querySelector("#input");
const output = document.querySelector("#output");
const formatBtn = document.querySelector("#formatBtn");
const copyBtn = document.querySelector("#copyBtn");
const downloadBtn = document.querySelector("#downloadBtn");
const clearBtn = document.querySelector("#clearBtn");
const indentSize = document.querySelector("#indentSize");
const compactBlankLines = document.querySelector("#compactBlankLines");
const statusBox = document.querySelector("#status");

const sectionPattern = /^(meta|events|match|outcome|condition|options):$/i;

function setStatus(message, type = "ok") {
  statusBox.textContent = message;
  statusBox.className = `status${type === "ok" ? "" : ` ${type}`}`;
}

function normalizeOperators(line) {
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

function formatYaraL(source, options) {
  const indentUnit = " ".repeat(options.indentSize);
  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  const formatted = [];
  const warnings = [];
  let indentLevel = 0;
  let insideSection = false;
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
      if (indentLevel === 0) {
        insideSection = false;
      }
    }

    if (sectionPattern.test(line)) {
      formatted.push(`${indentUnit.repeat(indentLevel)}${line}`);
      insideSection = true;
    } else {
      const bodyIndent = insideSection && !line.startsWith("}") ? indentLevel + 1 : indentLevel;
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
    setStatus("Paste a YARA-L rule to format.", "warning");
    return;
  }

  const result = formatYaraL(source, {
    indentSize: Number(indentSize.value),
    compactBlankLines: compactBlankLines.checked
  });

  output.value = result.text;

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
  setStatus("Editors cleared.");
  input.focus();
}

formatBtn.addEventListener("click", runFormatter);
copyBtn.addEventListener("click", copyOutput);
downloadBtn.addEventListener("click", downloadOutput);
clearBtn.addEventListener("click", clearEditors);
indentSize.addEventListener("change", runFormatter);
compactBlankLines.addEventListener("change", runFormatter);

input.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    runFormatter();
  }
});

setStatus("Ready.");

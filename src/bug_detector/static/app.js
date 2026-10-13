/**
 * PyBugLens — AI-Powered Python Code Intelligence
 * Web Dashboard Application Architecture & Reactive Controller
 *
 * Security: Strictly uses DOM textContent and elements to eliminate XSS risks.
 * Zero-Execution Guarantee: User-submitted code is never executed.
 */

// Global function reference for test suite inspection
let renderAnalysisResults;

document.addEventListener("DOMContentLoaded", () => {
  // ------------------------------------------------------------------------
  // DOM Elements - Shell & Navigation
  // ------------------------------------------------------------------------
  const appSidebar = document.getElementById("app-sidebar");
  const sidebarToggleBtn = document.getElementById("sidebar-toggle-btn");
  const navItems = document.querySelectorAll(".nav-item");
  const viewPanels = document.querySelectorAll(".view-panel");
  const activeFilenameDisplay = document.getElementById("active-filename-display");
  const currentFilenameBadge = document.getElementById("current-filename");
  const sidebarHistoryCount = document.getElementById("sidebar-history-count");

  // Theme controls
  const themeToggleBtn = document.getElementById("theme-toggle-btn");
  const themeToggleText = document.getElementById("theme-toggle-text");
  const settingThemeSelect = document.getElementById("setting-theme-select");

  // Top header status
  const demoIndicator = document.getElementById("demo-indicator");
  const healthIndicator = document.getElementById("health-indicator");
  const versionBadge = document.getElementById("version-badge");

  // ------------------------------------------------------------------------
  // DOM Elements - Code Editor
  // ------------------------------------------------------------------------
  const codeInput = document.getElementById("code-input");
  const editorGutter = document.getElementById("editor-gutter");
  const charCount = document.getElementById("char-count");
  const lineCount = document.getElementById("line-count");
  const tabIndicator = document.getElementById("tab-indicator");
  const sampleSelect = document.getElementById("sample-select");
  const analyzeBtn = document.getElementById("analyze-btn");
  const analyzeSpinner = document.getElementById("analyze-spinner");
  const analyzeIcon = document.getElementById("analyze-icon");
  const clearBtn = document.getElementById("clear-btn");
  const aiToggle = document.getElementById("ai-toggle");
  const aiToggleLabel = document.getElementById("ai-toggle-label");

  // ------------------------------------------------------------------------
  // DOM Elements - Results & Reports
  // ------------------------------------------------------------------------
  const emptyState = document.getElementById("empty-state");
  const resultsContainer = document.getElementById("results-container");
  const execTimePill = document.getElementById("exec-time");
  const copySummaryBtn = document.getElementById("copy-summary-btn");
  const exportJsonBtn = document.getElementById("export-json-btn");

  const statusBanner = document.getElementById("status-banner");
  const statusIcon = document.getElementById("status-icon");
  const statusTitle = document.getElementById("status-title");
  const statusDesc = document.getElementById("status-desc");

  // Metrics cards & filters
  const metricCards = document.querySelectorAll(".metric-card");
  const metricTotal = document.getElementById("metric-total");
  const metricCritical = document.getElementById("metric-critical");
  const metricError = document.getElementById("metric-error");
  const metricWarning = document.getElementById("metric-warning");
  const metricInfo = document.getElementById("metric-info");

  // AI Review Card
  const aiReviewCard = document.getElementById("ai-review-card");
  const aiModelTag = document.getElementById("ai-model-tag");
  const aiTokensTag = document.getElementById("ai-tokens-tag");
  const aiReviewContent = document.getElementById("ai-review-content");

  // Findings list & tools
  const findingsList = document.getElementById("findings-list");
  const findingsCountBadge = document.getElementById("findings-count-badge");
  const findingSearchInput = document.getElementById("finding-search-input");
  const findingSortSelect = document.getElementById("finding-sort-select");

  // ------------------------------------------------------------------------
  // DOM Elements - History & Settings
  // ------------------------------------------------------------------------
  const historyItemsContainer = document.getElementById("history-items-container");
  const modalHistoryItemsContainer = document.getElementById("modal-history-items-container");
  const refreshHistoryBtn = document.getElementById("refresh-history-btn");
  const clearHistoryViewBtn = document.getElementById("clear-history-view-btn");
  const demoModeHistoryNotice = document.getElementById("demo-mode-history-notice");
  const modalDemoNotice = document.getElementById("modal-demo-notice");

  const historyModal = document.getElementById("history-modal");
  const toggleHistoryBtn = document.getElementById("toggle-history-btn");
  const closeHistoryBtn = document.getElementById("close-history-btn");
  const clearHistoryBtn = document.getElementById("clear-history-btn");

  const settingFontSize = document.getElementById("setting-font-size");
  const settingTabSize = document.getElementById("setting-tab-size");

  // Status Bar
  const statusLatency = document.getElementById("status-latency");
  const statusLinesAnalyzed = document.getElementById("status-lines-analyzed");
  const toastContainer = document.getElementById("toast-container");

  // ------------------------------------------------------------------------
  // Application State
  // ------------------------------------------------------------------------
  const state = {
    demoMode: false,
    aiConfigured: false,
    currentResult: null,
    currentFilter: "all",
    searchQuery: "",
    sortBy: "line",
    tabSpaces: 4,
  };

  // ------------------------------------------------------------------------
  // Sample Code Catalog (10 Built-in Analyzers & Edge Cases)
  // ------------------------------------------------------------------------
  const SAMPLE_CODE = {
    clean: `def calculate_hypotenuse(a: float, b: float) -> float:
    """Calculate Euclidean hypotenuse safely."""
    return (a ** 2 + b ** 2) ** 0.5
`,
    mutable_default: `def append_to_cache(item: str, cache: list = []) -> list:
    """CORR001: Mutable default list argument shares state across calls."""
    cache.append(item)
    return cache
`,
    zero_division: `def compute_ratio(total: int) -> float:
    """CORR002: Division by literal zero."""
    return total / 0
`,
    ineffective_comparison: `def evaluate_threshold(x: int) -> bool:
    """CORR003: Standalone comparison statement has no effect."""
    x == 100
    return x > 50
`,
    unreachable: `def get_status() -> str:
    """CORR004: Statements following unconditional return are dead code."""
    return "active"
    print("This will never be executed")
`,
    eval_exec: `def run_dynamic(expression: str):
    """SEC001: Dangerous dynamic evaluation via eval()."""
    return eval(expression)
`,
    hardcoded_secret: `def authenticate():
    """SEC002: Hardcoded sensitive credentials in source code."""
    api_token = "sk-live-99887766554433221100aabbccddeeff"
    return api_token
`,
    insecure_tempfile: `import tempfile

def create_scratch_file():
    """SEC003: Insecure temporary file generation susceptible to symlink race."""
    return tempfile.mktemp()
`,
    bare_except: `def handle_process():
    """STYLE001: Bare except suppresses system exits and interrupts."""
    try:
        data = int("abc")
    except:
        pass
`,
    unused_var: `def compute_discount(price: float) -> float:
    """STYLE002: Unused local variable definition."""
    markup_factor = 1.25
    discount = 0.10
    return price * (1.0 - discount)
`,
    duplicate_branch: `def evaluate_flag(flag: bool) -> str:
    """STYLE003: Identical logic across conditional branches."""
    if flag:
        return "ready"
    else:
        return "ready"
`,
    syntax_error: `def broken_syntax(param)
    print("Missing colon in function definition")
`,
  };

  // ------------------------------------------------------------------------
  // Toast Notifications
  // ------------------------------------------------------------------------
  function showToast(message, type = "info") {
    if (!toastContainer) return;
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(10px)";
      toast.style.transition = "all 0.2s ease";
      setTimeout(() => toast.remove(), 250);
    }, 3000);
  }

  // ------------------------------------------------------------------------
  // Synchronized Gutter & Editor Statistics
  // ------------------------------------------------------------------------
  function updateEditorStats() {
    const text = codeInput.value;
    const lines = text ? text.split("\n") : [""];
    const totalLines = lines.length;

    // Update footer indicators
    if (charCount) charCount.textContent = `${text.length} chars`;
    if (lineCount) lineCount.textContent = `${totalLines} line${totalLines === 1 ? "" : "s"}`;

    // Rebuild line number gutter
    if (editorGutter) {
      const fragment = document.createDocumentFragment();
      for (let i = 1; i <= totalLines; i++) {
        const span = document.createElement("span");
        span.className = "gutter-line-number";
        span.textContent = i;
        fragment.appendChild(span);
      }
      editorGutter.innerHTML = "";
      editorGutter.appendChild(fragment);
      editorGutter.scrollTop = codeInput.scrollTop;
    }
  }

  // Scroll sync between code textarea and line gutter
  codeInput.addEventListener("scroll", () => {
    if (editorGutter) {
      editorGutter.scrollTop = codeInput.scrollTop;
    }
  });

  codeInput.addEventListener("input", updateEditorStats);

  // Tab key & Indentation handler (Tab -> 4 spaces, Shift+Tab -> Dedent)
  codeInput.addEventListener("keydown", (e) => {
    if (e.key === "Tab") {
      e.preventDefault();
      const start = codeInput.selectionStart;
      const end = codeInput.selectionEnd;
      const spaces = " ".repeat(state.tabSpaces);

      if (!e.shiftKey) {
        // Insert spaces at cursor
        if (start === end) {
          codeInput.setRangeText(spaces, start, end, "end");
        } else {
          // Multiline indent
          const value = codeInput.value;
          const lineStart = value.lastIndexOf("\n", start - 1) + 1;
          const lineEnd = value.indexOf("\n", end);
          const sliceEnd = lineEnd === -1 ? value.length : lineEnd;
          const lines = value.substring(lineStart, sliceEnd).split("\n");
          const indented = lines.map((l) => spaces + l).join("\n");
          codeInput.setRangeText(indented, lineStart, sliceEnd, "select");
        }
      } else {
        // Shift+Tab Dedent
        const value = codeInput.value;
        const lineStart = value.lastIndexOf("\n", start - 1) + 1;
        const lineEnd = value.indexOf("\n", end);
        const sliceEnd = lineEnd === -1 ? value.length : lineEnd;
        const lines = value.substring(lineStart, sliceEnd).split("\n");
        const dedented = lines
          .map((l) => {
            if (l.startsWith(spaces)) return l.substring(spaces.length);
            if (l.startsWith("  ")) return l.substring(2);
            if (l.startsWith(" ")) return l.substring(1);
            return l;
          })
          .join("\n");
        codeInput.setRangeText(dedented, lineStart, sliceEnd, "select");
      }
      updateEditorStats();
    }

    // Ctrl + Enter or Cmd + Enter shortcut for instant analysis
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      analyzeCode();
    }
  });

  // Highlight specific line in editor
  function jumpToLine(lineNumber) {
    switchView("workspace");
    const lines = codeInput.value.split("\n");
    if (lineNumber < 1 || lineNumber > lines.length) return;

    let charPos = 0;
    for (let i = 0; i < lineNumber - 1; i++) {
      charPos += lines[i].length + 1;
    }

    const lineLen = lines[lineNumber - 1].length;
    codeInput.focus();
    codeInput.setSelectionRange(charPos, charPos + lineLen);

    // Scroll roughly to line
    const approxLineHeight = 22.4;
    codeInput.scrollTop = Math.max(0, (lineNumber - 4) * approxLineHeight);

    // Highlight line in gutter
    if (editorGutter) {
      const numbers = editorGutter.querySelectorAll(".gutter-line-number");
      numbers.forEach((num, idx) => {
        if (idx + 1 === lineNumber) {
          num.classList.add("active");
        } else {
          num.classList.remove("active");
        }
      });
    }
  }

  // ------------------------------------------------------------------------
  // Sample Selection & Clearing
  // ------------------------------------------------------------------------
  sampleSelect.addEventListener("change", (e) => {
    const key = e.target.value;
    if (key && SAMPLE_CODE[key]) {
      codeInput.value = SAMPLE_CODE[key];
      const filename = `${key}_sample.py`;
      if (activeFilenameDisplay) activeFilenameDisplay.textContent = filename;
      if (currentFilenameBadge) currentFilenameBadge.textContent = filename;
      updateEditorStats();
      showToast(`Loaded sample: ${sampleSelect.options[sampleSelect.selectedIndex].text}`);
    }
  });

  clearBtn.addEventListener("click", () => {
    codeInput.value = "";
    sampleSelect.value = "";
    if (activeFilenameDisplay) activeFilenameDisplay.textContent = "snippet.py";
    if (currentFilenameBadge) currentFilenameBadge.textContent = "snippet.py";
    updateEditorStats();
    emptyState.classList.remove("hidden");
    resultsContainer.classList.add("hidden");
    execTimePill.classList.add("hidden");
    copySummaryBtn.classList.add("hidden");
    exportJsonBtn.classList.add("hidden");
    state.currentResult = null;
  });

  // ------------------------------------------------------------------------
  // View Navigation System
  // ------------------------------------------------------------------------
  function switchView(viewName) {
    viewPanels.forEach((panel) => {
      if (panel.id === `view-${viewName}`) {
        panel.classList.add("active");
      } else {
        panel.classList.remove("active");
      }
    });

    navItems.forEach((btn) => {
      if (btn.getAttribute("data-view") === viewName) {
        btn.classList.add("active");
      } else {
        btn.classList.remove("active");
      }
    });

    // Close mobile sidebar if open
    if (appSidebar) appSidebar.classList.remove("open");

    // Refresh history if opening history view
    if (viewName === "history") {
      loadHistory();
    }
  }

  navItems.forEach((btn) => {
    btn.addEventListener("click", () => {
      const view = btn.getAttribute("data-view");
      if (view) switchView(view);
    });
  });

  if (sidebarToggleBtn) {
    sidebarToggleBtn.addEventListener("click", () => {
      if (appSidebar) appSidebar.classList.toggle("open");
    });
  }

  // ------------------------------------------------------------------------
  // Theme Toggle & Persistence
  // ------------------------------------------------------------------------
  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("pybuglens_theme", theme);

    if (themeToggleText) {
      themeToggleText.textContent = theme === "dark" ? "Dark Navy" : "Light Mode";
    }
    if (settingThemeSelect) {
      settingThemeSelect.value = theme;
    }
  }

  themeToggleBtn.addEventListener("click", () => {
    const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
    const nextTheme = currentTheme === "dark" ? "light" : "dark";
    applyTheme(nextTheme);
  });

  if (settingThemeSelect) {
    settingThemeSelect.addEventListener("change", (e) => {
      applyTheme(e.target.value);
    });
  }

  // Load saved theme
  const savedTheme = localStorage.getItem("pybuglens_theme") || "dark";
  applyTheme(savedTheme);

  // ------------------------------------------------------------------------
  // Workspace Settings
  // ------------------------------------------------------------------------
  if (settingFontSize) {
    const savedFontSize = localStorage.getItem("pybuglens_font_size") || "14px";
    settingFontSize.value = savedFontSize;
    codeInput.style.fontSize = savedFontSize;
    editorGutter.style.fontSize = savedFontSize;

    settingFontSize.addEventListener("change", (e) => {
      const val = e.target.value;
      codeInput.style.fontSize = val;
      editorGutter.style.fontSize = val;
      localStorage.setItem("pybuglens_font_size", val);
      showToast(`Font size updated to ${val}`);
    });
  }

  if (settingTabSize) {
    const savedTab = localStorage.getItem("pybuglens_tab_size") || "4";
    settingTabSize.value = savedTab;
    state.tabSpaces = parseInt(savedTab, 10);
    if (tabIndicator) tabIndicator.textContent = `Spaces: ${state.tabSpaces}`;

    settingTabSize.addEventListener("change", (e) => {
      state.tabSpaces = parseInt(e.target.value, 10);
      codeInput.style.tabSize = state.tabSpaces;
      if (tabIndicator) tabIndicator.textContent = `Spaces: ${state.tabSpaces}`;
      localStorage.setItem("pybuglens_tab_size", e.target.value);
      showToast(`Indentation set to ${state.tabSpaces} spaces`);
    });
  }

  // ------------------------------------------------------------------------
  // Health & System Capability Discovery
  // ------------------------------------------------------------------------
  async function fetchHealth() {
    try {
      const response = await fetch("/api/health");
      if (!response.ok) throw new Error("Health endpoint unavailable");
      const data = await response.json();

      state.demoMode = Boolean(data.demo_mode);
      state.aiConfigured = Boolean(data.ai_configured);

      if (versionBadge) versionBadge.textContent = `v${data.version}`;

      if (data.demo_mode) {
        demoIndicator.classList.remove("hidden");
        aiToggle.disabled = true;
        aiToggle.checked = false;
        const toggleText = aiToggleLabel ? aiToggleLabel.querySelector(".toggle-text") : null;
        if (toggleText) toggleText.textContent = "AI (Disabled in Demo)";
      } else if (!data.ai_configured) {
        aiToggle.disabled = true;
        aiToggle.checked = false;
        const toggleText = aiToggleLabel ? aiToggleLabel.querySelector(".toggle-text") : null;
        if (toggleText) toggleText.textContent = "AI (Key Not Set)";
      }

      healthIndicator.textContent = "API Operational";
      healthIndicator.className = "pill pill-success";
    } catch {
      healthIndicator.textContent = "Disconnected";
      healthIndicator.className = "pill pill-danger";
    }
  }

  // ------------------------------------------------------------------------
  // Code Submission & Analysis Pipeline
  // ------------------------------------------------------------------------
  async function analyzeCode() {
    const sourceCode = codeInput.value.trim();
    if (!sourceCode) {
      showToast("Please enter or select Python code to inspect.", "warning");
      return;
    }

    // Set UI loading state
    analyzeBtn.disabled = true;
    if (analyzeSpinner) analyzeSpinner.classList.remove("hidden");
    if (analyzeIcon) analyzeIcon.classList.add("hidden");

    try {
      const filename = activeFilenameDisplay ? activeFilenameDisplay.textContent : "snippet.py";
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_code: sourceCode,
          filename: filename,
          enable_ai: aiToggle.checked && !state.demoMode,
        }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ detail: "Analysis failed." }));
        throw new Error(errData.detail || "Server error occurred during static analysis.");
      }

      const result = await response.json();
      renderAnalysisResults(result);
      showToast("Analysis completed successfully", "success");
      updateHistoryCount();
    } catch (err) {
      showToast(`Analysis Error: ${err.message}`, "danger");
    } finally {
      analyzeBtn.disabled = false;
      if (analyzeSpinner) analyzeSpinner.classList.add("hidden");
      if (analyzeIcon) analyzeIcon.classList.remove("hidden");
    }
  }

  analyzeBtn.addEventListener("click", analyzeCode);

  // ------------------------------------------------------------------------
  // Result Presentation & Findings Rendering
  // ------------------------------------------------------------------------
  renderAnalysisResults = function (result) {
    state.currentResult = result;
    emptyState.classList.add("hidden");
    resultsContainer.classList.remove("hidden");

    // Show header actions
    execTimePill.textContent = `${result.execution_duration_ms.toFixed(2)} ms`;
    execTimePill.classList.remove("hidden");
    copySummaryBtn.classList.remove("hidden");
    exportJsonBtn.classList.remove("hidden");

    // Status bar updates
    if (statusLatency) statusLatency.textContent = `Latency: ${result.execution_duration_ms.toFixed(2)} ms`;
    const linesCount = codeInput.value ? codeInput.value.split("\n").length : 0;
    if (statusLinesAnalyzed) statusLinesAnalyzed.textContent = `${linesCount} lines analyzed`;

    // Syntax Banner presentation
    statusBanner.className = "status-banner";
    if (!result.syntax.is_valid) {
      statusBanner.classList.add("error");
      statusIcon.textContent = "✕";
      statusTitle.textContent = "Syntax Error Detected";
      statusDesc.textContent = `${result.syntax.error_message || "Invalid syntax"} (Line ${result.syntax.line || 1}, Col ${result.syntax.column || 1})`;

      // Highlight syntax line in gutter
      if (result.syntax.line && editorGutter) {
        const numbers = editorGutter.querySelectorAll(".gutter-line-number");
        numbers.forEach((num, idx) => {
          if (idx + 1 === result.syntax.line) {
            num.classList.add("error-line");
          }
        });
      }
    } else if (result.findings.length === 0) {
      statusBanner.classList.add("success");
      statusIcon.textContent = "✓";
      statusTitle.textContent = "Syntax Valid — Clean Code";
      statusDesc.textContent = "Zero static bug defects or code smells detected across 10 AST rules.";
    } else {
      statusBanner.classList.add("warning");
      statusIcon.textContent = "⚠";
      statusTitle.textContent = "Syntax Valid — Issues Detected";
      statusDesc.textContent = `Found ${result.findings.length} static findings requiring review.`;
    }

    // Metric Summary Counters
    metricTotal.textContent = result.summary.total_findings;
    metricCritical.textContent = result.summary.critical_count;
    metricError.textContent = result.summary.error_count;
    metricWarning.textContent = result.summary.warning_count;
    metricInfo.textContent = result.summary.info_count;

    // AI Review Card Presentation
    if (result.ai_review && result.ai_review.enabled) {
      aiReviewCard.classList.remove("hidden");
      aiModelTag.textContent = result.ai_review.model_used || "OpenAI";
      aiTokensTag.textContent = result.ai_review.tokens_used
        ? `${result.ai_review.tokens_used} tokens`
        : "N/A";

      aiReviewContent.textContent = result.ai_review.success
        ? result.ai_review.review_text
        : `AI Review Notice: ${result.ai_review.error_message || "Service unavailable"}`;
    } else {
      aiReviewCard.classList.add("hidden");
    }

    // Render Filtered Findings
    renderFindingsList();
  };

  // Severity metrics click-to-filter
  metricCards.forEach((card) => {
    card.addEventListener("click", () => {
      metricCards.forEach((c) => c.classList.remove("active-filter"));
      card.classList.add("active-filter");
      state.currentFilter = card.getAttribute("data-filter") || "all";
      renderFindingsList();
    });
  });

  // Search input live filter
  if (findingSearchInput) {
    findingSearchInput.addEventListener("input", (e) => {
      state.searchQuery = e.target.value.toLowerCase().trim();
      renderFindingsList();
    });
  }

  // Sort select handler
  if (findingSortSelect) {
    findingSortSelect.addEventListener("change", (e) => {
      state.sortBy = e.target.value;
      renderFindingsList();
    });
  }

  function renderFindingsList() {
    if (!state.currentResult) return;
    const allFindings = state.currentResult.findings || [];

    // Filter by severity
    let filtered = allFindings.filter((finding) => {
      if (state.currentFilter === "all") return true;
      return finding.severity.toLowerCase() === state.currentFilter.toLowerCase();
    });

    // Filter by search query
    if (state.searchQuery) {
      filtered = filtered.filter((f) => {
        return (
          f.rule_id.toLowerCase().includes(state.searchQuery) ||
          f.message.toLowerCase().includes(state.searchQuery) ||
          f.explanation.toLowerCase().includes(state.searchQuery) ||
          f.category.toLowerCase().includes(state.searchQuery)
        );
      });
    }

    // Sort findings
    filtered.sort((a, b) => {
      if (state.sortBy === "line") {
        return a.location.line - b.location.line || a.location.column - b.location.column;
      }
      if (state.sortBy === "severity") {
        const priority = { CRITICAL: 4, ERROR: 3, WARNING: 2, INFO: 1 };
        return (priority[b.severity] || 0) - (priority[a.severity] || 0);
      }
      if (state.sortBy === "rule") {
        return a.rule_id.localeCompare(b.rule_id);
      }
      return 0;
    });

    // Update count badge
    findingsCountBadge.textContent = `${filtered.length} of ${allFindings.length}`;
    findingsList.innerHTML = "";

    if (filtered.length === 0) {
      const emptyDiv = document.createElement("div");
      emptyDiv.className = "finding-explanation";
      emptyDiv.style.padding = "1.5rem";
      emptyDiv.style.textAlign = "center";
      emptyDiv.textContent =
        allFindings.length === 0
          ? "No rule violations detected. Python code conforms to static verification checks."
          : "No findings match the selected filter or search criteria.";
      findingsList.appendChild(emptyDiv);
      return;
    }

    filtered.forEach((finding) => {
      const card = document.createElement("div");
      card.className = `finding-card ${finding.severity.toLowerCase()}`;

      // Metadata Header
      const meta = document.createElement("div");
      meta.className = "finding-meta";

      const sevBadge = document.createElement("span");
      sevBadge.className = `badge-sev ${finding.severity.toLowerCase()}`;
      sevBadge.textContent = finding.severity;

      const ruleTag = document.createElement("span");
      ruleTag.className = "rule-tag";
      ruleTag.textContent = finding.rule_id;

      const catTag = document.createElement("span");
      catTag.className = "cat-tag";
      catTag.textContent = finding.category;

      const locTag = document.createElement("span");
      locTag.className = "loc-tag";
      locTag.title = "Click to jump to line in editor";
      locTag.textContent = `Line ${finding.location.line}:${finding.location.column}`;
      locTag.addEventListener("click", () => jumpToLine(finding.location.line));

      meta.appendChild(sevBadge);
      meta.appendChild(ruleTag);
      meta.appendChild(catTag);
      meta.appendChild(locTag);

      // Headline
      const msg = document.createElement("div");
      msg.className = "finding-msg";
      msg.textContent = finding.message;

      // Explanation
      const exp = document.createElement("div");
      exp.className = "finding-explanation";
      exp.textContent = finding.explanation;

      card.appendChild(meta);
      card.appendChild(msg);
      card.appendChild(exp);

      // Code Snippet (if available)
      if (finding.code_snippet) {
        const snippet = document.createElement("pre");
        snippet.className = "finding-snippet";
        snippet.textContent = finding.code_snippet;
        card.appendChild(snippet);
      }

      // Remediation Recommendation
      if (finding.suggested_fix) {
        const fixBlock = document.createElement("div");
        fixBlock.className = "finding-fix";
        const fixTitle = document.createElement("strong");
        fixTitle.textContent = "Suggested Remediation:";
        const fixText = document.createElement("div");
        fixText.textContent = finding.suggested_fix;
        fixBlock.appendChild(fixTitle);
        fixBlock.appendChild(fixText);
        card.appendChild(fixBlock);
      }

      findingsList.appendChild(card);
    });
  }

  // ------------------------------------------------------------------------
  // Copy Summary & Export JSON
  // ------------------------------------------------------------------------
  copySummaryBtn.addEventListener("click", async () => {
    if (!state.currentResult) return;
    const res = state.currentResult;
    let md = `# PyBugLens Analysis Report\n\n`;
    md += `- **Timestamp:** ${res.timestamp}\n`;
    md += `- **Execution Time:** ${res.execution_duration_ms.toFixed(2)} ms\n`;
    md += `- **Syntax Valid:** ${res.syntax.is_valid ? "Yes" : "No"}\n`;
    md += `- **Total Findings:** ${res.summary.total_findings}\n\n`;

    if (res.findings.length > 0) {
      md += `### Findings\n\n`;
      res.findings.forEach((f, idx) => {
        md += `${idx + 1}. **[${f.severity}] ${f.rule_id}**: ${f.message} (Line ${f.location.line})\n`;
        md += `   - *Remediation:* ${f.suggested_fix || "None specified"}\n`;
      });
    } else {
      md += `*Zero static defects detected.*\n`;
    }

    try {
      await navigator.clipboard.writeText(md);
      showToast("Report copied to clipboard as Markdown", "success");
    } catch {
      showToast("Failed to copy report to clipboard", "danger");
    }
  });

  exportJsonBtn.addEventListener("click", () => {
    if (!state.currentResult) return;
    const blob = new Blob([JSON.stringify(state.currentResult, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `pybuglens_analysis_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("Analysis report exported as JSON", "success");
  });

  // ------------------------------------------------------------------------
  // Review History Management (Both Full View & Modal Drawer)
  // ------------------------------------------------------------------------
  async function updateHistoryCount() {
    if (state.demoMode) return;
    try {
      const response = await fetch("/api/history?limit=100");
      if (response.ok) {
        const items = await response.json();
        if (sidebarHistoryCount) sidebarHistoryCount.textContent = items.length;
      }
    } catch {
      // Ignored for offline safety
    }
  }

  async function loadHistory() {
    if (historyItemsContainer) historyItemsContainer.innerHTML = "";
    if (modalHistoryItemsContainer) modalHistoryItemsContainer.innerHTML = "";

    if (state.demoMode) {
      if (demoModeHistoryNotice) demoModeHistoryNotice.classList.remove("hidden");
      if (modalDemoNotice) modalDemoNotice.classList.remove("hidden");
      if (clearHistoryBtn) clearHistoryBtn.classList.add("hidden");
      if (clearHistoryViewBtn) clearHistoryViewBtn.classList.add("hidden");
      return;
    }

    if (demoModeHistoryNotice) demoModeHistoryNotice.classList.add("hidden");
    if (modalDemoNotice) modalDemoNotice.classList.add("hidden");
    if (clearHistoryBtn) clearHistoryBtn.classList.remove("hidden");
    if (clearHistoryViewBtn) clearHistoryViewBtn.classList.remove("hidden");

    try {
      const response = await fetch("/api/history?limit=30");
      if (response.status === 403) {
        if (demoModeHistoryNotice) demoModeHistoryNotice.classList.remove("hidden");
        return;
      }
      if (!response.ok) throw new Error("Failed to load review history.");

      const items = await response.json();
      if (sidebarHistoryCount) sidebarHistoryCount.textContent = items.length;

      if (!items || items.length === 0) {
        const emptyMsg = document.createElement("p");
        emptyMsg.className = "text-muted";
        emptyMsg.style.textAlign = "center";
        emptyMsg.style.padding = "2rem 0";
        emptyMsg.textContent = "No review records found in local SQLite database.";

        if (historyItemsContainer) historyItemsContainer.appendChild(emptyMsg.cloneNode(true));
        if (modalHistoryItemsContainer) modalHistoryItemsContainer.appendChild(emptyMsg);
        return;
      }

      items.forEach((item) => {
        // Build card for Full View
        if (historyItemsContainer) {
          const row = document.createElement("div");
          row.className = "history-card-row";

          const left = document.createElement("div");
          left.className = "history-row-left";

          const title = document.createElement("div");
          title.className = "history-row-filename";
          title.textContent = `${item.filename} (Hash: ${item.code_hash.substring(0, 8)}...)`;

          const meta = document.createElement("div");
          meta.className = "history-row-meta";
          meta.textContent = `${new Date(item.timestamp).toLocaleString()} • Duration: ${item.execution_duration_ms ? item.execution_duration_ms.toFixed(1) : 0}ms`;

          left.appendChild(title);
          left.appendChild(meta);

          const right = document.createElement("div");
          right.className = "history-row-right";

          const badge = document.createElement("span");
          badge.className = `badge ${item.total_findings > 0 ? "pill-warning" : "pill-success"}`;
          badge.textContent = `${item.total_findings} finding${item.total_findings === 1 ? "" : "s"}`;

          right.appendChild(badge);
          row.appendChild(left);
          row.appendChild(right);

          row.addEventListener("click", () => fetchAndLoadHistoricalReview(item.review_id));
          historyItemsContainer.appendChild(row);
        }

        // Build item for Modal Drawer
        if (modalHistoryItemsContainer) {
          const itemDiv = document.createElement("div");
          itemDiv.className = "history-item";

          const left = document.createElement("div");
          left.className = "history-item-left";
          const title = document.createElement("div");
          title.className = "history-item-title";
          title.textContent = `${item.filename} (${item.code_hash.substring(0, 8)}...)`;
          const date = document.createElement("div");
          date.className = "history-item-date";
          date.textContent = new Date(item.timestamp).toLocaleTimeString();
          left.appendChild(title);
          left.appendChild(date);

          const right = document.createElement("div");
          right.className = "history-item-right";
          const findingsTag = document.createElement("span");
          findingsTag.className = "badge";
          findingsTag.textContent = `${item.total_findings} items`;
          right.appendChild(findingsTag);

          itemDiv.appendChild(left);
          itemDiv.appendChild(right);
          itemDiv.addEventListener("click", () => fetchAndLoadHistoricalReview(item.review_id));
          modalHistoryItemsContainer.appendChild(itemDiv);
        }
      });
    } catch (err) {
      const errMsg = document.createElement("p");
      errMsg.className = "pill pill-danger";
      errMsg.textContent = err.message;
      if (historyItemsContainer) historyItemsContainer.appendChild(errMsg);
    }
  }

  async function fetchAndLoadHistoricalReview(reviewId) {
    try {
      const res = await fetch(`/api/history/${reviewId}`);
      if (!res.ok) throw new Error("Failed to load review details.");
      const data = await res.json();

      codeInput.value = data.source_code;
      if (activeFilenameDisplay) activeFilenameDisplay.textContent = data.filename || "snippet.py";
      if (currentFilenameBadge) currentFilenameBadge.textContent = data.filename || "snippet.py";
      updateEditorStats();
      renderAnalysisResults(data);

      if (historyModal) historyModal.classList.add("hidden");
      switchView("workspace");
      showToast(`Loaded historical review for ${data.filename}`, "info");
    } catch (err) {
      showToast(`Error loading review: ${err.message}`, "danger");
    }
  }

  // History buttons
  if (refreshHistoryBtn) refreshHistoryBtn.addEventListener("click", loadHistory);

  if (toggleHistoryBtn) {
    toggleHistoryBtn.addEventListener("click", () => {
      if (historyModal) historyModal.classList.remove("hidden");
      loadHistory();
    });
  }

  if (closeHistoryBtn) {
    closeHistoryBtn.addEventListener("click", () => {
      if (historyModal) historyModal.classList.add("hidden");
    });
  }

  if (historyModal) {
    historyModal.addEventListener("click", (e) => {
      if (e.target === historyModal) {
        historyModal.classList.add("hidden");
      }
    });
  }

  // Clear history handlers
  async function handleClearHistory() {
    if (!confirm("Are you sure you want to permanently clear all review history? This cannot be undone.")) {
      return;
    }
    try {
      const res = await fetch("/api/history/clear", { method: "POST" });
      if (!res.ok) throw new Error("Failed to clear review history.");
      loadHistory();
      if (sidebarHistoryCount) sidebarHistoryCount.textContent = "0";
      showToast("Review history successfully cleared", "success");
    } catch (err) {
      showToast(`Clear history failed: ${err.message}`, "danger");
    }
  }

  if (clearHistoryBtn) clearHistoryBtn.addEventListener("click", handleClearHistory);
  if (clearHistoryViewBtn) clearHistoryViewBtn.addEventListener("click", handleClearHistory);

  // Esc key closes modals
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (historyModal && !historyModal.classList.contains("hidden")) {
        historyModal.classList.add("hidden");
      }
    }
  });

  // ------------------------------------------------------------------------
  // Startup Lifecycle
  // ------------------------------------------------------------------------
  fetchHealth();
  updateEditorStats();
  updateHistoryCount();
});

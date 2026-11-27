"use strict";

// All text that comes from scanned code is added with textContent only.
// Nothing in this file builds HTML from data.

(function () {
  var tokenMeta = document.querySelector('meta[name="vulnsight-token"]');
  var token = tokenMeta ? tokenMeta.getAttribute("content") : "";

  var form = document.getElementById("scan-form");
  var pathInput = document.getElementById("path");
  var modeSelect = document.getElementById("mode");
  var scanButton = document.getElementById("scan-button");
  var exportButton = document.getElementById("export-button");
  var banner = document.getElementById("banner");
  var busy = document.getElementById("busy");
  var modeNote = document.getElementById("mode-note");
  var results = document.getElementById("results");

  var exportText = null;
  var selectedRow = null;

  function make(tag, text, className) {
    var node = document.createElement(tag);
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    if (className) {
      node.className = className;
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function show(node, visible) {
    node.hidden = !visible;
  }

  // -- errors: four different kinds, never mixed up ----------------------

  var BANNER_TITLES = {
    http: "The local server refused the request",
    input: "Invalid input",
    internal: "Unexpected internal error",
    network: "Could not reach the local server"
  };

  function showBanner(kind, message, status) {
    clear(banner);
    var title = BANNER_TITLES[kind] || BANNER_TITLES.internal;
    if (status) {
      title += " (HTTP " + status + ")";
    }
    banner.appendChild(make("strong", title));
    banner.appendChild(make("span", " " + message));
    banner.className = "banner banner-" + kind;
    show(banner, true);
  }

  function hideBanner() {
    show(banner, false);
    clear(banner);
  }

  // -- helpers -----------------------------------------------------------

  function place(file, line, column) {
    var text = file === null || file === undefined ? "<memory>" : file;
    if (line !== null && line !== undefined) {
      text += ":" + line;
      if (column !== null && column !== undefined) {
        text += ":" + column;
      }
    }
    return text;
  }

  function cell(text, className) {
    return make("td", text, className);
  }

  function section(title) {
    var box = make("div", null, "detail-section");
    box.appendChild(make("h3", title));
    return box;
  }

  function facts(pairs) {
    var list = make("dl", null, "facts");
    pairs.forEach(function (pair) {
      list.appendChild(make("dt", pair[0]));
      list.appendChild(make("dd", pair[1]));
    });
    return list;
  }

  // A missing optional value is labelled with what its absence means:
  // severity was never assessed, ML verification was never run.
  function optional(value, missing) {
    if (value === null || value === undefined) {
      return missing;
    }
    return JSON.stringify(value);
  }

  // -- rendering ---------------------------------------------------------

  function renderSummary(view) {
    var summary = document.getElementById("summary");
    clear(summary);

    var items = [
      ["Status", view.status],
      ["Target", view.target === null ? "-" : view.target],
      ["Resolved path", view.resolved_target === null ? "-" : view.resolved_target],
      ["Parameter mode", view.parameter_mode === null ? "unknown" : view.parameter_mode],
      ["Files scanned", view.files_scanned === null ? "unknown" : view.files_scanned],
      ["Findings", view.findings_total],
      ["Errors", view.error_count],
      ["Warnings", view.warning_count]
    ];

    items.forEach(function (item) {
      var box = make("div", null, "metric");
      box.appendChild(make("dt", item[0]));
      var value = make("dd", item[1]);
      if (item[0] === "Status") {
        value.className = "status status-" + view.status;
      }
      box.appendChild(value);
      summary.appendChild(box);
    });

    var note = document.getElementById("status-note");
    if (view.status === "failed") {
      note.textContent = "The scan failed: nothing could be analysed. See the errors below.";
      note.className = "note warn";
      show(note, true);
    } else if (view.status === "partial") {
      note.textContent = "The scan is partial: some files could not be analysed. The findings below are incomplete. See the errors below.";
      note.className = "note warn";
      show(note, true);
    } else {
      show(note, false);
    }
  }

  function renderFindings(view) {
    var body = document.getElementById("findings-body");
    var table = document.getElementById("findings-table");
    var none = document.getElementById("no-findings");
    var truncation = document.getElementById("truncation");

    clear(body);
    selectedRow = null;
    show(document.getElementById("detail-card"), false);
    clear(document.getElementById("detail"));

    show(table, view.findings.length > 0);
    show(none, view.findings_total === 0);

    if (view.truncated) {
      truncation.textContent =
        "Showing the first " + view.findings_shown + " of " + view.findings_total +
        " findings. The JSON download contains all " + view.findings_total + ".";
      show(truncation, true);
    } else {
      show(truncation, false);
    }

    view.findings.forEach(function (finding) {
      var row = make("tr");

      var cweCell = make("td");
      var pick = make("button", finding.cwe, "link");
      pick.type = "button";
      pick.title = finding.cwe_name === null ? "" : finding.cwe_name;
      pick.addEventListener("click", function () {
        selectFinding(finding, row);
      });
      cweCell.appendChild(pick);
      row.appendChild(cweCell);

      row.appendChild(cell(finding.confidence, "conf conf-" + finding.confidence));
      row.appendChild(cell(finding.file === null ? "<memory>" : finding.file, "mono"));
      row.appendChild(cell(finding.line, "num"));
      row.appendChild(cell(finding.sink === null ? "-" : finding.sink.callee, "mono"));
      body.appendChild(row);
    });
  }

  function selectFinding(finding, row) {
    if (selectedRow) {
      selectedRow.className = "";
    }
    selectedRow = row;
    row.className = "selected";
    renderDetail(finding);
  }

  function renderDetail(finding) {
    var detail = document.getElementById("detail");
    clear(detail);

    detail.appendChild(make("p", finding.message, "message"));

    detail.appendChild(facts([
      ["Rule", finding.rule_id],
      ["CWE", finding.cwe + (finding.cwe_name === null ? "" : " - " + finding.cwe_name)],
      ["Confidence", finding.confidence],
      ["Taint effect", finding.taint_effect === null ? "none" : finding.taint_effect],
      ["Location", place(finding.file, finding.line, finding.column) +
        (finding.end_line === null || finding.end_line === finding.line ?
          "" : " (to line " + finding.end_line + ")")],
      ["Function", finding.enclosing_function === null ? "-" : finding.enclosing_function],
      ["Severity", optional(finding.severity, "Not assessed")],
      ["ML verification", optional(finding.verification, "Not run")]
    ]));

    var sink = section("Sink");
    if (finding.sink === null) {
      sink.appendChild(make("p", "No sink."));
    } else {
      sink.appendChild(facts([
        ["Callee", finding.sink.callee],
        ["Resolution", finding.sink.certainty]
      ]));
    }
    detail.appendChild(sink);

    var evidence = section("Taint evidence");
    if (finding.evidence.length === 0) {
      evidence.appendChild(make("p", "No taint evidence."));
    }
    finding.evidence.forEach(function (label) {
      var box = make("div", null, "evidence");
      box.appendChild(make("p",
        label.origin_id + " (" + label.kind + ") at line " + label.line + ":" + label.column,
        "origin"));

      var steps = make("ol", null, "trace");
      label.trace.forEach(function (step) {
        if (step.kind === "elided") {
          // Not a taint operation: the trace was shortened here. Its line and
          // column are copied from a neighbouring step, so they are not shown.
          steps.appendChild(make("li", "... intermediate trace steps omitted ...", "elided"));
          return;
        }
        var text = step.kind + " at line " + step.line + ":" + step.column;
        if (step.text) {
          text += " - " + step.text;
        }
        steps.appendChild(make("li", text));
      });
      box.appendChild(steps);

      label.neutralizations.forEach(function (item) {
        box.appendChild(make("p",
          "Neutralized for " + item.cwe + " by " + item.via +
          (item.platforms.length ? " (" + item.platforms.join(", ") + ")" : ""),
          "neutral"));
      });
      evidence.appendChild(box);
    });
    detail.appendChild(evidence);

    show(document.getElementById("detail-card"), true);
  }

  function renderIssues(view) {
    var body = document.getElementById("issues-body");
    var table = document.getElementById("issues-table");
    clear(body);

    show(table, view.issues.length > 0);
    show(document.getElementById("no-issues"), view.issues.length === 0);

    view.issues.forEach(function (issue) {
      var row = make("tr");
      row.appendChild(cell(issue.level, "level level-" + issue.level));
      row.appendChild(cell(issue.code, "mono"));
      row.appendChild(cell(issue.file === null ? "-" : issue.file, "mono"));
      row.appendChild(cell(issue.line === null ? "-" : issue.line, "num"));
      row.appendChild(cell(issue.message));
      body.appendChild(row);
    });
  }

  function render(payload) {
    exportText = payload.export;
    renderSummary(payload.view);
    renderFindings(payload.view);
    renderIssues(payload.view);
    show(results, true);
  }

  // -- requests ----------------------------------------------------------

  function setBusy(isBusy) {
    scanButton.disabled = isBusy;
    show(busy, isBusy);
  }

  function readError(response) {
    return response.json().then(function (body) {
      var error = body && body.error;
      if (error && typeof error.message === "string") {
        showBanner(error.kind === "input" || error.kind === "internal" ? error.kind : "http",
          error.message, response.status);
      } else {
        showBanner("http", "Unexpected response.", response.status);
      }
    }, function () {
      showBanner("http", "Unexpected response.", response.status);
    });
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    hideBanner();
    setBusy(true);

    var request = { path: pathInput.value, parameter_mode: modeSelect.value };

    fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-VulnSight-Token": token
      },
      body: JSON.stringify(request)
    }).then(function (response) {
      if (!response.ok) {
        return readError(response);
      }
      return response.json().then(render, function () {
        showBanner("internal", "The server sent an unreadable result.");
      });
    }, function () {
      showBanner("network", "Is the dashboard still running?");
    }).then(function () {
      setBusy(false);
    });
  });

  modeSelect.addEventListener("change", function () {
    show(modeNote, modeSelect.value === "recall");
  });

  exportButton.addEventListener("click", function () {
    if (exportText === null) {
      return;
    }
    // The text is saved exactly as the server sent it.
    var blob = new Blob([exportText], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = "vulnsight-scan.json";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  });
}());

"""
reports/generator.py
────────────────────
Generates a self-contained HTML detection report from alert data.

The report is the human-readable output of the full pipeline —
a single HTML file with no external dependencies that can be opened
in any browser or shared as a portfolio artifact.

It includes:
  - Pipeline summary (total events, alerts, severity breakdown)
  - Detection breakdown by type (chat vs agent)
  - Full alert table sorted by severity
  - Per-alert detail: score breakdown, detection type, rules fired
"""

from pathlib import Path
from datetime import datetime, timezone
from loguru import logger

from alerts.alerting import Alert
from etl.normalize   import Event
from detectors.scorer import DetectionResult


class ReportGenerator:
    """
    Generates a self-contained HTML report from pipeline results.

    Instantiate once, call generate() with full pipeline data.
    """

    def __init__(self, config: dict):
        self.output_path = config["reports"]["output_file"]
        logger.debug("ReportGenerator initialised")

    def generate(
        self,
        events  : list[Event],
        results : list[DetectionResult],
        alerts  : list[Alert],
    ) -> str:
        """
        Generate and write the HTML report to disk.

        Args:
            events  : All normalized events
            results : All DetectionResult objects
            alerts  : All Alert objects (HIGH + CRITICAL only)

        Returns:
            Path to the generated report file.
        """
        html = self._build_html(events, results, alerts)

        output = Path(self.output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(html, encoding="utf-8")

        logger.info(f"Report generated → {self.output_path}")
        return self.output_path

    # ── HTML builders ─────────────────────────────────────────────────────────

    def _build_html(
        self,
        events  : list[Event],
        results : list[DetectionResult],
        alerts  : list[Alert],
    ) -> str:
        """Assemble the full HTML document."""
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Stats
        total       = len(events)
        total_alerts= len(alerts)
        critical    = sum(1 for a in alerts if a.severity == "CRITICAL")
        high        = sum(1 for a in alerts if a.severity == "HIGH")
        medium      = sum(1 for r in results if r.severity == "MEDIUM")
        low         = sum(1 for r in results if r.severity == "LOW")
        chat_alerts = sum(1 for a in alerts if a.event_type == "chat")
        agent_alerts= sum(1 for a in alerts if a.event_type == "agent")
        rule_only   = sum(1 for a in alerts if a.detection_type == "rule")
        anomaly_only= sum(1 for a in alerts if a.detection_type == "anomaly")
        both        = sum(1 for a in alerts if a.detection_type == "rule + anomaly")

        alert_rows  = "\n".join(self._build_alert_row(a) for a in alerts)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>AiSecPulse — Detection Report</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;600;800&display=swap');

    :root {{
      --bg:         #090c10;
      --bg2:        #0d1117;
      --bg3:        #161b22;
      --border:     #21262d;
      --text:       #c9d1d9;
      --text-dim:   #8b949e;
      --accent:     #00ff9f;
      --accent-dim: #00c97a;
      --critical:   #ff4d4d;
      --high:       #ff9944;
      --medium:     #f0c040;
      --low:        #4caf8a;
      --rule:       #7c9ef8;
      --anomaly:    #c084fc;
      --both:       #00ff9f;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Syne', sans-serif;
      min-height: 100vh;
      padding: 0 0 80px;
    }}

    /* ── Header ── */
    header {{
      border-bottom: 1px solid var(--border);
      padding: 40px 60px 32px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      background: linear-gradient(180deg, #0d1f17 0%, var(--bg) 100%);
    }}
    .header-left h1 {{
      font-size: 2rem;
      font-weight: 800;
      letter-spacing: -0.5px;
      color: #fff;
    }}
    .header-left h1 span {{ color: var(--accent); }}
    .header-left p {{
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.75rem;
      color: var(--text-dim);
      margin-top: 6px;
    }}
    .header-right {{
      text-align: right;
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.72rem;
      color: var(--text-dim);
      line-height: 1.8;
    }}
    .live-badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: #0d1f17;
      border: 1px solid var(--accent-dim);
      color: var(--accent);
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.68rem;
      padding: 4px 10px;
      border-radius: 2px;
      margin-bottom: 8px;
    }}
    .live-dot {{
      width: 6px; height: 6px;
      background: var(--accent);
      border-radius: 50%;
      animation: pulse 1.8s infinite;
    }}
    @keyframes pulse {{
      0%, 100% {{ opacity: 1; }}
      50% {{ opacity: 0.3; }}
    }}

    /* ── Layout ── */
    main {{ padding: 40px 60px; }}

    section {{ margin-bottom: 48px; }}
    section h2 {{
      font-size: 0.68rem;
      font-weight: 600;
      letter-spacing: 3px;
      text-transform: uppercase;
      color: var(--text-dim);
      border-bottom: 1px solid var(--border);
      padding-bottom: 10px;
      margin-bottom: 24px;
    }}

    /* ── Stat cards ── */
    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 16px;
    }}
    .stat-card {{
      background: var(--bg3);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 20px;
      position: relative;
      overflow: hidden;
    }}
    .stat-card::before {{
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 2px;
    }}
    .stat-card.c-accent::before  {{ background: var(--accent); }}
    .stat-card.c-critical::before{{ background: var(--critical); }}
    .stat-card.c-high::before    {{ background: var(--high); }}
    .stat-card.c-medium::before  {{ background: var(--medium); }}
    .stat-card.c-low::before     {{ background: var(--low); }}
    .stat-card.c-dim::before     {{ background: var(--border); }}

    .stat-value {{
      font-family: 'Share Tech Mono', monospace;
      font-size: 2.4rem;
      font-weight: 400;
      line-height: 1;
      margin-bottom: 8px;
    }}
    .stat-card.c-accent   .stat-value {{ color: var(--accent); }}
    .stat-card.c-critical .stat-value {{ color: var(--critical); }}
    .stat-card.c-high     .stat-value {{ color: var(--high); }}
    .stat-card.c-medium   .stat-value {{ color: var(--medium); }}
    .stat-card.c-low      .stat-value {{ color: var(--low); }}
    .stat-card.c-dim      .stat-value {{ color: var(--text-dim); }}

    .stat-label {{
      font-size: 0.7rem;
      font-weight: 600;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      color: var(--text-dim);
    }}

    /* ── Detection breakdown row ── */
    .breakdown-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
    }}
    .breakdown-card {{
      background: var(--bg3);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 18px 20px;
      display: flex;
      align-items: center;
      gap: 16px;
    }}
    .breakdown-icon {{
      width: 36px; height: 36px;
      border-radius: 4px;
      display: flex; align-items: center; justify-content: center;
      font-size: 1.1rem;
      flex-shrink: 0;
    }}
    .breakdown-icon.rule    {{ background: #1a2050; color: var(--rule); }}
    .breakdown-icon.anomaly {{ background: #230a3a; color: var(--anomaly); }}
    .breakdown-icon.both    {{ background: #0d1f17; color: var(--both); }}
    .breakdown-icon.chat    {{ background: #1a1a2e; color: #7c9ef8; }}
    .breakdown-icon.agent   {{ background: #1f1a0d; color: var(--high); }}

    .breakdown-info .val {{
      font-family: 'Share Tech Mono', monospace;
      font-size: 1.5rem;
      line-height: 1;
    }}
    .breakdown-info .lbl {{
      font-size: 0.68rem;
      letter-spacing: 1px;
      text-transform: uppercase;
      color: var(--text-dim);
      margin-top: 4px;
    }}

    /* ── Alert table ── */
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 6px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }}
    thead th {{
      background: var(--bg3);
      padding: 12px 16px;
      text-align: left;
      font-size: 0.65rem;
      font-weight: 600;
      letter-spacing: 2px;
      text-transform: uppercase;
      color: var(--text-dim);
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }}
    tbody tr {{
      border-bottom: 1px solid var(--border);
      transition: background 0.15s;
    }}
    tbody tr:last-child {{ border-bottom: none; }}
    tbody tr:hover {{ background: var(--bg3); }}
    tbody td {{
      padding: 14px 16px;
      vertical-align: top;
      color: var(--text);
    }}

    /* severity badge */
    .badge {{
      display: inline-block;
      padding: 2px 9px;
      border-radius: 2px;
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.68rem;
      font-weight: 600;
      letter-spacing: 1px;
    }}
    .badge.CRITICAL {{ background: #2a0a0a; color: var(--critical); border: 1px solid var(--critical); }}
    .badge.HIGH     {{ background: #251400; color: var(--high);     border: 1px solid var(--high); }}

    /* detection type badge */
    .dtype {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 2px;
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.65rem;
    }}
    .dtype.rule         {{ background: #1a2050; color: var(--rule); }}
    .dtype.anomaly      {{ background: #230a3a; color: var(--anomaly); }}
    .dtype.rule-anomaly {{ background: #0d1f17; color: var(--both); }}

    /* score bar */
    .score-wrap {{ display: flex; align-items: center; gap: 10px; }}
    .score-bar  {{
      flex: 1; height: 4px;
      background: var(--border);
      border-radius: 2px;
      overflow: hidden;
      min-width: 60px;
    }}
    .score-fill {{
      height: 100%;
      border-radius: 2px;
      transition: width 0.3s;
    }}
    .score-val {{
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.78rem;
      white-space: nowrap;
      min-width: 36px;
    }}

    /* prompt text */
    .prompt-text {{
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.72rem;
      color: var(--text-dim);
      max-width: 340px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}

    /* rules pills */
    .rules-list {{ display: flex; flex-wrap: wrap; gap: 4px; }}
    .rule-pill {{
      background: #0f1a30;
      color: var(--rule);
      border: 1px solid #1e2d50;
      padding: 1px 7px;
      border-radius: 2px;
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.62rem;
    }}
    .rule-pill.empty {{ color: var(--text-dim); border-color: var(--border); background: transparent; }}

    /* type tag */
    .type-tag {{
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.68rem;
      padding: 2px 7px;
      border-radius: 2px;
    }}
    .type-tag.chat  {{ background: #1a1a2e; color: var(--rule); }}
    .type-tag.agent {{ background: #1f1a0d; color: var(--high); }}

    /* footer */
    footer {{
      text-align: center;
      padding: 32px 60px 0;
      font-family: 'Share Tech Mono', monospace;
      font-size: 0.7rem;
      color: var(--text-dim);
      border-top: 1px solid var(--border);
    }}
    footer a {{ color: var(--accent); text-decoration: none; }}
  </style>
</head>
<body>

<header>
  <div class="header-left">
    <div class="live-badge"><span class="live-dot"></span> DETECTION REPORT</div>
    <h1><span>Ai</span>SecPulse</h1>
    <p>AI Anomaly Detection Platform &nbsp;·&nbsp; r0ms3c</p>
  </div>
  <div class="header-right">
    <div>Generated &nbsp;{generated_at}</div>
    <div>Source &nbsp;&nbsp;&nbsp;&nbsp;data/sample_events.json</div>
    <div>Engine &nbsp;&nbsp;&nbsp;&nbsp;rules + isolation forest</div>
  </div>
</header>

<main>

  <!-- Summary -->
  <section>
    <h2>Pipeline Summary</h2>
    <div class="stat-grid">
      <div class="stat-card c-accent">
        <div class="stat-value">{total}</div>
        <div class="stat-label">Events Processed</div>
      </div>
      <div class="stat-card c-critical">
        <div class="stat-value">{critical}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card c-high">
        <div class="stat-value">{high}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card c-medium">
        <div class="stat-value">{medium}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card c-low">
        <div class="stat-value">{low}</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-card c-dim">
        <div class="stat-value">{total_alerts}</div>
        <div class="stat-label">Total Alerts</div>
      </div>
    </div>
  </section>

  <!-- Detection Breakdown -->
  <section>
    <h2>Detection Breakdown</h2>
    <div class="breakdown-grid">
      <div class="breakdown-card">
        <div class="breakdown-icon rule">⚡</div>
        <div class="breakdown-info">
          <div class="val">{rule_only}</div>
          <div class="lbl">Rule Only</div>
        </div>
      </div>
      <div class="breakdown-card">
        <div class="breakdown-icon anomaly">◈</div>
        <div class="breakdown-info">
          <div class="val">{anomaly_only}</div>
          <div class="lbl">Anomaly Only</div>
        </div>
      </div>
      <div class="breakdown-card">
        <div class="breakdown-icon both">⬡</div>
        <div class="breakdown-info">
          <div class="val">{both}</div>
          <div class="lbl">Rule + Anomaly</div>
        </div>
      </div>
      <div class="breakdown-card">
        <div class="breakdown-icon chat">💬</div>
        <div class="breakdown-info">
          <div class="val">{chat_alerts}</div>
          <div class="lbl">Chat Alerts</div>
        </div>
      </div>
      <div class="breakdown-card">
        <div class="breakdown-icon agent">🤖</div>
        <div class="breakdown-info">
          <div class="val">{agent_alerts}</div>
          <div class="lbl">Agent Alerts</div>
        </div>
      </div>
    </div>
  </section>

  <!-- Alert Table -->
  <section>
    <h2>Alerts — High &amp; Critical ({total_alerts})</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Type</th>
            <th>User / Agent</th>
            <th>Prompt</th>
            <th>Final Score</th>
            <th>Detection</th>
            <th>Rules Fired</th>
          </tr>
        </thead>
        <tbody>
          {alert_rows}
        </tbody>
      </table>
    </div>
  </section>

</main>

<footer>
  <p>AiSecPulse &nbsp;·&nbsp; <a href="https://github.com/r0ms3c/aisecpulse">github.com/r0ms3c/aisecpulse</a> &nbsp;·&nbsp; MIT License</p>
</footer>

</body>
</html>"""

    def _build_alert_row(self, alert: Alert) -> str:
        """Build a single HTML table row for one alert."""
        # Score bar colour
        if alert.severity == "CRITICAL":
            bar_color = "var(--critical)"
        else:
            bar_color = "var(--high)"

        score_pct = int(alert.final_score * 100)

        # Detection type CSS class
        dtype_class = alert.detection_type.replace(" + ", "-").replace(" ", "-")

        # Rules pills
        if alert.reasons:
            pills = "".join(
                f'<span class="rule-pill">{r}</span>'
                for r in alert.reasons
            )
        else:
            pills = '<span class="rule-pill empty">anomaly only</span>'

        # Truncate prompt
        prompt_display = alert.prompt[:80] + "..." if len(alert.prompt) > 80 else alert.prompt
        prompt_display = prompt_display.replace("<", "&lt;").replace(">", "&gt;")

        return f"""
          <tr>
            <td><span class="badge {alert.severity}">{alert.severity}</span></td>
            <td><span class="type-tag {alert.event_type}">{alert.event_type}</span></td>
            <td style="font-family:'Share Tech Mono',monospace;font-size:0.75rem">{alert.user_id}</td>
            <td><div class="prompt-text" title="{prompt_display}">{prompt_display}</div></td>
            <td>
              <div class="score-wrap">
                <div class="score-bar">
                  <div class="score-fill" style="width:{score_pct}%;background:{bar_color}"></div>
                </div>
                <span class="score-val">{alert.final_score:.2f}</span>
              </div>
            </td>
            <td><span class="dtype {dtype_class}">{alert.detection_type}</span></td>
            <td><div class="rules-list">{pills}</div></td>
          </tr>"""
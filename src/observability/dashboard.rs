use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusHandle;

use crate::server::ServerState;

/// Render the admin dashboard as a self-contained HTML page.
pub fn render(state: &Arc<ServerState>, prometheus: &PrometheusHandle) -> String {
    let connections = state.connection_count();
    let channels = state.channel_count();
    let details = state.channel_details();

    let mut channels_html = String::new();
    if details.is_empty() {
        channels_html.push_str("<tr><td colspan=\"2\">No active channels</td></tr>");
    } else {
        for (name, members) in &details {
            // Truncate channel name for display (may be SHA-256 hash)
            let display_name = if name.len() > 16 {
                format!("{}...", &name[..16])
            } else {
                name.clone()
            };
            channels_html.push_str(&format!(
                "<tr><td><code>{display_name}</code></td><td>{members}</td></tr>"
            ));
        }
    }

    let metrics_text = prometheus.render();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>NVDA Remote Server</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; color: #333; background: #fafafa; }}
  h1 {{ color: #1a1a1a; border-bottom: 2px solid #ddd; padding-bottom: 0.5rem; }}
  .stats {{ display: flex; gap: 2rem; margin: 1.5rem 0; }}
  .stat {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 1.2rem 1.5rem; flex: 1; }}
  .stat .value {{ font-size: 2rem; font-weight: bold; color: #1a73e8; }}
  .stat .label {{ color: #666; font-size: 0.9rem; margin-top: 0.3rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 0.6rem 1rem; border-bottom: 1px solid #eee; }}
  th {{ background: #f5f5f5; font-weight: 600; }}
  details {{ margin-top: 1.5rem; }}
  summary {{ cursor: pointer; font-weight: 600; padding: 0.5rem 0; }}
  pre {{ background: #f5f5f5; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.8rem; }}
  footer {{ margin-top: 2rem; color: #999; font-size: 0.8rem; }}
</style>
</head>
<body>
<h1>NVDA Remote Server</h1>

<div class="stats">
  <div class="stat">
    <div class="value">{connections}</div>
    <div class="label">Active Connections</div>
  </div>
  <div class="stat">
    <div class="value">{channels}</div>
    <div class="label">Active Channels</div>
  </div>
</div>

<h2>Channels</h2>
<table>
  <thead><tr><th>Channel</th><th>Members</th></tr></thead>
  <tbody>{channels_html}</tbody>
</table>

<details>
  <summary>Prometheus Metrics</summary>
  <pre>{metrics_text}</pre>
</details>

<footer>Auto-refreshes every 5 seconds. <a href="/metrics">/metrics</a> | <a href="/stats">/stats</a></footer>
</body>
</html>"#
    )
}

use anyhow::Result;

use crate::session::build_session;
use crate::session::SessionBuilderConfig;

pub async fn handle_doctor() -> Result<()> {
    // Run deterministic diagnostic engine and print structured audit report to console
    let report = goose::doctor::DiagnosticReport::collect_deterministic().await;
    report.print_cli();

    let mut session = build_session(SessionBuilderConfig {
        no_session: true,
        interactive: true,
        ..Default::default()
    })
    .await;

    session.interactive(Some("/doctor".to_string())).await
}

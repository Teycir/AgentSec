//! `agentsec scan` (spec 8.5): ad hoc scan against one target/suite pair.

use std::path::Path;

use agentsec_core::ExitCode;

use crate::pipeline::{run_scan_pipeline, PipelineOptions};
use crate::{load_project_config_or_adhoc_default, load_suite, resolve_target};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    target: String,
    suite: String,
    config: String,
    out: Option<String>,
    format: Option<Vec<String>>,
    fail_on: Option<String>,
    timeout: u64,
) -> anyhow::Result<ExitCode> {
    let config_path = Path::new(&config);
    let project_config = load_project_config_or_adhoc_default(config_path)?;
    let resolved_target = resolve_target(&target, &project_config)?;
    let loaded_suite = load_suite(&suite)?;

    run_scan_pipeline(
        project_config,
        vec![resolved_target],
        vec![loaded_suite],
        PipelineOptions {
            out_dir_opt: out,
            formats_opt: format,
            fail_on_opt: fail_on,
            baseline_opt: None,
            update_baseline: false,
            timeout_override: Some(timeout),
        },
    )
    .await
}

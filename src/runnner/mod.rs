#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_must_use)]

use clarity_repl::clarity::types::QualifiedContractIdentifier;
use clarity_repl::repl::{Session, ExecutionResult};

use std::path::PathBuf;
use std::collections::BTreeMap;

use crate::deployment::types::DeploymentSpecification;

pub mod deno;
mod api_v2;
mod costs;
mod utils;

#[derive(Clone)]
pub struct Cache {
    session: Session,
    session_accounts_only: Session,
    deployment_path: Option<String>,
    deployment: DeploymentSpecification,
    execution_results: BTreeMap<QualifiedContractIdentifier, ExecutionResult>
}

pub fn run_scripts(
    files: Vec<String>,
    include_coverage: bool,
    include_costs_report: bool,
    watch: bool,
    allow_wallets: bool,
    allow_disk_write: bool,
    manifest_path: PathBuf,
    cache: Cache,
) -> Result<u32, (String, u32)> {
    match block_on(deno::do_run_scripts(
        files,
        include_coverage,
        include_costs_report,
        watch,
        allow_wallets,
        allow_disk_write,
        manifest_path,
        cache
    )) {
        Err(e) => Err((format!("{:?}", e), 0)),
        Ok(res) => Ok(res),
    }
}

pub fn block_on<F, R>(future: F) -> R
where
    F: std::future::Future<Output = R>,
{
    let rt = crate::utils::create_basic_runtime();
    rt.block_on(future)
}

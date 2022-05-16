mod clarity_language_backend;
mod utils;
use crate::deployment::{
    generate_default_deployment, initiate_session_from_deployment,
    update_session_with_contracts_analyses,
};
use clarity_language_backend::ClarityLanguageBackend;
use clarity_repl::analysis::ast_dependency_detector::DependencySet;
use clarity_repl::clarity::analysis::ContractAnalysis;
use clarity_repl::clarity::diagnostic::{Diagnostic as ClarityDiagnostic, Level as ClarityLevel};
use clarity_repl::clarity::types::QualifiedContractIdentifier;
use clarity_repl::repl::ast::ContractAST;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::{collections::BTreeMap, path::PathBuf};
use tokio;
use tower_lsp::lsp_types::*;
use tower_lsp::{LspService, Server};

pub fn run_lsp() {
    match block_on(do_run_lsp()) {
        Err(_e) => std::process::exit(1),
        _ => {}
    };
}

pub fn block_on<F, R>(future: F) -> R
where
    F: std::future::Future<Output = R>,
{
    let rt = crate::utils::create_basic_runtime();
    rt.block_on(future)
}

async fn do_run_lsp() -> Result<(), String> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        start_server(rx);
    });

    let (service, messages) = LspService::new(|client| ClarityLanguageBackend::new(client, tx));
    Server::new(stdin, stdout)
        .interleave(messages)
        .serve(service)
        .await;
    Ok(())
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum Symbol {
    PublicFunction,
    ReadonlyFunction,
    PrivateFunction,
    ImportedTrait,
    LocalVariable,
    Constant,
    DataMap,
    DataVar,
    FungibleToken,
    NonFungibleToken,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CompletionMaps {
    pub inter_contract: Vec<CompletionItem>,
    pub intra_contract: Vec<CompletionItem>,
    pub data_fields: Vec<CompletionItem>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContractState {
    intellisense: CompletionMaps,
    errors: Vec<Diagnostic>,
    warnings: Vec<Diagnostic>,
    notes: Vec<Diagnostic>,
    contract_id: QualifiedContractIdentifier,
    analysis: Option<ContractAnalysis>,
}

impl ContractState {
    pub fn new(
        contract_id: QualifiedContractIdentifier,
        ast: ContractAST,
        deps: DependencySet,
        mut diags: Vec<ClarityDiagnostic>,
        analysis: Option<ContractAnalysis>,
    ) -> ContractState {
        let mut errors = vec![];
        let mut warnings = vec![];
        let mut notes = vec![];

        for diag in diags.drain(..) {
            match diag.level {
                ClarityLevel::Error => {
                    errors.push(utils::convert_clarity_diagnotic_to_lsp_diagnostic(&diag));
                }
                ClarityLevel::Warning => {
                    warnings.push(utils::convert_clarity_diagnotic_to_lsp_diagnostic(&diag));
                }
                ClarityLevel::Note => {
                    notes.push(utils::convert_clarity_diagnotic_to_lsp_diagnostic(&diag));
                }
            }
        }

        let intellisense = match analysis {
            Some(ref analysis) => utils::build_intellisense(&analysis),
            None => CompletionMaps::default(),
        };

        ContractState {
            contract_id,
            intellisense,
            errors,
            warnings,
            notes,
            analysis,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct ProtocolState {
    contracts: HashMap<Url, ContractState>,
    native_functions: Vec<CompletionItem>,
}

impl ProtocolState {
    pub fn new() -> ProtocolState {
        ProtocolState {
            contracts: HashMap::new(),
            native_functions: utils::build_default_native_keywords_list(),
        }
    }

    pub fn clear(&mut self) {
        self.contracts.clear();
    }

    pub fn consolidate(
        &mut self,
        paths: &mut BTreeMap<QualifiedContractIdentifier, (Url, PathBuf)>,
        asts: &mut BTreeMap<QualifiedContractIdentifier, ContractAST>,
        deps: &mut BTreeMap<QualifiedContractIdentifier, DependencySet>,
        diags: &mut BTreeMap<QualifiedContractIdentifier, Vec<ClarityDiagnostic>>,
        analyses: &mut BTreeMap<QualifiedContractIdentifier, Option<ContractAnalysis>>,
    ) -> Vec<(Url, ContractState)> {
        let mut changes = vec![];
        // Remove old paths
        // TODO(lgalabru)

        // Add / Replace new paths
        for (contract_id, (url, _)) in paths.iter() {
            let (contract_id, ast) = match asts.remove_entry(&contract_id) {
                Some(ast) => ast,
                None => continue,
            };
            let deps = match deps.remove(&contract_id) {
                Some(deps) => deps,
                None => DependencySet::new(),
            };
            let diags = match diags.remove(&contract_id) {
                Some(diags) => diags,
                None => vec![],
            };
            let analysis = match analyses.remove(&contract_id) {
                Some(analysis) => analysis,
                None => None,
            };

            let contract_state = ContractState::new(contract_id, ast, deps, diags, analysis);
            self.contracts.insert(url.clone(), contract_state.clone());
            changes.push((url.clone(), contract_state));
        }

        changes
    }

    pub fn ingest_contracts_updates(&mut self, contracts_updates: &mut Vec<(Url, ContractState)>) {
        for (url, contract_state) in contracts_updates.drain(..) {
            self.contracts.insert(url, contract_state);
        }
    }

    pub fn get_completion_items_for_contract(&self, contract_uri: &Url) -> Vec<CompletionItem> {
        let mut keywords = self.native_functions.clone();

        let (mut contract_keywords, mut contract_calls) = {
            let contract_keywords = match self.contracts.get(&contract_uri) {
                Some(entry) => entry.intellisense.intra_contract.clone(),
                _ => vec![],
            };
            let mut contract_calls = vec![];
            for (url, contract_state) in self.contracts.iter() {
                if !contract_uri.eq(url) {
                    contract_calls.append(&mut contract_state.intellisense.inter_contract.clone());
                }
            }
            (contract_keywords, contract_calls)
        };

        keywords.append(&mut contract_keywords);
        keywords.append(&mut contract_calls);
        keywords
    }
}

pub enum LspRequest {
    ManifestOpened(PathBuf, Sender<Response>),
    ManifestChanged(PathBuf, Sender<Response>),
    ContractOpened(PathBuf, Sender<Response>),
    ContractChanged(PathBuf, Sender<Response>),
}

#[derive(Default, Debug, PartialEq)]
pub struct Response {
    error: Option<String>,
    contracts_updates: Vec<(Url, ContractState)>,
    state_cleared: bool,
}

impl Response {
    pub fn error(message: &str) -> Response {
        Response {
            error: Some(format!("{}", message)),
            contracts_updates: vec![],
            state_cleared: false,
        }
    }
}

fn start_server(command_rx: Receiver<LspRequest>) {
    let mut initialized = false;
    let mut manifest_path = PathBuf::new();
    let mut manifest_checksum = String::new();
    let mut protocol_state = ProtocolState::new();

    loop {
        let command = match command_rx.recv() {
            Ok(command) => command,
            Err(_e) => {
                break;
            }
        };
        match command {
            LspRequest::ManifestOpened(opened_manifest_path, response_tx) => {
                // The only reason why we're waiting for this kind of events, is building our initial state
                // if the system is initialized, move on.
                if initialized {
                    let _ = response_tx.send(Response::default());
                    continue;
                }

                if opened_manifest_path == manifest_path {
                    let _ = response_tx.send(Response::default());
                    continue;
                } else {
                    manifest_path = opened_manifest_path;
                }

                // With this manifest_path, let's initialize our state.
                match build_state(&manifest_path, &mut protocol_state) {
                    Ok(contracts_updates) => {
                        initialized = true;
                        let _ = response_tx.send(Response {
                            error: None,
                            contracts_updates,
                            state_cleared: true,
                        });
                    }
                    Err(e) => {
                        let _ = response_tx.send(Response::error(&e));
                    }
                };
            }
            LspRequest::ContractOpened(contract_path, response_tx) => {
                // The only reason why we're waiting for this kind of events, is building our initial state
                // if the system is initialized, move on.
                if initialized {
                    let _ = response_tx.send(Response::default());
                    continue;
                }

                let mut parent = contract_path.clone();
                let mut manifest_found = false;

                while parent.pop() {
                    parent.push("Clarinet.toml");
                    if parent.exists() {
                        manifest_found = true;
                        break;
                    }
                    parent.pop();
                }

                if manifest_found {
                    manifest_path = parent;
                }

                // With this manifest_path, let's initialize our state.
                match build_state(&manifest_path, &mut protocol_state) {
                    Ok(contracts_updates) => {
                        initialized = true;
                        let _ = response_tx.send(Response {
                            error: None,
                            contracts_updates,
                            state_cleared: true,
                        });
                    }
                    Err(e) => {
                        let _ = response_tx.send(Response::error(&e));
                    }
                };
            }
            LspRequest::ManifestChanged(file_path, response_tx) => {
                // We will rebuild the entire state, without to try any optimizations for now
                match build_state(&manifest_path, &mut protocol_state) {
                    Ok(contracts_updates) => {
                        let _ = response_tx.send(Response {
                            error: None,
                            contracts_updates,
                            state_cleared: true,
                        });
                    }
                    Err(e) => {
                        let _ = response_tx.send(Response::error(&e));
                    }
                };
            }
            LspRequest::ContractChanged(file_path, response_tx) => {
                // Let's try to be smart, and only trigger a full rebuild if and only if
                // the DependencySet changed.
                match build_state(&manifest_path, &mut protocol_state) {
                    Ok(contracts_updates) => {
                        let _ = response_tx.send(Response {
                            error: None,
                            contracts_updates,
                            state_cleared: true,
                        });
                    }
                    Err(e) => {
                        let _ = response_tx.send(Response::error(&e));
                    }
                };
            }
        }
    }
}

pub fn reset_state(protocol_state: &mut ProtocolState) {
    protocol_state.clear();
}

pub fn build_state(
    manifest_path: &PathBuf,
    protocol_state: &mut ProtocolState,
) -> Result<Vec<(Url, ContractState)>, String> {
    let mut asts = BTreeMap::new();
    let mut deps = BTreeMap::new();
    let mut diags = BTreeMap::new();
    let mut paths = BTreeMap::new();
    let mut analyses = BTreeMap::new();

    // In the LSP use case, trying to load an existing deployment
    // might not be suitable, in an edition context, we should
    // expect contracts to be created, edited, removed.
    // A on-disk deployment could quickly lead to an outdated
    // view of the repo.
    let (deployment, mut artifacts) = generate_default_deployment(&manifest_path, &None)?;
    for (contract_id, (contract_ast, contract_deps, contract_diags)) in artifacts.into_iter() {
        asts.insert(contract_id.clone(), contract_ast);
        deps.insert(contract_id.clone(), contract_deps);
        diags.insert(contract_id, contract_diags);
    }

    let mut session = initiate_session_from_deployment(&manifest_path);
    let results = update_session_with_contracts_analyses(&mut session, &deployment, &asts);
    for (contract_id, result) in results.into_iter() {
        let (url, path) = {
            let (_, relative_path) = deployment.contracts.get(&contract_id).unwrap();
            let relative_path = PathBuf::from_str(relative_path).unwrap();
            let mut path = manifest_path.clone();
            path.pop();
            path.extend(&relative_path);
            let url = Url::from_file_path(&path).unwrap();
            (url, path)
        };
        paths.insert(contract_id.clone(), (url, path));

        let (contract_analysis, mut analysis_diags) = match result {
            Ok((contract_analysis, diags)) => (Some(contract_analysis), diags),
            Err(diags) => (None, diags),
        };
        if let Some(entry) = diags.get_mut(&contract_id) {
            entry.append(&mut analysis_diags);
        }
        analyses.insert(contract_id.clone(), contract_analysis);
    }

    let contracts_updates =
        protocol_state.consolidate(&mut paths, &mut asts, &mut deps, &mut diags, &mut analyses);
    Ok(contracts_updates)
}

#[test]
fn test_opening_contract_should_return_fresh_analysis() {
    use std::sync::mpsc::channel;

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        start_server(rx);
    });

    let mut counter_path = std::env::current_dir().expect("Unable to get current dir");
    counter_path.push("examples");
    counter_path.push("counter");
    counter_path.push("contracts");
    counter_path.push("counter.clar");

    let (response_tx, response_rx) = channel();

    let _ = tx.send(LspRequest::ContractOpened(
        counter_path.clone(),
        response_tx.clone(),
    ));
    let response = response_rx.recv().expect("Unable to get response");

    // we should get 1 contract update
    assert_eq!(response.state_cleared, true);
    assert_eq!(response.contracts_updates.len(), 1);

    let (_url, state) = &response.contracts_updates[0];

    // the counter project should emit 2 warnings, coming from the check-checker
    assert_eq!(state.warnings.len(), 2);

    // re-opening this contract should not trigger a full analysis
    let _ = tx.send(LspRequest::ContractOpened(counter_path, response_tx));
    let response = response_rx.recv().expect("Unable to get response");
    assert_eq!(response, Response::default());
}

#[test]
fn test_opening_manifest_should_return_fresh_analysis() {
    use std::sync::mpsc::channel;

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        start_server(rx);
    });

    let mut manifest_path = std::env::current_dir().expect("Unable to get current dir");
    manifest_path.push("examples");
    manifest_path.push("counter");
    manifest_path.push("Clarinet.toml");

    let (response_tx, response_rx) = channel();
    let _ = tx.send(LspRequest::ManifestOpened(
        manifest_path.clone(),
        response_tx.clone(),
    ));
    let response = response_rx.recv().expect("Unable to get response");

    // we should get 1 contract update
    assert_eq!(response.state_cleared, true);
    assert_eq!(response.contracts_updates.len(), 1);

    let (_url, state) = &response.contracts_updates[0];

    // the counter project should emit 2 warnings, coming from the check-checker
    assert_eq!(state.warnings.len(), 2);

    // re-opening this manifest should not trigger a full analysis
    let _ = tx.send(LspRequest::ManifestOpened(manifest_path, response_tx));
    let response = response_rx.recv().expect("Unable to get response");
    assert_eq!(response, Response::default());
}

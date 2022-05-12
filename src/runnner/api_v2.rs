use deno_core::{OpFn, OpState};
use deno_core::error::AnyError;
use std::borrow::BorrowMut;
use std::path::PathBuf;
use deno_core::serde_json::{self, json, Value};
use crate::deployment::types::DeploymentSpecification;

use super::utils;
use std::collections::{BTreeMap, HashMap};
use clarity_repl::clarity::types;
use clarity_repl::clarity::coverage::{TestCoverageReport};
use clarity_repl::repl::Session;
use super::Cache;

pub enum TestEvent {
    SessionTerminated(SessionArtifacts)
}

pub struct SessionArtifacts {
    pub coverage_reports: Vec<TestCoverageReport>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewSessionArgs {
    name: String,
    load_deployment: bool,
    deployment_path: Option<String>,
}

pub fn new_session(state: &mut OpState, args: Value, _: ()) -> Result<String, AnyError> {
    let args: NewSessionArgs =
        serde_json::from_value(args).expect("Invalid request from JavaScript for \"op_load\".");

    let (session, deployment) = {
        let cache = state.borrow::<HashMap<Option<String>, Cache>>();
        
        let deployment = match args.deployment_path {
            Some(deploynent_path) => {
                let mut entry = cache.get(&Some(deploynent_path));
                if entry.is_none() {
                    let mut default_entry = cache.get(&None);
                    if let Some(default_entry) = default_entry.take() {
                        if default_entry.deployment_path == Some(deploynent_path) {
                            entry = Some(default_entry);
                        }
                    }
                    if entry.is_none() {
                        // Build the cache entry and insert it
                    }    
                }
                entry
            },
            None => {
                let mut default_entry = cache.get(&None);
                if let Some(default_entry) = default_entry.take() {
                    Some(default_entry)
                } else {
                    None
                    // Build the cache entry
                }
            }
        };
    };

    // Update + get a session id
    let session_id = {
        let session_id = match state.try_borrow_mut::<u16>() {
            Some(session_id) => session_id,
            None => panic!(),
        };
        *session_id += 1;
        session_id.clone()
    };

    let accounts = deployment.genesis.unwrap().wallets.clone();
    let contracts = vec![];
    
    for (contract_id, artifacts) in deployment.contracts.iter() {

    }
    
    {
        let sessions = match state.try_borrow_mut::<HashMap<usize, (Session, DeploymentSpecification)>>() {
            Some(sessions) => sessions,
            None => panic!(),
        };
        let session_id = sessions.insert(session_id.into(), (session, deployment));
    }




        // let manifest_path = state.borrow::<PathBuf>();


        // let manifest_path = state.borrow::<PathBuf>();    

        // let deployments: HashMap<PathBuf, DeploymentSpecification> = HashMap::new();
        // js_runtime.op_state().borrow_mut().put(deployments);

        // let sessions: HashMap<usize, Session> = HashMap::new();
        // js_runtime.op_state().borrow_mut().put(sessions);

        // js_runtime
        //     .op_state()
        //     .borrow_mut()
        //     .put::<Sender<api_v2::TestEvent>>(event_tx.clone());


    let (session_id, accounts, contracts) =
        handle_setup_chain_v2(manifest_path, args.name, args.load_deployment)?;

        let serialized_contracts = contracts.iter().map(|(a, s, _)| json!({
      "contract_id": a.contract_identifier.to_string(),
      "contract_interface": a.contract_interface.clone(),
      "dependencies": a.dependencies.clone().into_iter().map(|c| c.to_string()).collect::<Vec<String>>(),
      "source": s
    })).collect::<Vec<_>>();

    let allow_wallets = state.borrow::<bool>();
    let accounts = if *allow_wallets { accounts } else { &vec![] };

    Ok(json!({
        "session_id": session_id,
        "accounts": accounts,
        "contracts": serialized_contracts,
    })
    .to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoadDeploymentArgs {
    session_id: u32,
}

pub fn load_deployment(state: &mut OpState, args: Value, _: ()) -> Result<String, AnyError> {
    let args: LoadDeploymentArgs =
        serde_json::from_value(args).expect("Invalid request from JavaScript for \"op_load\".");
    let (session_id, accounts, contracts) = complete_setup_chain(args.session_id)?;
    let serialized_contracts = contracts.iter().map(|(a, s, _)| json!({
      "contract_id": a.contract_identifier.to_string(),
      "contract_interface": a.contract_interface.clone(),
      "dependencies": a.dependencies.clone().into_iter().map(|c| c.to_string()).collect::<Vec<String>>(),
      "source": s
    })).collect::<Vec<_>>();

    let allow_wallets = state.borrow::<bool>();
    let accounts = if *allow_wallets { accounts } else { vec![] };

    Ok(json!({
        "session_id": session_id,
        "accounts": accounts,
        "contracts": serialized_contracts,
    })
    .to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TerminateSessionArgs {
    session_id: u32,
}

pub fn terminate_session(state: &mut OpState, args: Value, _: ()) -> Result<String, AnyError> {
    let args: TerminateSessionArgs =
        serde_json::from_value(args).expect("Invalid request from JavaScript for \"op_load\".");
    let (session_id, accounts, contracts) = complete_setup_chain(args.session_id)?;
    let serialized_contracts = contracts.iter().map(|(a, s, _)| json!({
      "contract_id": a.contract_identifier.to_string(),
      "contract_interface": a.contract_interface.clone(),
      "dependencies": a.dependencies.clone().into_iter().map(|c| c.to_string()).collect::<Vec<String>>(),
      "source": s
    })).collect::<Vec<_>>();

    let allow_wallets = state.borrow::<bool>();
    let accounts = if *allow_wallets { accounts } else { vec![] };

    Ok(json!({
        "session_id": session_id,
        "accounts": accounts,
        "contracts": serialized_contracts,
    })
    .to_string())
}


#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MineEmptyBlocksArgs {
    session_id: u32,
    count: u32,
}

pub fn mine_empty_blocks(state: &mut OpState, args: Value, _: ()) -> Result<String, AnyError> {
    let args: MineEmptyBlocksArgs =
        serde_json::from_value(args).expect("Invalid request from JavaScript.");
    let block_height = perform_block(args.session_id, |name, session| {
        let block_height = session.advance_chain_tip(args.count);
        Ok(block_height)
    })?;

    Ok(json!({
      "session_id": args.session_id,
      "block_height": block_height,
    })
    .to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CallReadOnlyFnArgs {
    session_id: u32,
    sender: String,
    contract: String,
    method: String,
    args: Vec<String>,
}

pub fn call_read_only_fn(state: &mut OpState, args: Value, _: ()) -> Result<String, AnyError> {
    let args: CallReadOnlyFnArgs =
        serde_json::from_value(args).expect("Invalid request from JavaScript.");
    let (result, events) = perform_block(args.session_id, |name, session| {
        let execution = session
            .invoke_contract_call(
                &args.contract,
                &args.method,
                &args.args,
                &args.sender,
                "readonly-calls".into(),
            )
            .unwrap(); // TODO(lgalabru)
        let result = match execution.result {
            Some(output) => format!("{}", output),
            _ => unreachable!("Value empty"),
        };
        Ok((result, execution.events))
    })?;
    Ok(json!({
      "session_id": args.session_id,
      "result": result,
      "events": events,
    })
    .to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetAssetsMapsArgs {
    session_id: u32,
}

pub fn get_assets_maps(state: &mut OpState, args: Value, _: ()) -> Result<String, AnyError> {
    let args: GetAssetsMapsArgs =
        serde_json::from_value(args).expect("Invalid request from JavaScript.");
    let assets_maps = perform_block(args.session_id, |name, session| {
        let assets_maps = session.get_assets_maps();
        let mut lev1 = BTreeMap::new();
        for (key1, map1) in assets_maps.into_iter() {
            let mut lev2 = BTreeMap::new();
            for (key2, val2) in map1.into_iter() {
                lev2.insert(
                    key2,
                    u64::try_from(val2)
                        .expect("u128 unsupported at the moment, please open an issue."),
                );
            }
            lev1.insert(key1, lev2);
        }
        Ok(lev1)
    })?;
    Ok(json!({
      "session_id": args.session_id,
      "assets": assets_maps,
    })
    .to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MineBlockArgs {
    session_id: u32,
    transactions: Vec<TransactionArgs>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionArgs {
    sender: String,
    contract_call: Option<ContractCallArgs>,
    deploy_contract: Option<DeployContractArgs>,
    transfer_stx: Option<TransferSTXArgs>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContractCallArgs {
    contract: String,
    method: String,
    args: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeployContractArgs {
    name: String,
    code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferSTXArgs {
    amount: u64,
    recipient: String,
}

pub fn mine_block(state: &mut OpState, args: Value, _: ()) -> Result<String, AnyError> {
    let args: MineBlockArgs =
        serde_json::from_value(args).expect("Invalid request from JavaScript.");
    let (block_height, receipts) = perform_block(args.session_id, |name, session| {
        let initial_tx_sender = session.get_tx_sender();
        let mut receipts = vec![];
        for tx in args.transactions.iter() {
            if let Some(ref args) = tx.contract_call {
                let execution = match session.invoke_contract_call(
                    &args.contract,
                    &args.method,
                    &args.args,
                    &tx.sender,
                    name.into(),
                ) {
                    Ok(res) => res,
                    Err(diagnostics) => {
                        if diagnostics.len() > 0 {
                            // TODO(lgalabru): if CLARINET_BACKTRACE=1
                            // Retrieve the AST (penultimate entry), and the expression id (last entry)
                            println!(
                                "Runtime error: {}::{}({}) -> {}",
                                args.contract,
                                args.method,
                                args.args.join(", "),
                                diagnostics.last().unwrap().message
                            );
                        }
                        continue;
                    }
                };
                let result = match execution.result {
                    Some(output) => utils::value_to_string(&output),
                    _ => unreachable!("Value empty"),
                };
                receipts.push((result, execution.events));
            } else {
                session.set_tx_sender(tx.sender.clone());
                if let Some(ref args) = tx.deploy_contract {
                    let execution = session
                        .interpret(
                            args.code.clone(),
                            Some(args.name.clone()),
                            true,
                            false,
                            Some(name.into()),
                        )
                        .unwrap(); // TODO(lgalabru)
                    let result = match execution.result {
                        Some(output) => format!("{}", output),
                        _ => unreachable!("Value empty"),
                    };
                    receipts.push((result, execution.events));
                } else if let Some(ref args) = tx.transfer_stx {
                    let snippet = format!(
                        "(stx-transfer? u{} tx-sender '{})",
                        args.amount, args.recipient
                    );
                    let execution = session
                        .interpret(snippet, None, true, false, Some(name.into()))
                        .unwrap(); // TODO(lgalabru)
                    let result = match execution.result {
                        Some(output) => format!("{}", output),
                        _ => unreachable!("Value empty"),
                    };
                    receipts.push((result, execution.events));
                }
                session.set_tx_sender(initial_tx_sender.clone());
            }
        }
        let block_height = session.advance_chain_tip(1);
        Ok((block_height, receipts))
    })?;

    let payload = json!({
      "session_id": args.session_id,
      "block_height": block_height,
      "receipts":  receipts.iter().map(|r| {
        json!({
          "result": r.0,
          "events": r.1,
        })
      }).collect::<Vec<_>>()
    });

    Ok(payload.to_string())
}

pub fn handle_setup_chain_v2(
    manifest_path: &PathBuf,
    name: String,
    includes_pre_deployment_steps: bool,
) -> Result<(u32, &Vec<WalletSpecification>, Vec<(ContractAnalysis, String, String)>), AnyError> {
    let mut sessions = globals::SESSIONS.lock().unwrap();
    let session_id = sessions.len() as u32;
    let session_templated = {
        let res = globals::SESSION_TEMPLATE.lock().unwrap();
        !res.is_empty()
    };
    let can_use_cache = !includes_pre_deployment_steps && session_templated;
    let should_update_cache = !includes_pre_deployment_steps;

    let deployment = match read_or_default_to_generated_deployment(&manifest_path, &None) {
        Ok(deployment) => deployment,
        Err(message) => {
            println!("{}", message);
            std::process::exit(1);
        }
    };

    let (mut session, contracts) = if !can_use_cache {
        let mut session = initiate_session_from_deployment(manifest_path, &deployment);
        update_session_with_genesis_accounts(&mut session, &deployment);
        if !includes_pre_deployment_steps {
            update_session_with_contracts(&mut session, &deployment);
        }
        if should_update_cache {
            globals::SESSION_TEMPLATE.lock().unwrap().push(session.clone());
        }
        (session, vec![])
    } else {
        let session = SESSION_TEMPLATE.lock().unwrap().last().unwrap().clone();
        let contracts = session.initial_contracts_analysis.clone();
        (session, contracts)
    };

    if !includes_pre_deployment_steps {
        session.advance_chain_tip(1);
    }

    let wallets = &deployment.genesis.as_ref().unwrap().wallets;

    sessions.insert(session_id, (name, session, deployment));

    Ok((session_id, wallets, contracts))
}

pub fn complete_setup_chain(
    session_id: u32,
) -> Result<(u32, Vec<Account>, Vec<(ContractAnalysis, String, String)>), AnyError> {
    let mut sessions = globals::SESSIONS.lock().unwrap();
    match sessions.get_mut(&session_id) {
        Some((_, session, deployment)) => {
            let (_, contracts) = session
                .interpret_initial_contracts()
                .expect("Unable to load contracts");
            session.advance_chain_tip(1);
            let accounts = session.settings.initial_accounts.clone();
            Ok((session_id, accounts, contracts))
        }
        _ => unreachable!(),
    }
}

pub fn perform_block<F, R>(session_id: u32, handler: F) -> Result<R, AnyError>
where
    F: FnOnce(&str, &mut Session) -> Result<R, AnyError>,
{
    let mut sessions = globals::SESSIONS.lock().unwrap();
    match sessions.get_mut(&session_id) {
        None => {
            println!("Error: unable to retrieve session");
            panic!()
        }
        Some((name, ref mut session, deployment)) => handler(name.as_str(), session),
    }
}
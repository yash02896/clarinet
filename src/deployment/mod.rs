mod requirements;
pub mod types;
mod ui;

use self::types::{
    DeploymentSpecification, EmulatedContractPublishSpecification, GenesisSpecification,
    TransactionPlanSpecification, TransactionsBatchSpecification, WalletSpecification,
};
use crate::deployment::types::ContractPublishSpecification;
use crate::deployment::types::TransactionSpecification;

use crate::types::{AccountConfig, ChainConfig, ProjectManifest, StacksNetwork};
use crate::utils::mnemonic;
use crate::utils::stacks::StacksRpc;
use clarity_repl::analysis::ast_dependency_detector::{ASTDependencyDetector, DependencySet};
use clarity_repl::clarity::analysis::ContractAnalysis;
use clarity_repl::clarity::ast::ContractAST;
use clarity_repl::clarity::codec::transaction::{
    StacksTransaction, StacksTransactionSigner, TransactionAnchorMode, TransactionAuth,
    TransactionPayload, TransactionPostConditionMode, TransactionPublicKeyEncoding,
    TransactionSmartContract, TransactionSpendingCondition,
};
use clarity_repl::clarity::codec::StacksMessageCodec;
use clarity_repl::clarity::diagnostic::Diagnostic;
use clarity_repl::clarity::types::{PrincipalData, QualifiedContractIdentifier};
use clarity_repl::clarity::util::{
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use clarity_repl::clarity::ContractName;
use clarity_repl::clarity::{
    codec::{
        transaction::{
            RecoverableSignature, SinglesigHashMode, SinglesigSpendingCondition, TransactionVersion,
        },
        StacksString,
    },
    util::{
        address::AddressHashMode,
        secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey},
        StacksAddress,
    },
};
use clarity_repl::repl::SessionSettings;
use clarity_repl::repl::{ExecutionResult, Session};
use libsecp256k1::{PublicKey, SecretKey};
use serde_yaml;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, Sender};
use tiny_hderive::bip32::ExtendedPrivKey;

#[derive(Deserialize, Debug)]
pub struct Balance {
    pub balance: String,
    pub nonce: u64,
    pub balance_proof: String,
    pub nonce_proof: String,
}

pub enum PublishUpdate {
    ContractUpdate(ContractUpdate),
    Completed,
}

#[derive(Clone, Debug)]
pub struct ContractUpdate {
    pub contract_id: String,
    pub status: ContractStatus,
    pub comment: Option<String>,
}

#[derive(Clone, Debug)]
pub enum ContractStatus {
    Queued,
    Encoded,
    Broadcasted,
    Published,
    Error,
}

pub fn encode_contract_call(
    _contract_name: &ContractName,
    _source: &str,
    _nonce: u64,
    _deployment_fee_rate: u64,
    _network: &StacksNetwork,
) -> Result<(StacksTransaction, StacksAddress), String> {
    Err(format!("unimplemented"))
}

pub fn encode_contract_publish(
    contract_name: &ContractName,
    source: &str,
    account: &AccountConfig,
    nonce: u64,
    deployment_fee_rate: u64,
    network: &StacksNetwork,
) -> Result<StacksTransaction, String> {
    let payload = TransactionSmartContract {
        name: contract_name.clone(),
        code_body: StacksString::from_str(source).unwrap(),
    };

    let bip39_seed = match mnemonic::get_bip39_seed_from_mnemonic(&account.mnemonic, "") {
        Ok(bip39_seed) => bip39_seed,
        Err(_) => panic!(),
    };
    let ext = ExtendedPrivKey::derive(&bip39_seed[..], account.derivation.as_str()).unwrap();
    let secret_key = SecretKey::parse_slice(&ext.secret()).unwrap();
    let public_key = PublicKey::from_secret_key(&secret_key);

    let wrapped_public_key =
        Secp256k1PublicKey::from_slice(&public_key.serialize_compressed()).unwrap();
    let wrapped_secret_key = Secp256k1PrivateKey::from_slice(&ext.secret()).unwrap();

    let anchor_mode = TransactionAnchorMode::OnChainOnly;
    let tx_fee = deployment_fee_rate * source.len() as u64;

    let signer_addr = StacksAddress::from_public_keys(
        match network {
            StacksNetwork::Mainnet => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            _ => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        },
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![wrapped_public_key],
    )
    .unwrap();

    let spending_condition = TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
        signer: signer_addr.bytes.clone(),
        nonce: nonce,
        tx_fee: tx_fee,
        hash_mode: SinglesigHashMode::P2PKH,
        key_encoding: TransactionPublicKeyEncoding::Compressed,
        signature: RecoverableSignature::empty(),
    });

    let auth = TransactionAuth::Standard(spending_condition);
    let unsigned_tx = StacksTransaction {
        version: match network {
            StacksNetwork::Mainnet => TransactionVersion::Mainnet,
            _ => TransactionVersion::Testnet,
        },
        chain_id: match network {
            StacksNetwork::Mainnet => 0x00000001,
            _ => 0x80000000,
        },
        auth: auth,
        anchor_mode: anchor_mode,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::SmartContract(payload),
    };

    let mut unsigned_tx_bytes = vec![];
    unsigned_tx
        .consensus_serialize(&mut unsigned_tx_bytes)
        .expect("FATAL: invalid transaction");

    let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
    tx_signer.sign_origin(&wrapped_secret_key).unwrap();
    let signed_tx = tx_signer.get_tx().unwrap();

    Ok(signed_tx)
}

pub fn setup_session_with_deployment(
    manifest_path: &PathBuf,
    deployment: &DeploymentSpecification,
    contracts_asts: &Option<BTreeMap<QualifiedContractIdentifier, ContractAST>>,
) -> (
    Session,
    BTreeMap<QualifiedContractIdentifier, Result<ExecutionResult, Vec<Diagnostic>>>,
) {
    let mut session = initiate_session_from_deployment(&manifest_path);
    update_session_with_genesis_accounts(&mut session, deployment);
    let results =
        update_session_with_contracts_executions(&mut session, deployment, contracts_asts);
    (session, results)
}

pub fn initiate_session_from_deployment(manifest_path: &PathBuf) -> Session {
    let mut manifest = ProjectManifest::from_path(manifest_path);
    let mut settings = SessionSettings::default();
    settings
        .include_boot_contracts
        .append(&mut manifest.project.boot_contracts);
    settings.repl_settings = manifest.repl_settings.clone();
    settings.disk_cache_enabled = true;
    let session = Session::new(settings);
    session
}

pub fn update_session_with_genesis_accounts(
    session: &mut Session,
    deployment: &DeploymentSpecification,
) {
    if let Some(ref spec) = deployment.genesis {
        for wallet in spec.wallets.iter() {
            let _ = session.interpreter.mint_stx_balance(
                wallet.address.clone().into(),
                wallet.balance.try_into().unwrap(),
            );
            if wallet.name == "deployer" {
                session.set_tx_sender(wallet.address.to_address());
            }
        }
        session.load_boot_contracts();
    }
}

pub fn update_session_with_contracts_executions(
    session: &mut Session,
    deployment: &DeploymentSpecification,
    _contracts_asts: &Option<BTreeMap<QualifiedContractIdentifier, ContractAST>>,
) -> BTreeMap<QualifiedContractIdentifier, Result<ExecutionResult, Vec<Diagnostic>>> {
    let mut results = BTreeMap::new();
    for batch in deployment.plan.batches.iter() {
        for transaction in batch.transactions.iter() {
            match transaction {
                TransactionSpecification::ContractCall(_)
                | TransactionSpecification::ContractPublish(_) => {}
                TransactionSpecification::EmulatedContractPublish(tx) => {
                    let default_tx_sender = session.get_tx_sender();
                    session.set_tx_sender(tx.emulated_sender.to_string());

                    let contract_id = QualifiedContractIdentifier::new(
                        tx.emulated_sender.clone(),
                        tx.contract.clone(),
                    );

                    let result = session.interpret(
                        tx.source.clone(),
                        Some(tx.contract.to_string()),
                        None,
                        false,
                        None,
                    );

                    results.insert(contract_id, result);
                    session.set_tx_sender(default_tx_sender);
                }
                TransactionSpecification::EmulatedContractCall(tx) => {
                    let _ = session.invoke_contract_call(
                        &tx.contract_id.to_string(),
                        &tx.method.to_string(),
                        &tx.parameters,
                        &tx.emulated_sender.to_string(),
                        "deployment".to_string(),
                    );
                }
            }
        }
        session.advance_chain_tip(1);
    }
    results
}

pub fn update_session_with_contracts_analyses(
    session: &mut Session,
    deployment: &DeploymentSpecification,
    contracts_asts: &BTreeMap<QualifiedContractIdentifier, ContractAST>,
) -> BTreeMap<
    QualifiedContractIdentifier,
    Result<(ContractAnalysis, Vec<Diagnostic>), Vec<Diagnostic>>,
> {
    let mut results = BTreeMap::new();
    for batch in deployment.plan.batches.iter() {
        for transaction in batch.transactions.iter() {
            match transaction {
                TransactionSpecification::EmulatedContractCall(_)
                | TransactionSpecification::ContractCall(_)
                | TransactionSpecification::ContractPublish(_) => {}
                TransactionSpecification::EmulatedContractPublish(tx) => {
                    let mut diagnostics = vec![];

                    let default_tx_sender = session.get_tx_sender();
                    session.set_tx_sender(tx.emulated_sender.to_string());

                    let contract_id = QualifiedContractIdentifier::new(
                        tx.emulated_sender.clone(),
                        tx.contract.clone(),
                    );

                    if let Some(ast) = contracts_asts.get(&contract_id) {
                        let (annotations, mut annotation_diagnostics) =
                            session.interpreter.collect_annotations(&ast, &tx.source);
                        diagnostics.append(&mut annotation_diagnostics);
                        let mut ast = ast.clone();

                        let (analysis, mut analysis_diagnostics) = match session
                            .interpreter
                            .run_analysis(contract_id.clone(), &mut ast, &annotations)
                        {
                            Ok((analysis, diagnostics)) => (analysis, diagnostics),
                            Err((_, Some(diagnostic), _)) => {
                                diagnostics.push(diagnostic);
                                results.insert(contract_id, Err(diagnostics));
                                continue;
                            }
                            Err(_) => {
                                continue;
                            }
                        };
                        diagnostics.append(&mut analysis_diagnostics);
                        session.interpreter.save_contract(
                            contract_id.clone(),
                            &mut ast,
                            tx.source.clone(),
                            analysis.clone(),
                            false,
                        );
                        results.insert(contract_id, Ok((analysis, diagnostics)));
                    }

                    session.set_tx_sender(default_tx_sender);
                }
            }
        }
    }
    results
}

pub fn get_absolute_deployment_path(
    manifest_path: &PathBuf,
    relative_deployment_path: &str,
) -> PathBuf {
    let mut base_path = manifest_path.clone();
    base_path.pop();
    let path = match PathBuf::from_str(relative_deployment_path) {
        Ok(path) => path,
        Err(_e) => {
            println!("unable to read path {}", relative_deployment_path);
            std::process::exit(1);
        }
    };
    base_path.join(path)
}

pub fn get_default_deployment_path(
    manifest_path: &PathBuf,
    network: &Option<StacksNetwork>,
) -> PathBuf {
    let mut deployment_path = manifest_path.clone();
    deployment_path.pop();
    deployment_path.push("deployments");
    let file_path = match network {
        None => "Test.yaml",
        Some(StacksNetwork::Devnet) => "Devnet.yaml",
        Some(StacksNetwork::Testnet) => "Testnet.yaml",
        Some(StacksNetwork::Mainnet) => "Mainnet.yaml",
    };
    deployment_path.push(file_path);
    deployment_path
}

pub fn read_or_default_to_generated_deployment(
    manifest_path: &PathBuf,
    network: &Option<StacksNetwork>,
) -> Result<DeploymentSpecification, String> {
    let default_deployment_file_path = get_default_deployment_path(manifest_path, network);
    let deployment = if default_deployment_file_path.exists() {
        load_deployment(manifest_path, &default_deployment_file_path)?
    } else {
        let (deployement, _) = generate_default_deployment(manifest_path, network)?;
        deployement
    };
    Ok(deployment)
}

pub enum DeploymentEvent {
    Interrupted(String),
}

pub enum DeploymentCommand {
    Start,
}

pub enum TransactionStatus {
    Encoded,
    Broadcasted,
    OnChain,
}

pub fn apply_on_chain_deployment(
    manifest_path: &PathBuf,
    deployment: &DeploymentSpecification,
    deployment_event_tx: Sender<DeploymentEvent>,
    deployment_command_rx: Receiver<DeploymentCommand>,
) {
    let chain_config = ChainConfig::from_manifest_path(&manifest_path, &deployment.network);
    let delay_between_checks: u64 = 10;
    // Load deployers, deployment_fee_rate
    // Check fee, balances and deployers

    let mut batches = VecDeque::new();
    let network = deployment
        .network
        .clone()
        .expect("unable to retrieve network");
    let deployment_fee_rate = chain_config.network.deployment_fee_rate;
    let mut accounts_cached_nonces: BTreeMap<String, u64> = BTreeMap::new();
    let mut accounts_lookup: BTreeMap<String, &AccountConfig> = BTreeMap::new();

    if network == StacksNetwork::Devnet {
        for (_, account) in chain_config.accounts.iter() {
            accounts_cached_nonces.insert(account.address.clone(), 0);
        }
    }

    for (_, account) in chain_config.accounts.iter() {
        accounts_lookup.insert(account.address.clone(), account);
    }

    let node_url = chain_config.network.node_rpc_address.clone().unwrap();
    let stacks_rpc = StacksRpc::new(&node_url);

    // Phase 1: we traverse the deployment plan and encode all the transactions,
    // keeping the order.
    for batch_spec in deployment.plan.batches.iter() {
        let mut batch = Vec::new();
        for transaction in batch_spec.transactions.iter() {
            match transaction {
                TransactionSpecification::ContractCall(_tx) => {
                    // Retrieve nonce for issuer
                    unimplemented!();
                }
                TransactionSpecification::ContractPublish(tx) => {
                    // Retrieve nonce for issuer
                    let issuer_address = tx.expected_sender.to_address();
                    let nonce = match accounts_cached_nonces.get(&issuer_address) {
                        Some(cached_nonce) => cached_nonce.clone(),
                        None => stacks_rpc
                            .get_nonce(&issuer_address)
                            .expect("Unable to retrieve account"),
                    };
                    let account = accounts_lookup.get(&issuer_address).unwrap();

                    let stacks_transaction = match encode_contract_publish(
                        &tx.contract,
                        &tx.source,
                        *account,
                        nonce,
                        deployment_fee_rate,
                        &network,
                    ) {
                        Ok(res) => res,
                        Err(e) => {
                            let _ = deployment_event_tx.send(DeploymentEvent::Interrupted(e));
                            return;
                        }
                    };

                    accounts_cached_nonces.insert(issuer_address.clone(), nonce + 1);
                    batch.push((
                        tx.expected_sender.clone(),
                        tx.contract.clone(),
                        stacks_transaction,
                        TransactionStatus::Encoded,
                    ));
                }
                TransactionSpecification::EmulatedContractPublish(_)
                | TransactionSpecification::EmulatedContractCall(_) => {}
            }
        }

        batches.push_back(batch);
    }

    let _cmd = match deployment_command_rx.recv() {
        Ok(cmd) => cmd,
        Err(_) => {
            let _ = deployment_event_tx.send(DeploymentEvent::Interrupted(
                "deployment aborted - broken channel".to_string(),
            ));
            return;
        }
    };

    // Phase 2: we submit all the transactions previously encoded,
    // and wait for their inclusion in a block before moving to the next batch.
    let mut current_block_height = 0;
    for batch in batches.into_iter() {
        let mut ongoing_batch = BTreeMap::new();
        for (sender, contract_name, tx, _status) in batch.into_iter() {
            let _ = match stacks_rpc.post_transaction(tx) {
                Ok(res) => {
                    ongoing_batch.insert(
                        res.txid,
                        (sender, contract_name, TransactionStatus::Broadcasted),
                    );
                }
                Err(_e) => return,
            };
        }

        loop {
            let new_block_height = match stacks_rpc.get_info() {
                Ok(info) => info.burn_block_height,
                _ => {
                    std::thread::sleep(std::time::Duration::from_secs(delay_between_checks.into()));
                    continue;
                }
            };

            // If no block has been mined since `delay_between_checks`,
            // avoid flooding the stacks-node with status update requests.
            if new_block_height <= current_block_height {
                std::thread::sleep(std::time::Duration::from_secs(delay_between_checks.into()));
                continue;
            }

            current_block_height = new_block_height;

            let mut keep_looping = false;

            for (_txid, (deployer, contract_name, status)) in ongoing_batch.iter_mut() {
                match *status {
                    TransactionStatus::Broadcasted => {
                        let res =
                            stacks_rpc.get_contract_source(&deployer.to_address(), &contract_name);
                        if let Ok(_contract) = res {
                            *status = TransactionStatus::OnChain;
                        } else {
                            keep_looping = true;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if !keep_looping {
                break;
            }
        }
    }

    // if let Some(devnet_event_tx) = devnet_event_tx {
    //     let _ = devnet_event_tx.send(DevnetEvent::ProtocolDeployed);
    // } else {
    //     println!(
    //         "{} Contracts successfully deployed on {:?}",
    //         green!("✔"),
    //         network
    //     );
    // }
}

pub fn check_deployments(manifest_path: &PathBuf) -> Result<(), String> {
    let mut base_path = manifest_path.clone();
    base_path.pop();
    let files = get_deployments_files(manifest_path)?;
    for (path, relative_path) in files.into_iter() {
        let _spec = match DeploymentSpecification::from_config_file(&path, &base_path) {
            Ok(spec) => spec,
            Err(msg) => {
                println!("{} {} syntax incorrect\n{}", red!("x"), relative_path, msg);
                continue;
            }
        };
        println!("{} {} succesfully checked", green!("✔"), relative_path);
    }
    Ok(())
}

pub fn load_deployment_if_exists(
    manifest_path: &PathBuf,
    network: &Option<StacksNetwork>,
) -> Option<Result<DeploymentSpecification, String>> {
    let default_deployment_path = get_default_deployment_path(manifest_path, network);
    if !default_deployment_path.exists() {
        return None;
    }
    Some(load_deployment(manifest_path, &default_deployment_path))
}

pub fn load_deployment(
    manifest_path: &PathBuf,
    deployment_path: &PathBuf,
) -> Result<DeploymentSpecification, String> {
    let mut base_path = manifest_path.clone();
    base_path.pop();
    let spec = match DeploymentSpecification::from_config_file(&deployment_path, &base_path) {
        Ok(spec) => spec,
        Err(msg) => {
            return Err(format!(
                "{} {} syntax incorrect\n{}",
                red!("x"),
                deployment_path.display(),
                msg
            ));
        }
    };
    Ok(spec)
}

fn get_deployments_files(manifest_path: &PathBuf) -> Result<Vec<(PathBuf, String)>, String> {
    let mut hooks_home = manifest_path.clone();
    hooks_home.pop();
    let suffix_len = hooks_home.to_str().unwrap().len() + 1;
    hooks_home.push("deployments");
    let paths = match fs::read_dir(&hooks_home) {
        Ok(paths) => paths,
        Err(_) => return Ok(vec![]),
    };
    let mut hook_paths = vec![];
    for path in paths {
        let file = path.unwrap().path();
        let is_extension_valid = file
            .extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| Some(ext == "yml" || ext == "yaml"));

        if let Some(true) = is_extension_valid {
            let relative_path = file.clone();
            let (_, relative_path) = relative_path.to_str().unwrap().split_at(suffix_len);
            hook_paths.push((file, relative_path.to_string()));
        }
    }

    Ok(hook_paths)
}

pub fn write_deployment(
    deployment: &DeploymentSpecification,
    target_path: &PathBuf,
    prompt_override: bool,
) -> Result<(), String> {
    if target_path.exists() && prompt_override {
        println!(
            "Deployment {} already exists.\nOverwrite [Y/n]?",
            target_path.display()
        );
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer).unwrap();
        if buffer.starts_with("n") {
            return Err(format!("deployment update aborted"));
        }
    } else {
        let mut base_dir = target_path.clone();
        base_dir.pop();
        if !base_dir.exists() {
            let _ = std::fs::create_dir(base_dir);
        }
    }

    let file = deployment.to_specification_file();

    let content = match serde_yaml::to_string(&file) {
        Ok(res) => res,
        Err(err) => return Err(format!("unable to serialize deployment {}", err)),
    };

    let mut file = match File::create(&target_path) {
        Ok(file) => file,
        Err(e) => {
            return Err(format!(
                "unable to create file {}: {}",
                target_path.display(),
                e
            ));
        }
    };
    match file.write_all(content.as_bytes()) {
        Ok(_) => (),
        Err(e) => {
            return Err(format!(
                "unable to write file {}: {}",
                target_path.display(),
                e
            ));
        }
    };
    Ok(())
}

pub fn generate_default_deployment(
    manifest_path: &PathBuf,
    network: &Option<StacksNetwork>,
) -> Result<
    (
        DeploymentSpecification,
        BTreeMap<QualifiedContractIdentifier, (ContractAST, DependencySet, Vec<Diagnostic>)>,
    ),
    String,
> {
    let mut artifacts = BTreeMap::new();

    let mut project_config = ProjectManifest::from_path(&manifest_path);
    let chain_config = ChainConfig::from_manifest_path(&manifest_path, &network);

    let default_deployer = match chain_config.accounts.get("deployer") {
        Some(deployer) => deployer,
        None => {
            return Err(format!(
                "{} unable to retrieve default deployer account",
                red!("x")
            ));
        }
    };

    let mut transactions = vec![];
    let mut contracts_map = BTreeMap::new();
    let mut requirements_asts = BTreeMap::new();
    let mut requirements_deps = HashMap::new();

    let mut settings = SessionSettings::default();
    let parser_version = project_config.repl_settings.parser_version;
    settings.repl_settings = project_config.repl_settings.clone();
    let session = Session::new(settings.clone());
    let mut boot_contracts_asts = session.get_boot_contracts_asts();
    requirements_asts.append(&mut boot_contracts_asts);

    // Only handle requirements in test environments
    if project_config.project.requirements.is_some() {
        let default_cache_path = match PathBuf::from_str(&project_config.project.cache_dir) {
            Ok(path) => path,
            Err(_) => return Err("unable to get default cache path".to_string()),
        };
        let mut contracts = HashMap::new();

        let requirements = project_config.project.requirements.take().unwrap();

        // Load all the requirements
        // Some requirements are explicitly listed, some are discovered as we compute the ASTs.
        let mut queue = VecDeque::new();

        for requirement in requirements.into_iter() {
            let contract_id = match QualifiedContractIdentifier::parse(&requirement.contract_id) {
                Ok(contract_id) => contract_id,
                Err(_e) => {
                    return Err(format!(
                        "malformatted contract_id: {}",
                        requirement.contract_id
                    ))
                }
            };
            queue.push_front(contract_id);
        }

        while let Some(contract_id) = queue.pop_front() {
            // Extract principal from contract_id
            if requirements_deps.contains_key(&contract_id) {
                continue;
            }

            // Did we already got the source in a prior cycle?
            let ast = match requirements_asts.remove(&contract_id) {
                Some(ast) => ast,
                None => {
                    // Download the code
                    let (source, path) = requirements::retrieve_contract(
                        &contract_id,
                        true,
                        Some(default_cache_path.clone()),
                    )?;

                    // Build the struct representing the requirement in the deployment
                    let data = EmulatedContractPublishSpecification {
                        contract: contract_id.name.clone(),
                        emulated_sender: contract_id.issuer.clone(),
                        source: source.clone(),
                        relative_path: format!("{}", path.display()),
                    };
                    contracts.insert(contract_id.clone(), data);

                    // Compute the AST
                    let (ast, _, _) = session.interpreter.build_ast(
                        contract_id.clone(),
                        source.to_string(),
                        parser_version,
                    );
                    ast
                }
            };

            // Detect the eventual dependencies for this AST
            let mut contract_ast = HashMap::new();
            contract_ast.insert(contract_id.clone(), ast);
            let dependencies =
                ASTDependencyDetector::detect_dependencies(&contract_ast, &requirements_asts);
            let ast = contract_ast
                .remove(&contract_id)
                .expect("unable to retrieve ast");

            // Extract the known / unknown dependencies
            match dependencies {
                Ok(inferable_dependencies) => {
                    // Looping could be confusing - in this case, we submitted a HashMap with one contract, so we have at most one
                    // result in the `inferable_dependencies` map. We will just extract and keep the associated data (source, ast, deps).
                    for (contract_id, dependencies) in inferable_dependencies.into_iter() {
                        for dependency in dependencies.iter() {
                            queue.push_back(dependency.contract_id.clone());
                        }
                        requirements_deps.insert(contract_id.clone(), dependencies);
                        requirements_asts.insert(contract_id.clone(), ast);
                        break;
                    }
                }
                Err((inferable_dependencies, non_inferable_dependencies)) => {
                    // In the case of unknown dependencies, we were unable to construct an exhaustive list of dependencies.
                    // As such, we will enqueue re-enqueue the present (front) and push all the unknown contract_ids in front of it,
                    // and we will keep the source in memory to avoid useless disk access.
                    for (_, dependencies) in inferable_dependencies.iter() {
                        for dependency in dependencies.iter() {
                            queue.push_back(dependency.contract_id.clone());
                        }
                    }
                    requirements_asts.insert(contract_id.clone(), ast);
                    queue.push_front(contract_id);

                    for non_inferable_contract_id in non_inferable_dependencies.into_iter() {
                        queue.push_front(non_inferable_contract_id);
                    }
                }
            };
        }

        // Avoid listing requirements as deployment transactions to the deployment specification on Devnet / Testnet / Mainnet
        if network.is_none() {
            let ordered_contracts_ids =
                match ASTDependencyDetector::order_contracts(&requirements_deps) {
                    Ok(ordered_contracts) => ordered_contracts,
                    Err(e) => return Err(format!("unable to order contracts {}", e)),
                };

            for contract_id in ordered_contracts_ids.iter() {
                let data = contracts
                    .remove(contract_id)
                    .expect("unable to retrieve contract");
                let tx = TransactionSpecification::EmulatedContractPublish(data);
                transactions.push(tx);
            }
        }
    }

    let mut contracts = HashMap::new();

    for (name, config) in project_config.contracts.iter() {
        let contract = match ContractName::try_from(name.to_string()) {
            Ok(res) => res,
            Err(_) => return Err(format!("unable to use {} as a valid contract name", name)),
        };

        let deployer = match config.deployer {
            Some(ref deployer) => {
                let deployer = match chain_config.accounts.get(deployer) {
                    Some(deployer) => deployer,
                    None => {
                        return Err(format!(
                            "{} unable to retrieve account '{}'",
                            red!("x"),
                            deployer
                        ));
                    }
                };
                deployer
            }
            None => default_deployer,
        };

        let emulated_sender = match PrincipalData::parse_standard_principal(&deployer.address) {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to turn emulated_sender {} as a valid Stacks address",
                    deployer.address
                ))
            }
        };

        let mut path = manifest_path.clone();
        path.pop();
        path.push(&config.path);
        let source = match std::fs::read_to_string(&path) {
            Ok(code) => code,
            Err(err) => {
                return Err(format!(
                    "unable to read contract at path {:?}: {}",
                    config.path, err
                ))
            }
        };

        let contract = EmulatedContractPublishSpecification {
            contract,
            emulated_sender,
            source,
            relative_path: config.path.clone(),
        };

        let contract_id = QualifiedContractIdentifier::new(
            contract.emulated_sender.clone(),
            contract.contract.clone(),
        );

        contracts.insert(contract_id, contract);
    }

    let session = Session::new(settings);

    let mut contract_asts = HashMap::new();
    let mut contract_diags = HashMap::new();

    for (contract_id, contract) in contracts.iter() {
        let (ast, diags, _) = session.interpreter.build_ast(
            contract_id.clone(),
            contract.source.clone(),
            parser_version,
        );
        contract_asts.insert(contract_id.clone(), ast);
        contract_diags.insert(contract_id.clone(), diags);
    }

    let dependencies =
        ASTDependencyDetector::detect_dependencies(&contract_asts, &requirements_asts);

    let mut dependencies = match dependencies {
        Ok(dependencies) => dependencies,
        Err(_) => {
            return Err(format!("unable to detect dependencies"));
        }
    };

    dependencies.extend(requirements_deps);

    let ordered_contracts_ids = match ASTDependencyDetector::order_contracts(&dependencies) {
        Ok(ordered_contracts_ids) => ordered_contracts_ids
            .into_iter()
            .map(|c| c.clone())
            .collect::<Vec<_>>(),
        Err(e) => return Err(format!("unable to order contracts {}", e)),
    };

    for contract_id in ordered_contracts_ids.into_iter() {
        if requirements_asts.contains_key(&contract_id) {
            continue;
        }
        let data = contracts
            .remove(&contract_id)
            .expect("unable to retrieve contract");
        contracts_map.insert(
            contract_id.clone(),
            (data.source.clone(), data.relative_path.clone()),
        );
        let tx = if network.is_none() {
            TransactionSpecification::EmulatedContractPublish(data)
        } else {
            TransactionSpecification::ContractPublish(ContractPublishSpecification {
                contract: data.contract.clone(),
                expected_sender: data.emulated_sender.clone(),
                relative_path: data.relative_path.clone(),
                source: data.source.clone(),
            })
        };

        transactions.push(tx);

        let contract_id = contract_id.clone();
        let dep = dependencies
            .remove(&contract_id)
            .expect("unable to retrieve dependency set");
        let ast = contract_asts
            .remove(&contract_id)
            .expect("unable to retrieve ast");
        let diags = contract_diags.remove(&contract_id).unwrap_or_default();

        artifacts.insert(contract_id, (ast, dep, diags));
    }

    let _tx_chain_limit = 25;

    let mut batches = vec![];
    for (id, transactions) in transactions.chunks(25).enumerate() {
        batches.push(TransactionsBatchSpecification {
            id: id,
            transactions: transactions.to_vec(),
        })
    }

    let mut wallets = vec![];
    for (name, account) in chain_config.accounts.into_iter() {
        let address = match PrincipalData::parse_standard_principal(&account.address) {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to parse wallet {} in a valid Stacks address",
                    account.address
                ))
            }
        };

        wallets.push(WalletSpecification {
            name,
            address,
            balance: account.balance.into(),
        });
    }

    let name = match network {
        None => format!("Test deployment, used as a default for `clarinet console`, `clarinet test` and `clarinet check`"),
        Some(network) => format!("{:?} deployment", network)
    };

    let deployment = DeploymentSpecification {
        id: 0,
        name,
        network: network.clone(),
        start_block: 0,
        genesis: if network.is_none() {
            Some(GenesisSpecification {
                wallets,
                contracts: project_config.project.boot_contracts.clone(),
            })
        } else {
            None
        },
        plan: TransactionPlanSpecification { batches },
        contracts: contracts_map,
    };

    Ok((deployment, artifacts))
}

pub fn display_deployment(_deployment: &DeploymentSpecification) {}

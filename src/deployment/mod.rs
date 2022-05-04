mod ui;
mod types;

use clarity_repl::clarity::types::{StandardPrincipalData, PrincipalData, QualifiedContractIdentifier};
use clarity_repl::clarity::{ClarityName, ContractName};
use self::types::{DeploymentSpecification, TransactionPlanSpecificationFile, ContractCallSpecificationFile, EmulatedContractPublishSpecification, TransactionsBatchSpecification, TransactionPlanSpecification, GenesisSpecification, WalletSpecification};
use crate::deployment::types::{DeploymentSpecificationFile, TransactionsBatchSpecificationFile, TransactionSpecificationFile, TransactionSpecification};
use crate::integrate::DevnetEvent;
use crate::poke::{load_session, load_session_settings};
use crate::types::{ChainsCoordinatorCommand, StacksNetwork, ProjectManifest, ChainConfig};
use crate::utils::mnemonic;
use crate::utils::stacks::StacksRpc;
use clarity_repl::clarity::codec::transaction::{
    StacksTransaction, StacksTransactionSigner, TransactionAnchorMode, TransactionAuth,
    TransactionPayload, TransactionPostConditionMode, TransactionPublicKeyEncoding,
    TransactionSmartContract, TransactionSpendingCondition,
};
use clarity_repl::clarity::codec::StacksMessageCodec;
use clarity_repl::clarity::util::{
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
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
use clarity_repl::repl::Session;
use clarity_repl::repl::settings::{Account, InitialContract};
use libsecp256k1::{PublicKey, SecretKey};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::fs::{self, File};
use std::io::Write;
use tiny_hderive::bip32::ExtendedPrivKey;
use serde_yaml;

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

pub fn endode_contract(
    contract: &InitialContract,
    account: &Account,
    nonce: u64,
    deployment_fee_rate: u64,
    network: &StacksNetwork,
) -> Result<(StacksTransaction, StacksAddress), String> {
    let contract_name = contract.name.clone().unwrap();

    let payload = TransactionSmartContract {
        name: contract_name.as_str().into(),
        code_body: StacksString::from_string(&contract.code).unwrap(),
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
    let tx_fee = deployment_fee_rate * contract.code.len() as u64;

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

    Ok((signed_tx, signer_addr))
}

#[allow(dead_code)]
pub fn publish_contract(
    contract: &InitialContract,
    deployers_lookup: &HashMap<String, Account>,
    deployers_nonces: &mut HashMap<String, u64>,
    node_url: &str,
    deployment_fee_rate: u64,
    network: &StacksNetwork,
) -> Result<(String, u64, String, String), String> {
    let contract_name = contract.name.clone().unwrap();

    let stacks_rpc = StacksRpc::new(&node_url);

    let deployer = match deployers_lookup.get(&contract_name) {
        Some(deployer) => deployer,
        None => deployers_lookup.get("*").unwrap(),
    };

    let nonce = match deployers_nonces.get(&deployer.name) {
        Some(nonce) => *nonce,
        None => {
            let nonce = stacks_rpc
                .get_nonce(&deployer.address)
                .expect("Unable to retrieve account");
            deployers_nonces.insert(deployer.name.clone(), nonce);
            nonce
        }
    };

    let (signed_tx, signer_addr) =
        endode_contract(contract, deployer, nonce, deployment_fee_rate, network)?;
    let txid = match stacks_rpc.post_transaction(signed_tx) {
        Ok(res) => res.txid,
        Err(e) => return Err(format!("{:?}", e)),
    };
    deployers_nonces.insert(deployer.name.clone(), nonce + 1);
    Ok((txid, nonce, signer_addr.to_string(), contract_name))
}

/// publish_all_contracts publish all the contracts referenced by the manifest passed.
/// this method is being used by developers
pub fn publish_all_contracts(
    manifest_path: &PathBuf,
    network: &StacksNetwork,
    analysis_enabled: bool,
    delay_between_checks: u32,
    devnet_event_tx: Option<&Sender<DevnetEvent>>,
    chains_coordinator_commands_tx: Option<Sender<ChainsCoordinatorCommand>>,
) -> Result<(Vec<String>, ProjectManifest), Vec<String>> {
    let (settings, chain, project_manifest) = if analysis_enabled {
        let start_repl = false;
        let (session, chain, project_manifest, output) =
            match load_session(manifest_path, start_repl, &network) {
                Ok((session, chain, project_manifest, output)) => {
                    (session, chain, project_manifest, output)
                }
                Err((_, e)) => return Err(vec![e]),
            };

        if let Some(message) = output {
            println!("{}", message);
            println!("{}", yellow!("Would you like to continue [Y/n]:"));
            let mut buffer = String::new();
            std::io::stdin().read_line(&mut buffer).unwrap();
            if buffer == "n\n" {
                println!("{}", red!("Contracts deployment aborted"));
                std::process::exit(1);
            }
        }
        (session.settings, chain, project_manifest)
    } else {
        let (settings, chain, project_manifest) =
            match load_session_settings(manifest_path, &network) {
                Ok((session, chain, project_manifest)) => (session, chain, project_manifest),
                Err(e) => return Err(vec![e]),
            };
        (settings, chain, project_manifest)
    };

    let (tx, rx) = channel();
    let (per_contract_event_tx, per_contract_event_rx) = channel();

    let contracts_to_deploy = settings.initial_contracts.len();
    let node_url = settings.node.clone();

    // Approach's description: after getting all the contracts indexed by the manifest, we build a
    // a sorted set that we will be splitting in batches of 25 contracts, which is the number of
    // transactions that you can have for one user at a given time in a mempool.
    // We then keep fetching the stacks-node every `delay_between_checks` seconds and wait for
    // all the contracts to be published, and then move on to the next batch.
    // We're using a channel here because this routine can be used in 2 different contexts:
    // - clarinet contracts publish: display a UI that let developers tracking the progress
    // - clarinet integrate / orchestra: nothing displayed, but the events are being used
    // for coordinating the chains setup.
    let per_contract_event_tx_moved = per_contract_event_tx.clone();
    let deploying_thread_handle = std::thread::spawn(move || {
        let mut total_contracts_deployed = 0;
        let stacks_rpc = StacksRpc::new(&node_url);

        while contracts_to_deploy != total_contracts_deployed {
            let mut current_block_height = 0;
            let mut contracts_batch: Vec<(StacksTransaction, StacksAddress, String)> =
                rx.recv().unwrap();
            let mut batch_deployed = false;
            let mut contracts_being_deployed: BTreeMap<(String, String), bool> = BTreeMap::new();
            loop {
                let new_block_height = match stacks_rpc.get_info() {
                    Ok(info) => info.burn_block_height,
                    _ => {
                        std::thread::sleep(std::time::Duration::from_secs(
                            delay_between_checks.into(),
                        ));
                        continue;
                    }
                };

                if new_block_height <= current_block_height {
                    std::thread::sleep(std::time::Duration::from_secs(delay_between_checks.into()));
                    continue;
                }

                current_block_height = new_block_height;

                if !batch_deployed {
                    batch_deployed = true;
                    for (tx, deployer, contract_name) in contracts_batch.drain(..) {
                        let _ = match stacks_rpc.post_transaction(tx) {
                            Ok(res) => {
                                let _ = per_contract_event_tx_moved.send(
                                    PublishUpdate::ContractUpdate(ContractUpdate {
                                        contract_id: format!("{}.{}", deployer, contract_name),
                                        status: ContractStatus::Broadcasted,
                                        comment: Some(format!(
                                            "Contract broadcasted: {}",
                                            res.txid.clone()
                                        )),
                                    }),
                                );
                                contracts_being_deployed
                                    .insert((deployer.to_string(), contract_name), true);
                                res.txid
                            }
                            Err(e) => {
                                let _ = per_contract_event_tx_moved.send(
                                    PublishUpdate::ContractUpdate(ContractUpdate {
                                        contract_id: format!("{}.{}", deployer, contract_name),
                                        status: ContractStatus::Error,
                                        comment: Some(format!("Broadcast error: {:?}", e)),
                                    }),
                                );
                                std::process::exit(1);
                            }
                        };
                    }
                    std::thread::sleep(std::time::Duration::from_secs(delay_between_checks.into()));
                    continue;
                }

                let mut keep_looping = false;

                for ((deployer, contract_name), value) in contracts_being_deployed.iter_mut() {
                    if *value {
                        let res = stacks_rpc.get_contract_source(&deployer, &contract_name);
                        if let Ok(_contract) = res {
                            *value = false;
                            total_contracts_deployed += 1;
                            let _ = per_contract_event_tx_moved.send(
                                PublishUpdate::ContractUpdate(ContractUpdate {
                                    contract_id: format!("{}.{}", deployer, contract_name),
                                    status: ContractStatus::Published,
                                    comment: None,
                                }),
                            );
                        } else {
                            keep_looping = true;
                            break;
                        }
                    }
                }

                if !keep_looping {
                    break;
                }
            }
        }
        let _ = per_contract_event_tx_moved.send(PublishUpdate::Completed);
    });

    let results = vec![];
    let mut deployers_nonces = HashMap::new();
    let mut deployers_lookup: HashMap<String, Account> = HashMap::new();

    for account in settings.initial_accounts.iter() {
        deployers_lookup.insert(account.name.to_string(), account.clone());
        if account.name == "deployer" {
            deployers_lookup.insert("*".into(), account.clone());
        }
        // Let's avoid fetching nonces in the case of initial Devnet setup.
        if devnet_event_tx.is_some() {
            deployers_nonces.insert(account.name.clone(), 0);
        }
    }

    let node_url = settings.node.clone();
    let stacks_rpc = StacksRpc::new(&node_url);

    for batch in settings.initial_contracts.chunks(25) {
        let mut encoded_contracts = vec![];

        for contract in batch.iter() {
            let contract_name = contract.name.clone().unwrap();

            let deployer = match deployers_lookup.get(&contract_name) {
                Some(deployer) => deployer,
                None => deployers_lookup.get("*").unwrap(),
            };

            let nonce = match deployers_nonces.get(&deployer.name) {
                Some(nonce) => *nonce,
                None => {
                    let nonce = stacks_rpc
                        .get_nonce(&deployer.address)
                        .expect("Unable to retrieve account");
                    deployers_nonces.insert(deployer.name.clone(), nonce);
                    nonce
                }
            };

            let (signed_tx, signer_addr) = endode_contract(
                contract,
                deployer,
                nonce,
                chain.network.deployment_fee_rate,
                network,
            )
            .expect("Unable to encode contract");

            let _ = per_contract_event_tx.send(PublishUpdate::ContractUpdate(ContractUpdate {
                contract_id: format!("{}.{}", deployer.address, contract_name),
                status: ContractStatus::Encoded,
                comment: Some(format!("Contract encoded and queued")),
            }));

            encoded_contracts.push((signed_tx, signer_addr, contract_name));
            deployers_nonces.insert(deployer.name.clone(), nonce + 1);
        }

        let _ = tx.send(encoded_contracts);
    }

    if devnet_event_tx.is_none() {
        let mut contracts = Vec::new();
        for contract in settings.initial_contracts.iter() {
            let deployer = {
                let deployer = contract.deployer.clone().unwrap_or("deployer".to_string());
                match deployers_lookup.get(&deployer) {
                    Some(deployer) => deployer,
                    None => deployers_lookup.get("*").unwrap(),
                }
            };
            contracts.push((deployer.address.to_string(), contract.name.clone().unwrap()));
        }

        ctrlc::set_handler(move || {
            let _ = per_contract_event_tx.send(PublishUpdate::Completed);
        })
        .expect("Error setting Ctrl-C handler");

        let _ = ui::start_ui(&node_url, per_contract_event_rx, contracts);
    } else {
        let _ = deploying_thread_handle.join();
    }

    // TODO(lgalabru): if devnet, we should be pulling all the links.

    if let Some(chains_coordinator_commands_tx) = chains_coordinator_commands_tx {
        let _ = chains_coordinator_commands_tx.send(ChainsCoordinatorCommand::ProtocolDeployed);
    }

    if let Some(devnet_event_tx) = devnet_event_tx {
        let _ = devnet_event_tx.send(DevnetEvent::ProtocolDeployed);
    } else {
        println!(
            "{} Contracts successfully deployed on {:?}",
            green!("✔"),
            network
        );
    }

    Ok((results, project_manifest))
}

pub fn setup_session_from_deployment(deployment: &DeploymentSpecification) -> Result<Session, String> {
    use clarity_repl::repl::SessionSettings;
    use crate::deployment::types::TransactionSpecification;

    let mut settings = SessionSettings::default();
    let mut session = Session::new(settings);

    // let mut project_path = manifest_path.clone();
    // project_path.pop();

    // let mut chain_config_path = project_path.clone();
    // // chain_config_path.pop();
    // chain_config_path.push("settings");

    // chain_config_path.push(match env {
    //     StacksNetwork::Devnet => "Devnet.toml",
    //     StacksNetwork::Testnet => "Testnet.toml",
    //     StacksNetwork::Mainnet => "Mainnet.toml",
    // });

    // let mut project_config = ProjectManifest::from_path(&manifest_path);
    // let chain_config = ChainConfig::from_path(&chain_config_path, env);

    // let mut deployer_address = None;
    // let mut initial_deployer = None;

    // settings.node = chain_config
    //     .network
    //     .node_rpc_address
    //     .clone()
    //     .take()
    //     .unwrap_or(match env {
    //         StacksNetwork::Devnet => "http://127.0.0.1:20443".into(),
    //         StacksNetwork::Testnet => "https://stacks-node-api.testnet.stacks.co".into(),
    //         StacksNetwork::Mainnet => "https://stacks-node-api.mainnet.stacks.co".into(),
    //     });

    // settings.include_boot_contracts = vec![
    //     "pox".to_string(),
    //     "costs-v1".to_string(),
    //     "costs-v2".to_string(),
    //     "bns".to_string(),
    // ];
    // settings.initial_deployer = initial_deployer;
    // settings.repl_settings = project_config.repl_settings.clone();
    // settings.disk_cache_enabled = true;

    if let Some(ref genesis) = deployment.genesis {
        for wallet in genesis.wallets.iter() {
            let _ = session.interpreter.mint_stx_balance(wallet.principal.clone().into(), wallet.amount.try_into().unwrap());
        }
    }

    for batch in deployment.plan.batches.iter() {
        for transaction in batch.transactions.iter() {
            match transaction {
                TransactionSpecification::ContractCall(_) | TransactionSpecification::ContractPublish(_) => {}
                TransactionSpecification::EmulatedContractPublish(tx) => {
                    let default_tx_sender = session.get_tx_sender();
                    session.set_tx_sender(tx.emulated_sender.to_string());
                    let _ = session.interpret(tx.source.clone(), Some(tx.contract.to_string()), false, false, None);
                    session.set_tx_sender(default_tx_sender);
                }
                TransactionSpecification::EmulatedContractCall(tx) => {
                    let _ = session.invoke_contract_call(&tx.contract_id.to_string(), &tx.method.to_string(), &tx.parameters, &tx.emulated_sender.to_string(), "deployment".to_string());
                }
            }
        }
        session.advance_chain_tip(1);
    }

    Ok(session)
    // for (name, account) in deployment..accounts.iter() {
    //     let account = repl::settings::Account {
    //         name: name.clone(),
    //         balance: account.balance,
    //         address: account.address.clone(),
    //         mnemonic: account.mnemonic.clone(),
    //         derivation: account.derivation.clone(),
    //     };
    //     if name == "deployer" {
    //         initial_deployer = Some(account.clone());
    //         deployer_address = Some(account.address.clone());
    //     }
    //     settings.initial_accounts.push(account);
    // }

    // for name in project_config.ordered_contracts().iter() {
    //     let config = project_config.contracts.get(name).unwrap();
    //     let mut contract_path = project_path.clone();
    //     contract_path.push(&config.path);

    //     let code = match fs::read_to_string(&contract_path) {
    //         Ok(code) => code,
    //         Err(err) => {
    //             return Err(format!(
    //                 "Error: unable to read {:?}: {}",
    //                 contract_path, err
    //             ))
    //         }
    //     };

    //     settings
    //         .initial_contracts
    //         .push(repl::settings::InitialContract {
    //             code: code,
    //             path: contract_path.to_str().unwrap().into(),
    //             name: Some(name.clone()),
    //             deployer: deployer_address.clone(),
    //         });
    // }

    // let links = match project_config.project.requirements.take() {
    //     Some(links) => links,
    //     None => vec![],
    // };

    // for link_config in links.iter() {
    //     settings.initial_links.push(repl::settings::InitialLink {
    //         contract_id: link_config.contract_id.clone(),
    //         stacks_node_addr: None,
    //         cache: Some(project_config.project.cache_dir.clone()),
    //     });
    // }

    // settings.include_boot_contracts = vec![
    //     "pox".to_string(),
    //     "costs-v1".to_string(),
    //     "costs-v2".to_string(),
    //     "bns".to_string(),
    // ];
    // settings.initial_deployer = initial_deployer;
    // settings.repl_settings = project_config.repl_settings.clone();
    // settings.disk_cache_enabled = true;
}

pub fn check_deployments(manifest_path: &PathBuf) -> Result<(), String> {
    let mut base_path = manifest_path.clone();
    base_path.pop();
    let files = get_deployments_files(manifest_path)?;
    for (path, relative_path) in files.into_iter() {
        let spec = match DeploymentSpecification::from_config_file(&path, &base_path) {
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

pub fn load_deployment(manifest_path: &PathBuf, deployment_path: &PathBuf) -> Result<DeploymentSpecification, String> {
    let mut base_path = manifest_path.clone();
    base_path.pop();
    let spec = match DeploymentSpecification::from_config_file(&deployment_path, &base_path) {
        Ok(spec) => spec,
        Err(msg) => {
            return Err(format!("{} {} syntax incorrect\n{}", red!("x"), deployment_path.display(), msg));
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
        Err(_) => return Ok(vec![])
    };
    let mut hook_paths = vec![];
    for path in paths {
        let file = path.unwrap().path();
        let is_extension_valid = file.extension()
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

pub fn write_deployment(deployment: &DeploymentSpecification, target_path: &PathBuf) -> Result<(), String> {

    let file = deployment.to_specification_file();

    let content = match serde_yaml::to_string(&file) {
        Ok(res) => res,
        Err(err) => {
            return Err(format!("unable to serialize deployment {}", err))
        }
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

pub fn generate_default_deployment(manifest_path: &PathBuf, network: Option<StacksNetwork>) -> Result<DeploymentSpecification, String> {

    let mut project_path = manifest_path.clone();
    project_path.pop();

    let mut chain_config_path = project_path.clone();
    chain_config_path.push("settings");

    chain_config_path.push(match network {
        None | Some(StacksNetwork::Devnet) => "Devnet.toml",
        Some(StacksNetwork::Testnet) => "Testnet.toml",
        Some(StacksNetwork::Mainnet) => "Mainnet.toml",
    });

    let mut project_config = ProjectManifest::from_path(&manifest_path);
    let chain_config = ChainConfig::from_path(&chain_config_path, match network {
        None => &StacksNetwork::Devnet,
        Some(ref network) => network,
    });

    let default_deployer = match chain_config.accounts.get("deployer") {
        Some(deployer) => deployer,
        None => {
            return Err(format!("{} unable to retrieve default deployer account in {}", red!("x"), chain_config_path.display()));
        }
    };

    let mut contracts = HashMap::new();

    for (name, config) in project_config.contracts.iter() {

        let contract = match ContractName::try_from(name.to_string()) {
            Ok(res) => res,
            Err(_) => return Err(format!("unable to use {} as a valid contract name", name))
        };

        let deployer = match config.deployer {
            Some(ref deployer) => {
                let deployer = match chain_config.accounts.get(deployer) {
                    Some(deployer) => deployer,
                    None => {
                        return Err(format!("{} unable to retrieve account {} in {}", red!("x"), deployer, chain_config_path.display()));
                    }
                };
                deployer
            }
            None => default_deployer
        };

        let emulated_sender = match PrincipalData::parse_standard_principal(&deployer.address) {
            Ok(res) => res,
            Err(_) => return Err(format!("unable to turn emulated_sender {} as a valid Stacks address", deployer.address))
        };

        let source = match  std::fs::read_to_string(&config.path) {
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

        let contract_id = QualifiedContractIdentifier::new(contract.emulated_sender.clone(), contract.contract.clone());

        contracts.insert(contract_id, contract);
    }

    use clarity_repl::repl::SessionSettings;
    use clarity_repl::analysis::ast_dependency_detector::ASTDependencyDetector;

    let settings = SessionSettings::default();
    let mut session = Session::new(settings);

    let mut contract_asts = HashMap::new();

    for (contract_id, contract) in contracts.iter() {
        let (ast, _, _) = session.interpreter.build_ast(
            contract_id.clone(),
            contract.source.clone(),
            2,
        );
        contract_asts.insert(contract_id.clone(), ast);
    }

    let dependencies =
    ASTDependencyDetector::detect_dependencies(&contract_asts, &BTreeMap::new());
    let ordered_contracts_ids = match ASTDependencyDetector::order_contracts(&dependencies) {
        Ok(ordered_contracts) => ordered_contracts,
        Err(e) => {
            return Err(format!(
                "unable order contracts {}",
                e
            ))
        }
    };

    let mut transactions = vec![];
    for contract_id in ordered_contracts_ids.iter() {
        let data = contracts.remove(contract_id).expect("unable to retrieve contract");
        let tx = TransactionSpecification::EmulatedContractPublish(data);
        transactions.push(tx);
    }

    let tx_chain_limit = 25;

    let mut batches = vec![];
    for (id, transactions) in transactions.chunks(25).enumerate() {
        batches.push(TransactionsBatchSpecification {
            id: id,
            transactions: transactions.to_vec()
        })
    }

    let mut wallets = vec![];
    for (label, account) in chain_config.accounts.into_iter() {

        let principal = match PrincipalData::parse_standard_principal(&account.address) {
            Ok(res) => res,
            Err(_) => return Err(format!("unable to parse wallet {} in a valid Stacks address", account.address))
        };

        wallets.push(WalletSpecification {
            label,
            principal,
            amount: account.balance.into(),
        });
    }

    // TODO(lgalabru): use project_config.repl_settings.include_boot_contracts.clone()
    let boot_contracts = vec![
        "pox".to_string(),
        "costs-v2".to_string(),
        "bns".to_string(),
    ];

    let deployment = DeploymentSpecification {
        id: 0,
        name: "Test deployment, used by default by `clarinet console`, `clarinet test` and `clarinet check`".to_string(),
        network: None,
        start_block: 0,
        genesis: Some(GenesisSpecification {
            wallets,
            contracts: boot_contracts
        }),
        plan: TransactionPlanSpecification {
            batches
        }
    };

    // let links = match project_config.project.requirements.take() {
    //     Some(links) => links,
    //     None => vec![],
    // };

    // for link_config in links.iter() {
    //     settings.initial_links.push(repl::settings::InitialLink {
    //         contract_id: link_config.contract_id.clone(),
    //         stacks_node_addr: None,
    //         cache: Some(project_config.project.cache_dir.clone()),
    //     });
    // }

    // settings.include_boot_contracts = vec![
    //     "pox".to_string(),
    //     "costs-v1".to_string(),
    //     "costs-v2".to_string(),
    //     "bns".to_string(),
    // ];
    // settings.initial_deployer = initial_deployer;
    // settings.repl_settings = project_config.repl_settings.clone();
    // settings.disk_cache_enabled = true;

    Ok(deployment)
}

pub fn create_default_test_deployment(manifest_path: &PathBuf) -> Result<DeploymentSpecification, String> {
    let deployment = generate_default_deployment(&manifest_path, None)?;
    Ok(deployment)
}


pub fn display_deployment(deployment: &DeploymentSpecification) {

}
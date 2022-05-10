use clarity_repl::clarity::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData,
};
use clarity_repl::clarity::util::hash::hex_bytes;
use clarity_repl::clarity::util::StacksAddress;
use clarity_repl::clarity::{ClarityName, ContractName};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use std::fs;
use std::fs::DirEntry;
use std::str::FromStr;

use crate::types::StacksNetwork;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionPlanSpecification {
    pub batches: Vec<TransactionsBatchSpecification>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionPlanSpecificationFile {
    pub batches: Vec<TransactionsBatchSpecificationFile>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionsBatchSpecificationFile {
    pub id: usize,
    pub transactions: Vec<TransactionSpecificationFile>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum TransactionSpecificationFile {
    #[serde(rename = "contract-call")]
    ContractCall(ContractCallSpecificationFile),
    #[serde(rename = "contract-publish")]
    ContractPublish(ContractPublishSpecificationFile),
    #[serde(rename = "emulated-contract-call")]
    EmulatedContractCall(EmulatedContractCallSpecificationFile),
    #[serde(rename = "emulated-contract-publish")]
    EmulatedContractPublish(EmulatedContractPublishSpecificationFile),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ContractCallSpecificationFile {
    pub contract_id: String,
    #[serde(rename = "expected-sender")]
    pub expected_sender: String,
    pub method: String,
    pub parameters: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ContractPublishSpecificationFile {
    pub contract: String,
    #[serde(rename = "expected-sender")]
    pub expected_sender: String,
    pub path: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EmulatedContractCallSpecificationFile {
    pub contract_id: String,
    #[serde(rename = "emulated-sender")]
    pub emulated_sender: String,
    pub method: String,
    pub parameters: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EmulatedContractPublishSpecificationFile {
    pub contract: String,
    #[serde(rename = "emulated-sender")]
    pub emulated_sender: String,
    pub path: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionsBatchSpecification {
    pub id: usize,
    pub transactions: Vec<TransactionSpecification>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum TransactionSpecification {
    #[serde(rename = "contract-call")]
    ContractCall(ContractCallSpecification),
    #[serde(rename = "contract-publish")]
    ContractPublish(ContractPublishSpecification),
    #[serde(rename = "emulated-contract-call")]
    EmulatedContractCall(EmulatedContractCallSpecification),
    #[serde(rename = "emulated-contract-publish")]
    EmulatedContractPublish(EmulatedContractPublishSpecification),
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ContractCallSpecification {
    pub contract_id: QualifiedContractIdentifier,
    pub expected_sender: StandardPrincipalData,
    pub method: ClarityName,
    pub parameters: Vec<String>,
}

impl ContractCallSpecification {
    pub fn from_specifications(
        specs: &ContractCallSpecificationFile,
    ) -> Result<ContractCallSpecification, String> {
        let contract_id = match QualifiedContractIdentifier::parse(&specs.contract_id) {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to parse {} as a valid contract_id",
                    specs.contract_id
                ))
            }
        };

        let expected_sender = match PrincipalData::parse_standard_principal(&specs.expected_sender)
        {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to turn emulated_sender {} as a valid Stacks address",
                    specs.expected_sender
                ))
            }
        };

        let method = match ClarityName::try_from(specs.method.to_string()) {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to use {} as a valid contract name",
                    specs.method
                ))
            }
        };

        Ok(ContractCallSpecification {
            contract_id,
            expected_sender,
            method,
            parameters: specs.parameters.clone(),
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct ContractPublishSpecification {
    pub contract: ContractName,
    pub expected_sender: StandardPrincipalData,
    pub relative_path: String,
    pub source: String,
}

impl ContractPublishSpecification {
    pub fn from_specifications(
        specs: &ContractPublishSpecificationFile,
        base_path: &PathBuf,
    ) -> Result<ContractPublishSpecification, String> {
        let contract = match ContractName::try_from(specs.contract.to_string()) {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to use {} as a valid contract name",
                    specs.contract
                ))
            }
        };

        let expected_sender = match PrincipalData::parse_standard_principal(&specs.expected_sender)
        {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to turn emulated_sender {} as a valid Stacks address",
                    specs.expected_sender
                ))
            }
        };

        let path = match PathBuf::try_from(&specs.path) {
            Ok(res) => res,
            Err(_) => return Err(format!("unable to turn {} into a valid path", specs.path)),
        };

        let mut contract_path = base_path.clone();
        contract_path.push(path);

        let source = match fs::read_to_string(&contract_path) {
            Ok(code) => code,
            Err(err) => {
                return Err(format!(
                    "unable to read contract at path {:?}: {}",
                    contract_path, err
                ))
            }
        };

        Ok(ContractPublishSpecification {
            contract,
            expected_sender,
            source,
            relative_path: specs.path.clone(),
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct EmulatedContractCallSpecification {
    pub contract_id: QualifiedContractIdentifier,
    pub emulated_sender: StandardPrincipalData,
    pub method: ClarityName,
    pub parameters: Vec<String>,
}

impl EmulatedContractCallSpecification {
    pub fn from_specifications(
        specs: &EmulatedContractCallSpecificationFile,
    ) -> Result<EmulatedContractCallSpecification, String> {
        let contract_id = match QualifiedContractIdentifier::parse(&specs.contract_id) {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to parse {} as a valid contract_id",
                    specs.contract_id
                ))
            }
        };

        let emulated_sender = match PrincipalData::parse_standard_principal(&specs.emulated_sender)
        {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to turn emulated_sender {} as a valid Stacks address",
                    specs.emulated_sender
                ))
            }
        };

        let method = match ClarityName::try_from(specs.method.to_string()) {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to use {} as a valid contract name",
                    specs.method
                ))
            }
        };

        Ok(EmulatedContractCallSpecification {
            contract_id,
            emulated_sender,
            method,
            parameters: specs.parameters.clone(),
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct EmulatedContractPublishSpecification {
    pub contract: ContractName,
    pub emulated_sender: StandardPrincipalData,
    pub source: String,
    pub relative_path: String,
}

impl EmulatedContractPublishSpecification {
    pub fn from_specifications(
        specs: &EmulatedContractPublishSpecificationFile,
        base_path: &PathBuf,
    ) -> Result<EmulatedContractPublishSpecification, String> {
        let contract = match ContractName::try_from(specs.contract.to_string()) {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to use {} as a valid contract name",
                    specs.contract
                ))
            }
        };

        let emulated_sender = match PrincipalData::parse_standard_principal(&specs.emulated_sender)
        {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to turn emulated_sender {} as a valid Stacks address",
                    specs.emulated_sender
                ))
            }
        };

        let path = match PathBuf::try_from(&specs.path) {
            Ok(res) => res,
            Err(_) => return Err(format!("unable to turn {} into a valid path", specs.path)),
        };

        let mut contract_path = base_path.clone();
        contract_path.push(path);

        let source = match fs::read_to_string(&contract_path) {
            Ok(code) => code,
            Err(err) => {
                return Err(format!(
                    "unable to read contract at path {:?}: {}",
                    contract_path, err
                ))
            }
        };

        Ok(EmulatedContractPublishSpecification {
            contract,
            emulated_sender,
            source,
            relative_path: specs.path.clone(),
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DeploymentSpecification {
    pub id: u32,
    pub name: String,
    pub network: Option<StacksNetwork>,
    pub genesis: Option<GenesisSpecification>,
    #[serde(rename = "start-block")]
    pub start_block: u64,
    pub plan: TransactionPlanSpecification,
}

impl DeploymentSpecification {
    pub fn from_config_file(
        path: &PathBuf,
        base_path: &PathBuf,
    ) -> Result<DeploymentSpecification, String> {
        let path = match File::open(path) {
            Ok(path) => path,
            Err(_e) => {
                panic!("unable to locate {}", path.display());
            }
        };
        let mut spec_file_reader = BufReader::new(path);
        let mut spec_file_buffer = vec![];
        spec_file_reader.read_to_end(&mut spec_file_buffer).unwrap();

        let specification_file: DeploymentSpecificationFile =
            match serde_yaml::from_slice(&spec_file_buffer[..]) {
                Ok(res) => res,
                Err(msg) => return Err(format!("unable to read file {}", msg)),
            };

        let deployment_spec = if specification_file.network.to_lowercase() == "test" {
            DeploymentSpecification::from_specifications(&specification_file, None, base_path)?
        } else if specification_file.network.to_lowercase() == "devnet" {
            DeploymentSpecification::from_specifications(
                &specification_file,
                Some(StacksNetwork::Devnet),
                base_path,
            )?
        } else if specification_file.network.to_lowercase() == "testnet" {
            DeploymentSpecification::from_specifications(
                &specification_file,
                Some(StacksNetwork::Testnet),
                base_path,
            )?
        } else if specification_file.network.to_lowercase() == "mainnet" {
            DeploymentSpecification::from_specifications(
                &specification_file,
                Some(StacksNetwork::Mainnet),
                base_path,
            )?
        } else {
            return Err(format!(
                "network '{}' not supported (test, devnet, testnet, mainnet)",
                specification_file.network
            ));
        };

        Ok(deployment_spec)
    }

    pub fn from_specifications(
        specs: &DeploymentSpecificationFile,
        network: Option<StacksNetwork>,
        base_path: &PathBuf,
    ) -> Result<DeploymentSpecification, String> {
        let (plan, genesis) = match &network {
            None => {
                let mut batches = vec![];
                let mut genesis = None;
                if let Some(ref plan) = specs.plan {
                    for batch in plan.batches.iter() {
                        let mut transactions = vec![];
                        for tx in batch.transactions.iter() {
                            let transaction = match tx {
                                TransactionSpecificationFile::EmulatedContractCall(spec) => {
                                    TransactionSpecification::EmulatedContractCall(EmulatedContractCallSpecification::from_specifications(spec)?)
                                }
                                TransactionSpecificationFile::EmulatedContractPublish(spec) => {
                                    TransactionSpecification::EmulatedContractPublish(EmulatedContractPublishSpecification::from_specifications(spec, base_path)?)
                                }
                                _ => {
                                    return Err(format!("{} only supports transactions of type 'emulated-contract-call' and 'emulated-contract-publish", specs.network.to_lowercase()))
                                }
                            };
                            transactions.push(transaction);
                        }
                        batches.push(TransactionsBatchSpecification {
                            id: batch.id,
                            transactions,
                        });
                    }
                }
                if let Some(ref genesis_specs) = specs.genesis {
                    genesis = Some(GenesisSpecification::from_specifications(genesis_specs)?);
                }
                (TransactionPlanSpecification { batches }, genesis)
            }
            Some(network) => {
                let mut batches = vec![];
                if let Some(ref plan) = specs.plan {
                    for batch in plan.batches.iter() {
                        let mut transactions = vec![];
                        for tx in batch.transactions.iter() {
                            let transaction = match tx {
                                TransactionSpecificationFile::ContractCall(spec) => {
                                    TransactionSpecification::ContractCall(ContractCallSpecification::from_specifications(spec)?)
                                }
                                TransactionSpecificationFile::ContractPublish(spec) => {
                                    TransactionSpecification::ContractPublish(ContractPublishSpecification::from_specifications(spec, base_path)?)
                                }
                                _ => {
                                    return Err(format!("{} only supports transactions of type 'contract-call' and 'contract-publish", specs.network.to_lowercase()))
                                }
                            };
                            transactions.push(transaction);
                        }
                        batches.push(TransactionsBatchSpecification {
                            id: batch.id,
                            transactions,
                        });
                    }
                }
                (TransactionPlanSpecification { batches }, None)
            }
        };
        Ok(DeploymentSpecification {
            id: specs.id.unwrap_or(0),
            name: specs.name.to_string(),
            network,
            genesis,
            start_block: specs.start_block.unwrap_or(0),
            plan,
        })
    }

    pub fn to_specification_file(&self) -> DeploymentSpecificationFile {
        DeploymentSpecificationFile {
            id: Some(self.id),
            name: self.name.clone(),
            network: match self.network {
                None => "test".to_string(),
                Some(StacksNetwork::Devnet) => "devnet".to_string(),
                Some(StacksNetwork::Testnet) => "testnet".to_string(),
                Some(StacksNetwork::Mainnet) => "mainnet".to_string(),
            },
            start_block: Some(self.start_block),
            genesis: match self.genesis {
                Some(ref g) => Some(g.to_specification_file()),
                None => None,
            },
            plan: Some(self.plan.to_specification_file()),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DeploymentSpecificationFile {
    pub id: Option<u32>,
    pub name: String,
    pub network: String,
    #[serde(rename = "start-block")]
    pub start_block: Option<u64>,
    pub genesis: Option<GenesisSpecificationFile>,
    pub plan: Option<TransactionPlanSpecificationFile>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct GenesisSpecificationFile {
    pub wallets: Vec<WalletSpecificationFile>,
    pub contracts: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct WalletSpecificationFile {
    pub label: String,
    pub principal: String,
    pub amount: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct GenesisSpecification {
    pub wallets: Vec<WalletSpecification>,
    pub contracts: Vec<String>,
}

impl GenesisSpecification {
    pub fn from_specifications(
        specs: &GenesisSpecificationFile,
    ) -> Result<GenesisSpecification, String> {
        let mut wallets = vec![];
        for wallet in specs.wallets.iter() {
            wallets.push(WalletSpecification::from_specifications(wallet)?);
        }

        Ok(GenesisSpecification {
            wallets,
            contracts: specs.contracts.clone(),
        })
    }

    pub fn to_specification_file(&self) -> GenesisSpecificationFile {
        let mut wallets = vec![];
        for wallet in self.wallets.iter() {
            wallets.push(WalletSpecificationFile {
                label: wallet.label.to_string(),
                principal: wallet.principal.to_string(),
                amount: format!("{}", wallet.amount),
            })
        }

        GenesisSpecificationFile {
            wallets,
            contracts: self.contracts.clone(),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct WalletSpecification {
    pub label: String,
    pub principal: StandardPrincipalData,
    pub amount: u128,
}

impl WalletSpecification {
    pub fn from_specifications(
        specs: &WalletSpecificationFile,
    ) -> Result<WalletSpecification, String> {
        let principal = match PrincipalData::parse_standard_principal(&specs.principal) {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to turn {}'s principal as a valid Stacks address",
                    specs.label
                ))
            }
        };

        let amount = match u128::from_str_radix(&specs.amount, 10) {
            Ok(res) => res,
            Err(_) => {
                return Err(format!(
                    "unable to parse {}'s balance as a u128",
                    specs.label
                ))
            }
        };

        Ok(WalletSpecification {
            label: specs.label.to_string(),
            principal,
            amount,
        })
    }
}

impl TransactionPlanSpecification {
    pub fn to_specification_file(&self) -> TransactionPlanSpecificationFile {
        let mut batches = vec![];
        for batch in self.batches.iter() {
            let mut transactions = vec![];
            for tx in batch.transactions.iter() {
                let tx = match tx {
                    TransactionSpecification::ContractCall(tx) => {
                        TransactionSpecificationFile::ContractCall(ContractCallSpecificationFile {
                            contract_id: tx.contract_id.to_string(),
                            expected_sender: tx.expected_sender.to_address(),
                            method: tx.method.to_string(),
                            parameters: tx.parameters.clone(),
                        })
                    }
                    TransactionSpecification::ContractPublish(tx) => {
                        TransactionSpecificationFile::ContractPublish(
                            ContractPublishSpecificationFile {
                                contract: tx.contract.to_string(),
                                expected_sender: tx.expected_sender.to_address(),
                                path: tx.relative_path.clone(),
                            },
                        )
                    }
                    TransactionSpecification::EmulatedContractCall(tx) => {
                        TransactionSpecificationFile::EmulatedContractCall(
                            EmulatedContractCallSpecificationFile {
                                contract_id: tx.contract_id.to_string(),
                                emulated_sender: tx.emulated_sender.to_address(),
                                method: tx.method.to_string(),
                                parameters: tx.parameters.clone(),
                            },
                        )
                    }
                    TransactionSpecification::EmulatedContractPublish(tx) => {
                        TransactionSpecificationFile::EmulatedContractPublish(
                            EmulatedContractPublishSpecificationFile {
                                contract: tx.contract.to_string(),
                                emulated_sender: tx.emulated_sender.to_address(),
                                path: tx.relative_path.clone(),
                            },
                        )
                    }
                };
                transactions.push(tx);
            }

            batches.push(TransactionsBatchSpecificationFile {
                id: batch.id,
                transactions,
            });
        }

        TransactionPlanSpecificationFile { batches }
    }
}

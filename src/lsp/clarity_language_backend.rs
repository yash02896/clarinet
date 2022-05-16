use super::{utils, LspRequest, ProtocolState};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{async_trait, Client, LanguageServer};

type Logs = Vec<String>;

// The LSP is being initialized when clarity files are being detected in the project.
// We want the LSP to be notified when 2 kind of edits happened:
// - .clar file opened:
//      - if the state is empty
//      - if the state is ready
// - Clarinet.toml file saved
// - .clar files saved
//      - if indexed in `Clarinet.toml`:
//      - if not indexed:
// - Clarinet.toml file saved

#[derive(Debug)]
pub struct ClarityLanguageBackend {
    client: Client,
    command_tx: Arc<Mutex<Sender<LspRequest>>>,
    protocol_state: RwLock<ProtocolState>,
}

impl ClarityLanguageBackend {
    pub fn new(client: Client, command_tx: Sender<LspRequest>) -> Self {
        Self {
            client,
            command_tx: Arc::new(Mutex::new(command_tx)),
            protocol_state: RwLock::new(ProtocolState::new()),
        }
    }
}

#[async_trait]
impl LanguageServer for ClarityLanguageBackend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            server_info: None,
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Options(
                    TextDocumentSyncOptions {
                        open_close: Some(true),
                        change: Some(TextDocumentSyncKind::Full),
                        will_save: Some(true),
                        will_save_wait_until: Some(false),
                        save: Some(TextDocumentSyncSaveOptions::Supported(true)),
                    },
                )),
                completion_provider: Some(CompletionOptions {
                    resolve_provider: Some(false),
                    trigger_characters: None,
                    all_commit_characters: None,
                    work_done_progress_options: Default::default(),
                }),
                type_definition_provider: None,
                hover_provider: Some(HoverProviderCapability::Simple(false)),
                declaration_provider: Some(DeclarationCapability::Simple(false)),
                ..ServerCapabilities::default()
            },
        })
    }

    async fn initialized(&self, _params: InitializedParams) {}

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn execute_command(&self, _: ExecuteCommandParams) -> Result<Option<Value>> {
        Ok(None)
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        // We receive notifications for toml and clar files, but only want to achieve this capability
        // for clar files.
        let contract_uri = params.text_document_position.text_document.uri;
        if !contract_uri.to_string().ends_with(".clar") {
            return Ok(None);
        }

        let mut keywords = {
            let protocol_state_reader = match self.protocol_state.read() {
                Ok(protocol_state_reader) => protocol_state_reader,
                Err(_) => return Ok(None),
            };
            protocol_state_reader.get_completion_items_for_contract(&contract_uri)
        };
        // Little big detail: should we wrap the inserted_text with braces?
        let should_wrap = {
            // let line = params.text_document_position.position.line;
            // let char = params.text_document_position.position.character;
            // let doc = params.text_document_position.text_document.uri;
            //
            // TODO(lgalabru): from there, we'd need to get the prior char
            // and see if a parenthesis was opened. If not, we need to wrap.
            // The LSP would need to update its local document cache, via
            // the did_change method.
            true
        };
        if should_wrap {
            for item in keywords.iter_mut() {
                match item.kind {
                    Some(CompletionItemKind::Event)
                    | Some(CompletionItemKind::Function)
                    | Some(CompletionItemKind::Module)
                    | Some(CompletionItemKind::Class)
                    | Some(CompletionItemKind::Method) => {
                        item.insert_text = Some(format!("({})", item.insert_text.take().unwrap()));
                    }
                    _ => {}
                }
            }
        }
        Ok(Some(CompletionResponse::from(keywords)))
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let response_rx = if let Some(contract_path) = get_contract_file(&params.text_document.uri)
        {
            let (response_tx, response_rx) = channel();
            let _ = match self.command_tx.lock() {
                Ok(tx) => tx.send(LspRequest::ContractOpened(contract_path, response_tx)),
                Err(_) => return,
            };
            response_rx
        } else if let Some(manifest_path) = get_manifest_file(&params.text_document.uri) {
            let (response_tx, response_rx) = channel();
            let _ = match self.command_tx.lock() {
                Ok(tx) => tx.send(LspRequest::ManifestOpened(manifest_path, response_tx)),
                Err(_) => return,
            };
            response_rx
        } else {
            self.client
                .log_message(MessageType::Warning, "Unsupported file opened")
                .await;
            return;
        };

        self.client
            .log_message(
                MessageType::Warning,
                "Command submitted to background thread",
            )
            .await;
        let (contracts, tldr) = if let Ok(ref mut response) = response_rx.recv() {
            if !response.contracts_updates.is_empty() {
                if let Ok(ref mut protocol_state_writer) = self.protocol_state.write() {
                    if response.state_cleared {
                        protocol_state_writer.clear();
                    }
                    protocol_state_writer.ingest_contracts_updates(&mut response.contracts_updates);
                }
                match self.protocol_state.read() {
                    Ok(protocol_state) => protocol_state.get_aggregated_diagnostics(),
                    Err(_) => (vec![], None),
                }
            } else {
                (vec![], None)
            }
        } else {
            (vec![], None)
        };

        self.client.log_message(MessageType::Error, "3").await;
        for (url, diags) in contracts.into_iter() {
            self.client.publish_diagnostics(url, diags, None).await;
        }
        if let Some((level, message)) = tldr {
            self.client.show_message(level, message).await;
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let response_rx = if let Some(contract_path) = get_contract_file(&params.text_document.uri)
        {
            let (response_tx, response_rx) = channel();
            let _ = match self.command_tx.lock() {
                Ok(tx) => tx.send(LspRequest::ContractChanged(contract_path, response_tx)),
                Err(_) => return,
            };
            response_rx
        } else if let Some(manifest_path) = get_contract_file(&params.text_document.uri) {
            let (response_tx, response_rx) = channel();
            let _ = match self.command_tx.lock() {
                Ok(tx) => tx.send(LspRequest::ManifestChanged(manifest_path, response_tx)),
                Err(_) => return,
            };
            response_rx
        } else {
            return;
        };

        if let Ok(ref mut response) = response_rx.recv() {
            if !response.contracts_updates.is_empty() {
                if let Ok(ref mut protocol_state_writer) = self.protocol_state.write() {
                    if response.state_cleared {
                        protocol_state_writer.clear();
                    }
                    protocol_state_writer.ingest_contracts_updates(&mut response.contracts_updates);
                }
            }
        }
    }

    async fn did_change(&self, _changes: DidChangeTextDocumentParams) {}

    async fn did_close(&self, _: DidCloseTextDocumentParams) {}

    // fn symbol(&self, params: WorkspaceSymbolParams) -> Self::SymbolFuture {
    //     Box::new(future::ok(None))
    // }

    // fn goto_declaration(&self, _: TextDocumentPositionParams) -> Self::DeclarationFuture {
    //     Box::new(future::ok(None))
    // }

    // fn goto_definition(&self, _: TextDocumentPositionParams) -> Self::DefinitionFuture {
    //     Box::new(future::ok(None))
    // }

    // fn goto_type_definition(&self, _: TextDocumentPositionParams) -> Self::TypeDefinitionFuture {
    //     Box::new(future::ok(None))
    // }

    // fn hover(&self, _: TextDocumentPositionParams) -> Self::HoverFuture {
    //     // todo(ludo): to implement
    //     let result = Hover {
    //         contents: HoverContents::Scalar(MarkedString::String("".to_string())),
    //         range: None,
    //     };
    //     Box::new(future::ok(None))
    // }

    // fn document_highlight(&self, _: TextDocumentPositionParams) -> Self::HighlightFuture {
    //     Box::new(future::ok(None))
    // }
}

fn get_manifest_file(text_document_uri: &Url) -> Option<PathBuf> {
    match text_document_uri.to_file_path() {
        Ok(path) if path.ends_with("Clarinet.toml") => Some(path),
        _ => None,
    }
}

fn get_contract_file(text_document_uri: &Url) -> Option<PathBuf> {
    match text_document_uri.to_file_path() {
        Ok(path) => match path.extension() {
            Some(ext) if ext.to_str() == Some("clar") => Some(path),
            _ => None,
        },
        _ => None,
    }
}

fn get_file_name(uri: &Url) -> Option<String> {
    uri.to_file_path()
        .ok()
        .as_ref()
        .and_then(|f| f.file_name())
        .and_then(|f| f.to_str())
        .and_then(|f| Some(f.to_string()))
}

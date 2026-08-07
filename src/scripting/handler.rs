//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 06/08/2026
//! Files   : nexsiz/src/scripting/handler.rs
//!
//! RPC command handler – campaign control + all plugin bridges + structured seeds.

use crate::common::types::{Field, FieldType, Message, TestCase};
use crate::coverage::CoverageProvider;
use crate::execution::worker::SharedStats;
use crate::input::corpus::SharedCorpus;
use crate::input::model::load_seeds_from_dir;
use crate::plugin::oracle::resolve_oracle;
use crate::plugin::PluginRegistry;
use crate::scripting::encryptor_bridge::{validate_encryptor_name, EncryptorBridge};
use crate::scripting::integrity_bridge::{validate_strategy, IntegrityBridge};
use crate::scripting::json::{self, JsonValue};
use crate::scripting::mutator_bridge::{dictionary_from_params, MutatorBridge};
use crate::scripting::oracle_bridge::OracleBridge;
use crate::scripting::protocol::{METHODS, PROTOCOL_VERSION};
use crate::scripting::protocol_bridge::{model_from_params, ProtocolBridge};
use crate::scripting::seed_parse::testcase_from_structured;
use crate::state::tracker::StateTracker;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct RpcContext {
    pub corpus: SharedCorpus,
    pub stats: Arc<SharedStats>,
    pub stop: Arc<AtomicBool>,
    pub tracker: Arc<StateTracker>,
    pub coverage: Arc<dyn CoverageProvider>,
    pub plugins: Arc<Mutex<PluginRegistry>>,
    pub seed_dir: String,
    pub output_dir: String,
    pub started: Instant,
    pub oracle_name: Arc<Mutex<String>>,
    pub model_name: Arc<Mutex<String>>,
    pub integrity_name: Arc<Mutex<String>>,
    pub encryptor_name: Arc<Mutex<String>>,
    pub target_summary: String,
    pub workers: usize,
    pub oracle_bridge: Arc<OracleBridge>,
    pub protocol_bridge: Arc<ProtocolBridge>,
    pub integrity_bridge: Arc<IntegrityBridge>,
    pub encryptor_bridge: Arc<EncryptorBridge>,
    pub mutator_bridge: Arc<MutatorBridge>,
}

pub enum HandleOutcome {
    Response(String),
    EnterOracleMode,
}

impl RpcContext {
    pub fn handle_line(&self, line: &str) -> HandleOutcome {
        let req = match json::parse(line.trim()) {
            Ok(v) => v,
            Err(e) => {
                return HandleOutcome::Response(error_response(
                    None,
                    &format!("parse error: {}", e),
                ))
            }
        };

        let id = req.get("id").cloned();
        let method = match req.get_str("method") {
            Some(m) => m,
            None => return HandleOutcome::Response(error_response(id, "missing method")),
        };
        let params = req
            .get("params")
            .cloned()
            .unwrap_or(JsonValue::Object(Default::default()));

        if method == "register_oracle" {
            return HandleOutcome::EnterOracleMode;
        }

        let result = match method {
            "ping" => Ok(json::obj(vec![("pong", json::b(true))])),
            "version" => Ok(json::obj(vec![
                ("nexsiz", json::s(crate::VERSION)),
                ("rpc", json::n(PROTOCOL_VERSION as f64)),
            ])),
            "list_methods" => Ok(JsonValue::Array(
                METHODS.iter().map(|m| json::s(*m)).collect(),
            )),
            "stats" => Ok(self.stats_json()),
            "stop" => {
                self.stop.store(true, Ordering::Relaxed);
                Ok(json::obj(vec![("stopped", json::b(true))]))
            }
            "load_seeds" => self.cmd_load_seeds(&params),
            "add_seed_raw" => self.cmd_add_seed_raw(&params),
            "add_seed_structured" => self.cmd_add_seed_structured(&params),
            "export_corpus" => self.cmd_export_corpus(&params),
            "set_oracle" => self.cmd_set_oracle(&params),
            "set_model" => self.cmd_set_name(&params, "model"),
            "set_integrity" => self.cmd_set_name(&params, "integrity"),
            "set_encryptor" => self.cmd_set_name(&params, "encryptor"),
            "get_config" => Ok(self.config_json()),
            "unregister_oracle" => {
                self.oracle_bridge.unregister();
                *self.oracle_name.lock().unwrap() = "default".into();
                Ok(json::obj(vec![("unregistered", json::b(true))]))
            }
            "oracle_status" => Ok(json::obj(vec![
                ("active", json::b(self.oracle_bridge.is_active())),
                ("hits", json::n(self.oracle_bridge.hits() as f64)),
                ("misses", json::n(self.oracle_bridge.misses() as f64)),
            ])),
            "register_protocol" => self.cmd_register_protocol(&params),
            "unregister_protocol" => {
                self.protocol_bridge.unregister();
                *self.model_name.lock().unwrap() = "default".into();
                Ok(json::obj(vec![("unregistered", json::b(true))]))
            }
            "protocol_status" => Ok(json::obj(vec![
                ("active", json::b(self.protocol_bridge.is_active())),
                ("name", json::s(self.protocol_bridge.name())),
                (
                    "dictionary_len",
                    json::n(self.protocol_bridge.dictionary_len() as f64),
                ),
            ])),
            "get_protocol" => self.cmd_get_protocol(),
            "register_integrity" => self.cmd_register_integrity(&params),
            "unregister_integrity" => {
                self.integrity_bridge.unregister();
                *self.integrity_name.lock().unwrap() = "default".into();
                Ok(json::obj(vec![("unregistered", json::b(true))]))
            }
            "integrity_status" => Ok(json::obj(vec![
                ("active", json::b(self.integrity_bridge.is_active())),
                ("strategy", json::s(self.integrity_bridge.name())),
            ])),
            "register_encryptor" => self.cmd_register_encryptor(&params),
            "unregister_encryptor" => {
                self.encryptor_bridge.unregister();
                *self.encryptor_name.lock().unwrap() = "null".into();
                Ok(json::obj(vec![("unregistered", json::b(true))]))
            }
            "encryptor_status" => Ok(json::obj(vec![
                ("active", json::b(self.encryptor_bridge.is_active())),
                ("name", json::s(self.encryptor_bridge.display_name())),
                (
                    "has_key",
                    json::b(self.encryptor_bridge.key_material().is_some()),
                ),
            ])),
            "register_mutator" => self.cmd_register_mutator(&params),
            "unregister_mutator" => {
                self.mutator_bridge.unregister();
                Ok(json::obj(vec![("unregistered", json::b(true))]))
            }
            "mutator_status" => Ok(json::obj(vec![
                ("active", json::b(self.mutator_bridge.is_active())),
                (
                    "dictionary_len",
                    json::n(self.mutator_bridge.dictionary_len() as f64),
                ),
                ("generation", json::n(self.mutator_bridge.generation() as f64)),
            ])),
            other => Err(format!("unknown method: {}", other)),
        };

        match result {
            Ok(val) => HandleOutcome::Response(success_response(id, val)),
            Err(e) => HandleOutcome::Response(error_response(id, &e)),
        }
    }

    fn stats_json(&self) -> JsonValue {
        let elapsed = self.started.elapsed().as_secs_f64();
        let execs = self.stats.execs.load(Ordering::Relaxed);
        let eps = if elapsed > 0.0 {
            execs as f64 / elapsed
        } else {
            0.0
        };
        json::obj(vec![
            ("execs", json::n(execs as f64)),
            ("crashes", json::n(self.stats.crashes.load(Ordering::Relaxed) as f64)),
            ("hangs", json::n(self.stats.hangs.load(Ordering::Relaxed) as f64)),
            ("new_paths", json::n(self.stats.new_paths.load(Ordering::Relaxed) as f64)),
            ("new_states", json::n(self.stats.new_states.load(Ordering::Relaxed) as f64)),
            ("corpus", json::n(self.corpus.len() as f64)),
            ("interesting", json::n(self.corpus.interesting_count() as f64)),
            ("tracker_states", json::n(self.tracker.state_count() as f64)),
            ("coverage_edges", json::n(self.coverage.total_edges() as f64)),
            ("coverage_provider", json::s(self.coverage.name())),
            ("execs_per_sec", json::n(eps)),
            ("elapsed_secs", json::n(elapsed)),
            ("stopped", json::b(self.stop.load(Ordering::Relaxed))),
            ("python_oracle", json::b(self.oracle_bridge.is_active())),
            ("python_protocol", json::b(self.protocol_bridge.is_active())),
            ("python_integrity", json::b(self.integrity_bridge.is_active())),
            ("python_encryptor", json::b(self.encryptor_bridge.is_active())),
            ("python_mutator", json::b(self.mutator_bridge.is_active())),
        ])
    }

    fn config_json(&self) -> JsonValue {
        json::obj(vec![
            ("target", json::s(&self.target_summary)),
            ("workers", json::n(self.workers as f64)),
            ("seed_dir", json::s(&self.seed_dir)),
            ("output_dir", json::s(&self.output_dir)),
            ("oracle", json::s(self.oracle_name.lock().unwrap().clone())),
            ("model", json::s(self.model_name.lock().unwrap().clone())),
            ("integrity", json::s(self.integrity_name.lock().unwrap().clone())),
            ("encryptor", json::s(self.encryptor_name.lock().unwrap().clone())),
            ("coverage", json::s(self.coverage.name())),
            ("python_oracle_active", json::b(self.oracle_bridge.is_active())),
            ("python_protocol_active", json::b(self.protocol_bridge.is_active())),
            ("python_integrity_active", json::b(self.integrity_bridge.is_active())),
            ("python_encryptor_active", json::b(self.encryptor_bridge.is_active())),
            ("python_mutator_active", json::b(self.mutator_bridge.is_active())),
        ])
    }

    fn cmd_load_seeds(&self, params: &JsonValue) -> Result<JsonValue, String> {
        let dir = params.get_str("dir").unwrap_or(&self.seed_dir).to_string();
        let seeds = load_seeds_from_dir(&dir, 1).map_err(|e| e.to_string())?;
        let added = self.corpus.add_seeds(seeds);
        Ok(json::obj(vec![
            ("dir", json::s(dir)),
            ("added", json::n(added as f64)),
            ("corpus", json::n(self.corpus.len() as f64)),
        ]))
    }

    fn cmd_add_seed_raw(&self, params: &JsonValue) -> Result<JsonValue, String> {
        let b64 = params
            .get_str("data_b64")
            .ok_or_else(|| "missing data_b64".to_string())?;
        let raw = b64_decode(b64).map_err(|e| format!("base64: {}", e))?;
        let name = params.get_str("name").unwrap_or("rpc_seed");
        let mut msg = Message::new(name);
        msg.add_field(Field::new("raw", FieldType::Binary, raw));
        let tc = TestCase::new(0, vec![msg]);
        match self.corpus.add_if_new(tc) {
            Some(id) => Ok(json::obj(vec![
                ("id", json::n(id as f64)),
                ("accepted", json::b(true)),
            ])),
            None => Ok(json::obj(vec![
                ("accepted", json::b(false)),
                ("reason", json::s("duplicate")),
            ])),
        }
    }

    fn cmd_add_seed_structured(&self, params: &JsonValue) -> Result<JsonValue, String> {
        let tc = testcase_from_structured(params)?;
        let nbytes = tc.serialize().len();
        let nmsg = tc.messages.len();
        match self.corpus.add_if_new(tc) {
            Some(id) => Ok(json::obj(vec![
                ("id", json::n(id as f64)),
                ("accepted", json::b(true)),
                ("messages", json::n(nmsg as f64)),
                ("bytes", json::n(nbytes as f64)),
            ])),
            None => Ok(json::obj(vec![
                ("accepted", json::b(false)),
                ("reason", json::s("duplicate")),
            ])),
        }
    }

    fn cmd_export_corpus(&self, params: &JsonValue) -> Result<JsonValue, String> {
        let dir = params
            .get_str("dir")
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}/queue", self.output_dir));
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let mut exported = 0u64;
        let len = self.corpus.len();
        for id in 1..=(len as u64 + 64) {
            if let Some(tc) = self.corpus.get(id) {
                let path = Path::new(&dir).join(format!("id_{:06}", id));
                if fs::write(&path, tc.serialize()).is_ok() {
                    exported += 1;
                }
            }
            if exported as usize >= len {
                break;
            }
        }
        Ok(json::obj(vec![
            ("dir", json::s(dir)),
            ("exported", json::n(exported as f64)),
        ]))
    }

    fn cmd_set_oracle(&self, params: &JsonValue) -> Result<JsonValue, String> {
        let name = params
            .get_str("name")
            .ok_or_else(|| "missing name".to_string())?
            .to_string();
        if name == "python" {
            return Err("use register_oracle to attach a Python is_interesting handler".into());
        }
        let oracle = resolve_oracle(Some(&name));
        let resolved = oracle.name().to_string();
        {
            let mut reg = self.plugins.lock().unwrap();
            reg.oracle = oracle;
        }
        *self.oracle_name.lock().unwrap() = resolved.clone();
        Ok(json::obj(vec![("oracle", json::s(resolved))]))
    }

    fn cmd_set_name(&self, params: &JsonValue, which: &str) -> Result<JsonValue, String> {
        let name = params
            .get_str("name")
            .ok_or_else(|| "missing name".to_string())?
            .to_string();
        match which {
            "model" => *self.model_name.lock().unwrap() = name.clone(),
            "integrity" => *self.integrity_name.lock().unwrap() = name.clone(),
            "encryptor" => *self.encryptor_name.lock().unwrap() = name.clone(),
            _ => {}
        }
        Ok(json::obj(vec![
            (which, json::s(name)),
            ("note", json::s("recorded; prefer register_* bridges for live effect")),
        ]))
    }

    fn cmd_register_protocol(&self, params: &JsonValue) -> Result<JsonValue, String> {
        let model = model_from_params(params)?;
        let name = model.name.clone();
        let dict_len = model.dictionary.len();
        self.protocol_bridge.register(model);
        *self.model_name.lock().unwrap() = format!("python:{}", name);
        Ok(json::obj(vec![
            ("registered", json::b(true)),
            ("name", json::s(name)),
            ("dictionary_len", json::n(dict_len as f64)),
            (
                "note",
                json::s("model active for new worker spawns; register before campaign start"),
            ),
        ]))
    }

    fn cmd_get_protocol(&self) -> Result<JsonValue, String> {
        match self.protocol_bridge.model() {
            None => Ok(json::obj(vec![("active", json::b(false))])),
            Some(m) => {
                let dict: Vec<JsonValue> = m
                    .dictionary
                    .iter()
                    .take(64)
                    .map(|b| match std::str::from_utf8(b) {
                        Ok(s) if s.chars().all(|c| !c.is_control() || c == '\r' || c == '\n') => {
                            json::obj(vec![("encoding", json::s("utf8")), ("data", json::s(s))])
                        }
                        _ => json::obj(vec![
                            ("encoding", json::s("base64")),
                            ("data", json::s(b64_encode(b))),
                        ]),
                    })
                    .collect();
                Ok(json::obj(vec![
                    ("active", json::b(true)),
                    ("name", json::s(m.name)),
                    ("dictionary", JsonValue::Array(dict)),
                    ("dictionary_len", json::n(m.dictionary.len() as f64)),
                    ("length_prefixed", json::b(m.length_prefixed)),
                    (
                        "delimiter",
                        match m.delimiter {
                            Some(d) => json::n(d as f64),
                            None => JsonValue::Null,
                        },
                    ),
                ]))
            }
        }
    }

    fn cmd_register_integrity(&self, params: &JsonValue) -> Result<JsonValue, String> {
        let raw = params
            .get_str("strategy")
            .or_else(|| params.get_str("name"))
            .ok_or_else(|| "missing strategy (or name)".to_string())?;
        let strategy = validate_strategy(raw)?;
        self.integrity_bridge.register(strategy.clone());
        *self.integrity_name.lock().unwrap() = format!("python:{}", strategy);
        Ok(json::obj(vec![
            ("registered", json::b(true)),
            ("strategy", json::s(strategy)),
            ("note", json::s("workers pick up strategy on next cycle (live, single repair owner)")),
        ]))
    }

    fn cmd_register_encryptor(&self, params: &JsonValue) -> Result<JsonValue, String> {
        let raw = params
            .get_str("name")
            .ok_or_else(|| "missing name".to_string())?;
        let name = validate_encryptor_name(raw)?;
        let key = params.get_str("key").map(|s| s.to_string());
        self.encryptor_bridge.register(name.clone(), key);
        *self.encryptor_name.lock().unwrap() = format!("python:{}", name);
        Ok(json::obj(vec![
            ("registered", json::b(true)),
            ("name", json::s(name)),
            ("has_key", json::b(params.get_str("key").is_some())),
            ("note", json::s("workers re-resolve encryptor on next cycle (live)")),
        ]))
    }

    fn cmd_register_mutator(&self, params: &JsonValue) -> Result<JsonValue, String> {
        let dict = dictionary_from_params(params)?;
        let extend = params
            .get("extend")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if extend {
            self.mutator_bridge.extend(dict);
        } else {
            self.mutator_bridge.register(dict);
        }
        Ok(json::obj(vec![
            ("registered", json::b(true)),
            ("dictionary_len", json::n(self.mutator_bridge.dictionary_len() as f64)),
            ("generation", json::n(self.mutator_bridge.generation() as f64)),
            (
                "note",
                json::s("extra dictionary merged live into worker mutators; no repair involvement"),
            ),
        ]))
    }
}

fn success_response(id: Option<JsonValue>, result: JsonValue) -> String {
    let mut m = std::collections::HashMap::new();
    if let Some(i) = id {
        m.insert("id".into(), i);
    }
    m.insert("ok".into(), JsonValue::Bool(true));
    m.insert("result".into(), result);
    json::stringify(&JsonValue::Object(m)) + "\n"
}

fn error_response(id: Option<JsonValue>, msg: &str) -> String {
    let mut m = std::collections::HashMap::new();
    if let Some(i) = id {
        m.insert("id".into(), i);
    }
    m.insert("ok".into(), JsonValue::Bool(false));
    m.insert("error".into(), json::s(msg));
    json::stringify(&JsonValue::Object(m)) + "\n"
}

fn b64_decode(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: i32 = 0;
    for c in input.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let val = TABLE
            .iter()
            .position(|&x| x == c as u8)
            .ok_or_else(|| format!("invalid base64 char: {}", c))? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn b64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    let rest = data.len() - i;
    if rest == 1 {
        let n = (data[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rest == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

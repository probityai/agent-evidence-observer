//! Versioned raw observation types for ExecSurface.
//!
//! Raw observations are backend evidence. PIDs/TIDs and syscall-oriented
//! details may appear here, while canonical identity is defined later.

use serde::{Deserialize, Serialize};

pub mod canonical;
pub mod semantics_v3;

pub const RAW_OBSERVATION_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub schema_version: u32,
    pub backend: BackendMetadata,
    pub complete: bool,
    pub outcome: CommandOutcome,
    pub events: Vec<RawEvent>,
    pub warnings: Vec<ObserverWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendMetadata {
    pub name: String,
    pub platform: String,
    pub architecture: String,
    pub capabilities: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CommandOutcome {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEvent {
    pub sequence: u64,
    pub tid: i32,
    #[serde(flatten)]
    pub kind: RawEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum RawEventKind {
    ProcessSpawn {
        child_tid: i32,
        mechanism: SpawnMechanism,
    },
    ProcessExec {
        path: String,
    },
    FilePathAccess {
        operation: FileOperation,
        path: String,
        flags: Option<u64>,
    },
    FileOpenAt2 {
        path: String,
        flags: u64,
        resolve: u64,
    },
    FileDescriptorAccess {
        operation: FileOperation,
        fd: i32,
        path: String,
    },
    FileRename {
        from: String,
        to: String,
    },
    NetworkConnectAttempt {
        endpoint: NetworkEndpoint,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnMechanism {
    Fork,
    Vfork,
    Clone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperation {
    Open,
    Create,
    Delete,
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "address_family", rename_all = "snake_case")]
pub enum NetworkEndpoint {
    Inet { ip: String, port: u16 },
    Inet6 { ip: String, port: u16 },
    Unix { path: Option<String> },
    Other { family: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverWarning {
    pub code: String,
    pub tid: Option<i32>,
    pub message: String,
}

impl Observation {
    pub fn empty(backend: BackendMetadata) -> Self {
        Self {
            schema_version: RAW_OBSERVATION_SCHEMA_VERSION,
            backend,
            complete: true,
            outcome: CommandOutcome::default(),
            events: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

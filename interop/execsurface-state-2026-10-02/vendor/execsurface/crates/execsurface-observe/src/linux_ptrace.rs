use std::collections::HashMap;
use std::ffi::c_void;
use std::fs;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::ptr;

use execsurface_model::{
    BackendMetadata, CommandOutcome, FileOperation, NetworkEndpoint, Observation, ObserverWarning,
    RawEvent, RawEventKind, SpawnMechanism,
};

use crate::{CommandSpec, ObserveError, ObserveOptions};

const MAX_PATH_BYTES: usize = 4096;
const MAX_SOCKADDR_BYTES: usize = 128;
const OPEN_HOW_BYTES: usize = 24;
const PTRACE_GET_SYSCALL_INFO_REQUEST: libc::c_uint = 0x420e;
const PTRACE_SYSCALL_INFO_ENTRY: u8 = 1;
const PTRACE_SYSCALL_INFO_EXIT: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct PtraceSyscallInfo {
    op: u8,
    pad: [u8; 3],
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    data: [u64; 7],
}

impl PtraceSyscallInfo {
    fn entry(&self) -> Option<(u64, [u64; 6])> {
        if self.op != PTRACE_SYSCALL_INFO_ENTRY {
            return None;
        }
        Some((
            self.data[0],
            [
                self.data[1],
                self.data[2],
                self.data[3],
                self.data[4],
                self.data[5],
                self.data[6],
            ],
        ))
    }

    fn exit(&self) -> Option<i64> {
        (self.op == PTRACE_SYSCALL_INFO_EXIT).then_some(self.data[0] as i64)
    }
}

#[derive(Debug, Clone)]
struct FdEntry {
    path: String,
    cloexec: bool,
}

#[derive(Debug, Clone)]
enum PendingSyscall {
    Open {
        cloexec: bool,
    },
    Io {
        operation: FileOperation,
        fd: i32,
    },
    IoPair {
        read_fd: i32,
        write_fd: i32,
    },
    Close {
        fd: i32,
    },
    CloseRange {
        first: u32,
        last: u32,
    },
    Dup {
        old_fd: i32,
        cloexec: bool,
    },
    DupTo {
        old_fd: i32,
        new_fd: i32,
        cloexec: bool,
    },
    SetFdFlags {
        fd: i32,
        flags: i32,
    },
    Rename {
        from: String,
        to: String,
    },
    Clone {
        flags: u64,
    },
}

#[derive(Debug, Clone)]
struct TraceeState {
    pending_exec: Option<String>,
    pending_syscall: Option<PendingSyscall>,
    newborn: bool,
    fd_table_id: u64,
    tgid: libc::pid_t,
    retired_by_exec: bool,
    restart_esrch_seen: bool,
    exit_event_status: Option<libc::c_int>,
    exit_group_pending: bool,
    syscall_info_esrch_after_exit_group: bool,
}

impl TraceeState {
    fn root(fd_table_id: u64, tgid: libc::pid_t) -> Self {
        Self {
            pending_exec: None,
            pending_syscall: None,
            newborn: false,
            fd_table_id,
            tgid,
            retired_by_exec: false,
            restart_esrch_seen: false,
            exit_event_status: None,
            exit_group_pending: false,
            syscall_info_esrch_after_exit_group: false,
        }
    }

    fn child(fd_table_id: u64, tgid: libc::pid_t) -> Self {
        Self {
            pending_exec: None,
            pending_syscall: None,
            newborn: true,
            fd_table_id,
            tgid,
            retired_by_exec: false,
            restart_esrch_seen: false,
            exit_event_status: None,
            exit_group_pending: false,
            syscall_info_esrch_after_exit_group: false,
        }
    }
}

struct FdTables {
    tables: HashMap<u64, HashMap<i32, FdEntry>>,
    next_id: u64,
}

impl FdTables {
    fn new() -> Self {
        let mut tables = HashMap::new();
        tables.insert(1, HashMap::new());
        Self { tables, next_id: 2 }
    }

    fn root_id(&self) -> u64 {
        1
    }

    fn clone_table(&mut self, id: u64) -> u64 {
        let table = self.tables.get(&id).cloned().unwrap_or_default();
        self.insert_table(table)
    }

    fn insert_table(&mut self, table: HashMap<i32, FdEntry>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.tables.insert(id, table);
        id
    }

    fn insert_fd(&mut self, table_id: u64, fd: i32, entry: FdEntry) {
        self.tables.entry(table_id).or_default().insert(fd, entry);
    }

    fn remove_fd(&mut self, table_id: u64, fd: i32) {
        if let Some(table) = self.tables.get_mut(&table_id) {
            table.remove(&fd);
        }
    }

    fn close_range(&mut self, table_id: u64, first: u32, last: u32) {
        if let Some(table) = self.tables.get_mut(&table_id) {
            table.retain(|fd, _| {
                let fd = *fd as u32;
                fd < first || fd > last
            });
        }
    }

    fn fd(&self, table_id: u64, fd: i32) -> Option<&FdEntry> {
        self.tables.get(&table_id)?.get(&fd)
    }

    fn duplicate(&mut self, table_id: u64, old_fd: i32, new_fd: i32, cloexec: bool) {
        let Some(mut entry) = self.fd(table_id, old_fd).cloned() else {
            return;
        };
        entry.cloexec = cloexec;
        self.insert_fd(table_id, new_fd, entry);
    }

    fn set_cloexec(&mut self, table_id: u64, fd: i32, cloexec: bool) {
        if let Some(entry) = self
            .tables
            .get_mut(&table_id)
            .and_then(|table| table.get_mut(&fd))
        {
            entry.cloexec = cloexec;
        }
    }

    fn rename_paths(&mut self, from: &str, to: &str) {
        for table in self.tables.values_mut() {
            for entry in table.values_mut() {
                if entry.path == from {
                    entry.path = to.to_owned();
                } else if let Some(suffix) = entry
                    .path
                    .strip_prefix(from)
                    .filter(|suffix| suffix.starts_with('/'))
                {
                    entry.path = format!("{to}{suffix}");
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct CloneFdCertification {
    clone_events: u64,
    correlated_clone_flags: u64,
    shared_fd_transitions: u64,
    cloned_fd_transitions: u64,
    clone_thread_transitions: u64,
    clone_origin_fork_events: u64,
    clone_origin_vfork_events: u64,
    ambiguity: bool,
}

impl CloneFdCertification {
    fn record_clone(&mut self, flags: Option<u64>) {
        self.clone_events += 1;
        let Some(flags) = flags else {
            self.ambiguity = true;
            return;
        };

        self.correlated_clone_flags += 1;
        if flags & libc::CLONE_FILES as u64 != 0 {
            self.shared_fd_transitions += 1;
        } else {
            self.cloned_fd_transitions += 1;
        }
        if flags & libc::CLONE_THREAD as u64 != 0 {
            self.clone_thread_transitions += 1;
        }
    }

    fn record_clone_creation_event(&mut self, flags: Option<u64>, event: libc::c_int) {
        self.record_clone(flags);
        if event == libc::PTRACE_EVENT_FORK {
            self.clone_origin_fork_events += 1;
        } else if event == libc::PTRACE_EVENT_VFORK {
            self.clone_origin_vfork_events += 1;
        }
    }

    fn invalidate(&mut self) {
        self.ambiguity = true;
    }

    pub(super) fn fully_certified(&self) -> bool {
        !self.ambiguity
            && self.clone_events == self.correlated_clone_flags
            && self.clone_events == self.shared_fd_transitions + self.cloned_fd_transitions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PtraceObservation {
    pub(super) observation: Observation,
    pub(super) clone_fd_certification: CloneFdCertification,
}

struct Collector {
    observation: Observation,
    sequence: u64,
    event_limit: usize,
    event_limit_reported: bool,
    clone_fd_certification: CloneFdCertification,
}

impl Collector {
    fn new(event_limit: usize) -> Self {
        let backend = BackendMetadata {
            name: "linux-ptrace-metadata-v2".to_owned(),
            platform: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            capabilities: vec![
                "descendant_tracking".to_owned(),
                "exec_path".to_owned(),
                "path_syscall_attempts".to_owned(),
                "trace_time_dirfd_resolution".to_owned(),
                "openat2_metadata".to_owned(),
                "fd_read_write_attribution".to_owned(),
                "fd_dup_close_lifecycle".to_owned(),
                "clone_files_fd_sharing".to_owned(),
                "close_on_exec_tracking".to_owned(),
                "connect_destination".to_owned(),
                "fail_closed_event_budget".to_owned(),
            ],
            limitations: vec![
                "selected syscall metadata only; memory-mapped I/O and io_uring data access are not attributed"
                    .to_owned(),
                "file open/create/delete/rename records are syscall attempts; fd read/write records require successful positive-byte I/O"
                    .to_owned(),
                "kernel fd paths are runtime object evidence, not causal source-code provenance"
                    .to_owned(),
                "ptrace can perturb scheduling and trace-aware programs can behave differently".to_owned(),
                "hostname intent is not inferred from connect(2)".to_owned(),
                "Linux x86_64 only".to_owned(),
                format!("observation event budget is {event_limit}; overflow marks evidence incomplete"),
                "observation sessions are serialized within one host process to avoid cross-reaping ptrace children"
                    .to_owned(),
            ],
        };
        Self {
            observation: Observation::empty(backend),
            sequence: 0,
            event_limit,
            event_limit_reported: false,
            clone_fd_certification: CloneFdCertification::default(),
        }
    }

    fn event(&mut self, tid: libc::pid_t, kind: RawEventKind) {
        if self.observation.events.len() >= self.event_limit {
            if !self.event_limit_reported {
                self.event_limit_reported = true;
                self.warning(
                    tid,
                    "event_limit_exceeded",
                    format!(
                        "observer event budget {} exceeded; evidence is truncated",
                        self.event_limit
                    ),
                );
            }
            return;
        }
        self.sequence += 1;
        self.observation.events.push(RawEvent {
            sequence: self.sequence,
            tid,
            kind,
        });
    }

    fn warning(&mut self, tid: libc::pid_t, code: &str, message: impl Into<String>) {
        self.observation.complete = false;
        if matches!(
            code,
            "clone_flags_unavailable" | "clone3_flags_unreadable" | "syscall_pairing_lost"
        ) {
            self.clone_fd_certification.invalidate();
        }
        self.observation.warnings.push(ObserverWarning {
            code: code.to_owned(),
            tid: Some(tid),
            message: message.into(),
        });
    }
}

pub(super) fn observe(
    spec: &CommandSpec,
    options: ObserveOptions,
) -> Result<PtraceObservation, ObserveError> {
    let (program, argv) = spec.c_argv()?;
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(ptr::null());

    // SAFETY: after fork, the child uses only libc tracing/signal/exec/exit calls.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error().into());
    }

    if child == 0 {
        // SAFETY: child-only path before exec.
        unsafe {
            if libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                ptr::null_mut::<c_void>(),
                ptr::null_mut::<c_void>(),
            ) == -1
            {
                libc::_exit(126);
            }
            if libc::raise(libc::SIGSTOP) != 0 {
                libc::_exit(126);
            }
            libc::execvp(program.as_ptr(), argv_ptrs.as_ptr());
            libc::_exit(127);
        }
    }

    trace_parent(child, options)
}

fn trace_parent(
    root: libc::pid_t,
    options: ObserveOptions,
) -> Result<PtraceObservation, ObserveError> {
    let mut status = 0;
    if unsafe { libc::waitpid(root, &mut status, 0) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if !libc::WIFSTOPPED(status) {
        return Err(ObserveError::Protocol(
            "tracee did not enter the expected initial stop".to_owned(),
        ));
    }

    let options_mask = libc::PTRACE_O_TRACESYSGOOD
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEEXIT
        | libc::PTRACE_O_EXITKILL;

    ptrace_call(
        libc::PTRACE_SETOPTIONS,
        root,
        ptr::null_mut(),
        options_mask as usize as *mut c_void,
    )?;

    let mut fd_tables = FdTables::new();
    let mut tracees = HashMap::new();
    tracees.insert(root, TraceeState::root(fd_tables.root_id(), root));
    let mut preregistration_stops: HashMap<libc::pid_t, libc::c_int> = HashMap::new();

    let mut collector = Collector::new(options.event_limit);
    let mut root_outcome = CommandOutcome::default();

    resume_syscall(root, 0)?;

    while !tracees.is_empty() || !preregistration_stops.is_empty() {
        let mut wait_status = 0;
        let tid = unsafe { libc::waitpid(-1, &mut wait_status, libc::__WALL) };
        if tid < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD)
                && tracees.is_empty()
                && preregistration_stops.is_empty()
            {
                break;
            }
            if error.raw_os_error() == Some(libc::ECHILD) && !preregistration_stops.is_empty() {
                let mut pending = preregistration_stops.keys().copied().collect::<Vec<_>>();
                pending.sort_unstable();
                return Err(ObserveError::Protocol(format!(
                    "M9_PREREGISTRATION_STOPS_AT_ECHILD pending_tids={pending:?}"
                )));
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                let mut unresolved = tracees
                    .iter()
                    .filter_map(|(tid, state)| {
                        state.exit_event_status.is_none().then_some((
                            *tid,
                            state.tgid,
                            state.retired_by_exec,
                            state.restart_esrch_seen,
                            state.exit_group_pending,
                            state.syscall_info_esrch_after_exit_group,
                        ))
                    })
                    .collect::<Vec<_>>();
                unresolved.sort_unstable_by_key(|entry| entry.0);
                if !unresolved.is_empty() {
                    return Err(ObserveError::Protocol(format!(
                        "M9_STALE_TRACEES_WITHOUT_EXIT_EVIDENCE_AT_ECHILD tracked={unresolved:?}"
                    )));
                }

                let mut reconciled = tracees
                    .iter()
                    .map(|(tid, state)| {
                        (
                            *tid,
                            state.tgid,
                            state.retired_by_exec,
                            state.restart_esrch_seen,
                            state.exit_group_pending,
                            state.syscall_info_esrch_after_exit_group,
                            state.exit_event_status.unwrap(),
                        )
                    })
                    .collect::<Vec<_>>();
                reconciled.sort_unstable_by_key(|entry| entry.0);
                for (stale_tid, _, _, _, _, _, exit_status) in &reconciled {
                    if !apply_terminal_outcome(root, *stale_tid, *exit_status, &mut root_outcome) {
                        return Err(ObserveError::Protocol(format!(
                            "M9_EXIT_EVENT_STATUS_NONTERMINAL_AT_ECHILD tid={stale_tid} status={exit_status:#x}"
                        )));
                    }
                }
                tracees.clear();
                break;
            }
            return Err(error.into());
        }

        if (libc::WIFEXITED(wait_status) || libc::WIFSIGNALED(wait_status))
            && !tracees.contains_key(&tid)
        {
            return Err(ObserveError::Protocol(format!(
                "M9_UNTRACKED_TERMINAL_WAIT tid={tid} status={wait_status:#x}"
            )));
        }

        if record_terminal_wait_status(root, tid, wait_status, &mut tracees, &mut root_outcome) {
            continue;
        }

        if !libc::WIFSTOPPED(wait_status) {
            continue;
        }

        let stop_signal = libc::WSTOPSIG(wait_status);
        let event = ((wait_status as u32) >> 16) as libc::c_int;

        if !tracees.contains_key(&tid) {
            if stop_signal != libc::SIGSTOP || event != 0 {
                return Err(ObserveError::Protocol(format!(
                    "M9_UNEXPECTED_STOP_BEFORE_REGISTRATION tid={tid} signal={stop_signal} event={event} status={wait_status:#x}"
                )));
            }
            if preregistration_stops.insert(tid, wait_status).is_some() {
                return Err(ObserveError::Protocol(format!(
                    "M9_DUPLICATE_PREREGISTRATION_STOP tid={tid}"
                )));
            }
            continue;
        }

        if tracees
            .get(&tid)
            .map(|state| state.retired_by_exec)
            .unwrap_or(false)
            && !(stop_signal == libc::SIGTRAP && event == libc::PTRACE_EVENT_EXIT)
        {
            return Err(ObserveError::Protocol(format!(
                "M9_RETIRED_EXEC_UNEXPECTED_STOP tid={tid} signal={stop_signal} event={event}"
            )));
        }

        if stop_signal == libc::SIGTRAP && event != 0 {
            handle_ptrace_event(
                tid,
                event,
                &mut tracees,
                &mut preregistration_stops,
                &mut fd_tables,
                &mut collector,
            )?;
            resume_after_observed_stop(root, tid, 0, &mut tracees, &mut root_outcome)?;
            continue;
        }

        if stop_signal == (libc::SIGTRAP | 0x80) {
            let info = match syscall_info(tid) {
                Ok(info) => info,
                Err(ObserveError::Os(error)) if error.raw_os_error() == Some(libc::ESRCH) => {
                    let recoverable = tracees
                        .get(&tid)
                        .map(|state| {
                            state.exit_group_pending
                                && state.pending_syscall.is_none()
                                && !state.retired_by_exec
                                && state.exit_event_status.is_none()
                        })
                        .unwrap_or(false);
                    if !recoverable {
                        return Err(ObserveError::Protocol(format!(
                            "PTRACE_GET_SYSCALL_INFO returned ESRCH for tid {tid} without bounded exit-group lifecycle evidence"
                        )));
                    }
                    let state = tracees.get_mut(&tid).ok_or_else(|| {
                        ObserveError::Protocol(format!(
                            "bounded GET_SYSCALL_INFO ESRCH recovery lost tracked tid {tid}"
                        ))
                    })?;
                    state.syscall_info_esrch_after_exit_group = true;
                    /*
                     * The kernel has already refused a ptrace read while the
                     * same thread group is in an explicitly observed
                     * exit_group teardown. Do not fabricate syscall phase
                     * information and do not restart the dying thread here.
                     * Its subsequent PTRACE_EVENT_EXIT / terminal wait remains
                     * responsible for lifecycle completion.
                     */
                    continue;
                }
                Err(error) => return Err(error),
            };
            if let Some((nr, args)) = info.entry() {
                handle_syscall_entry(tid, nr, args, &mut tracees, &mut collector);
            } else if let Some(result) = info.exit() {
                handle_syscall_exit(tid, result, &mut tracees, &mut fd_tables, &mut collector);
            }
            resume_after_observed_stop(root, tid, 0, &mut tracees, &mut root_outcome)?;
            continue;
        }

        let suppress_signal = match tracees.get_mut(&tid) {
            Some(state) if state.newborn => {
                state.newborn = false;
                true
            }
            _ => stop_signal == libc::SIGTRAP,
        };

        resume_after_observed_stop(
            root,
            tid,
            if suppress_signal { 0 } else { stop_signal },
            &mut tracees,
            &mut root_outcome,
        )?;
    }

    collector.observation.outcome = root_outcome;
    Ok(PtraceObservation {
        observation: collector.observation,
        clone_fd_certification: collector.clone_fd_certification,
    })
}

fn apply_terminal_outcome(
    root: libc::pid_t,
    tid: libc::pid_t,
    wait_status: libc::c_int,
    root_outcome: &mut CommandOutcome,
) -> bool {
    if libc::WIFEXITED(wait_status) {
        if tid == root {
            root_outcome.exit_code = Some(libc::WEXITSTATUS(wait_status));
        }
        return true;
    }

    if libc::WIFSIGNALED(wait_status) {
        if tid == root {
            root_outcome.signal = Some(libc::WTERMSIG(wait_status));
        }
        return true;
    }

    false
}

fn record_terminal_wait_status(
    root: libc::pid_t,
    tid: libc::pid_t,
    wait_status: libc::c_int,
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
    root_outcome: &mut CommandOutcome,
) -> bool {
    if apply_terminal_outcome(root, tid, wait_status, root_outcome) {
        tracees.remove(&tid);
        return true;
    }
    false
}

fn resume_after_observed_stop(
    _root: libc::pid_t,
    tid: libc::pid_t,
    signal: libc::c_int,
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
    _root_outcome: &mut CommandOutcome,
) -> Result<(), ObserveError> {
    match resume_syscall(tid, signal) {
        Ok(()) => Ok(()),
        Err(ObserveError::Os(resume_error)) if resume_error.raw_os_error() == Some(libc::ESRCH) => {
            let state = tracees.get_mut(&tid).ok_or_else(|| {
                ObserveError::Protocol(format!("M9_RESTART_ESRCH_FOR_UNTRACKED_TID tid={tid}"))
            })?;
            state.restart_esrch_seen = true;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn handle_ptrace_event(
    tid: libc::pid_t,
    event: libc::c_int,
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
    preregistration_stops: &mut HashMap<libc::pid_t, libc::c_int>,
    fd_tables: &mut FdTables,
    collector: &mut Collector,
) -> Result<(), ObserveError> {
    match event {
        libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE => {
            let child_tid = get_event_message(tid)? as libc::pid_t;
            // C2/C3: the originating syscall is stronger evidence than the ptrace
            // event label. Linux may report a clone-origin child as FORK/VFORK
            // depending on clone flags / exit signal. Preserve the pending clone
            // flags whenever they exist, regardless of event label.
            let pending_clone_flags = tracees
                .get(&tid)
                .and_then(|state| state.pending_syscall.as_ref())
                .and_then(|pending| match pending {
                    PendingSyscall::Clone { flags } => Some(*flags),
                    _ => None,
                });
            let clone_origin = pending_clone_flags.is_some();

            // Preserve public raw-v2 ProcessSpawn semantics: mechanism remains
            // event-label based. Syscall-origin truth is retained separately in the
            // internal completeness certificate and must not silently reinterpret v2.
            let mechanism = match event {
                libc::PTRACE_EVENT_FORK => SpawnMechanism::Fork,
                libc::PTRACE_EVENT_VFORK => SpawnMechanism::Vfork,
                _ => SpawnMechanism::Clone,
            };

            let parent_table = tracees
                .get(&tid)
                .map(|state| state.fd_table_id)
                .unwrap_or(fd_tables.root_id());
            let parent_tgid = tracees.get(&tid).map(|state| state.tgid).unwrap_or(tid);
            let clone_flags = if clone_origin {
                pending_clone_flags
            } else if event == libc::PTRACE_EVENT_CLONE {
                collector.warning(
                    tid,
                    "clone_flags_unavailable",
                    "PTRACE child-creation event requires clone/clone3 origin flags, but no causally paired clone syscall was retained; fd sharing and thread-group semantics are incomplete",
                );
                None
            } else {
                None
            };

            if clone_origin || event == libc::PTRACE_EVENT_CLONE {
                collector
                    .clone_fd_certification
                    .record_clone_creation_event(clone_flags, event);
            }

            let share_files = clone_flags
                .map(|flags| flags & libc::CLONE_FILES as u64 != 0)
                .unwrap_or(false);
            let child_tgid = if clone_flags
                .map(|flags| flags & libc::CLONE_THREAD as u64 != 0)
                .unwrap_or(false)
            {
                parent_tgid
            } else {
                child_tid
            };

            let child_table = if share_files {
                parent_table
            } else {
                fd_tables.clone_table(parent_table)
            };

            tracees
                .entry(child_tid)
                .or_insert_with(|| TraceeState::child(child_table, child_tgid));

            if let Some(buffered_status) = preregistration_stops.remove(&child_tid) {
                let buffered_signal = libc::WSTOPSIG(buffered_status);
                let buffered_event = ((buffered_status as u32) >> 16) as libc::c_int;
                if !libc::WIFSTOPPED(buffered_status)
                    || buffered_signal != libc::SIGSTOP
                    || buffered_event != 0
                {
                    return Err(ObserveError::Protocol(format!(
                        "M9_INVALID_BUFFERED_PREREGISTRATION_STOP tid={child_tid} signal={buffered_signal} event={buffered_event} status={buffered_status:#x}"
                    )));
                }
                let child_state = tracees.get_mut(&child_tid).ok_or_else(|| {
                    ObserveError::Protocol(format!(
                        "M9_REGISTERED_CHILD_STATE_MISSING tid={child_tid}"
                    ))
                })?;
                child_state.newborn = false;
                resume_syscall(child_tid, 0)?;
            }

            collector.event(
                tid,
                RawEventKind::ProcessSpawn {
                    child_tid,
                    mechanism,
                },
            );
        }
        libc::PTRACE_EVENT_EXEC => {
            let former_tid = get_event_message(tid)? as libc::pid_t;
            let mut state = if former_tid == tid {
                tracees.remove(&tid).ok_or_else(|| {
                    ObserveError::Protocol(format!(
                        "PTRACE_EVENT_EXEC arrived for untracked tid {tid}"
                    ))
                })?
            } else {
                let execing = tracees.remove(&former_tid).ok_or_else(|| {
                    ObserveError::Protocol(format!(
                        "PTRACE_EVENT_EXEC remapped tid {former_tid} -> {tid}, but former tid was not tracked"
                    ))
                })?;
                if let Some(displaced_leader) = tracees.remove(&tid) {
                    if displaced_leader.tgid != execing.tgid {
                        return Err(ObserveError::Protocol(format!(
                            "PTRACE_EVENT_EXEC identity conflict former_tid={former_tid} new_tid={tid} former_tgid={} displaced_tgid={}",
                            execing.tgid, displaced_leader.tgid
                        )));
                    }
                }
                execing
            };

            let old_tgid = state.tgid;
            let mut retired = Vec::new();
            for (other_tid, other_state) in tracees.iter_mut() {
                if other_state.tgid == old_tgid {
                    other_state.retired_by_exec = true;
                    other_state.pending_exec = None;
                    other_state.pending_syscall = None;
                    retired.push(*other_tid);
                }
            }
            retired.sort_unstable();

            state.tgid = tid;
            state.newborn = false;
            state.retired_by_exec = false;
            state.restart_esrch_seen = false;
            state.exit_event_status = None;
            state.exit_group_pending = false;
            state.syscall_info_esrch_after_exit_group = false;
            tracees.insert(tid, state);

            apply_exec_fd_semantics(tid, tracees, fd_tables);
            let state = tracees.get_mut(&tid).ok_or_else(|| {
                ObserveError::Protocol(format!(
                    "PTRACE_EVENT_EXEC lost reconciled state for tid {tid}"
                ))
            })?;
            match state.pending_exec.take() {
                Some(path) => collector.event(tid, RawEventKind::ProcessExec { path }),
                None => collector.warning(
                    tid,
                    "exec_without_path",
                    "PTRACE_EVENT_EXEC was observed without a readable pending exec pathname",
                ),
            }
        }
        libc::PTRACE_EVENT_EXIT => {
            let exit_status = get_event_message(tid)? as libc::c_int;
            let state = tracees.get_mut(&tid).ok_or_else(|| {
                ObserveError::Protocol(format!("PTRACE_EVENT_EXIT arrived for untracked tid {tid}"))
            })?;
            state.exit_event_status = Some(exit_status);
        }
        _ => {}
    }
    Ok(())
}

fn apply_exec_fd_semantics(
    tid: libc::pid_t,
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
    fd_tables: &mut FdTables,
) {
    let Some(old_id) = tracees.get(&tid).map(|state| state.fd_table_id) else {
        return;
    };
    let users = tracees
        .values()
        .filter(|state| state.fd_table_id == old_id)
        .count();

    let mut table = fd_tables.tables.get(&old_id).cloned().unwrap_or_default();
    table.retain(|_, entry| !entry.cloexec);

    if users > 1 {
        let new_id = fd_tables.insert_table(table);
        if let Some(state) = tracees.get_mut(&tid) {
            state.fd_table_id = new_id;
        }
    } else {
        fd_tables.tables.insert(old_id, table);
    }
}

fn handle_syscall_entry(
    tid: libc::pid_t,
    nr: u64,
    args: [u64; 6],
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
    collector: &mut Collector,
) {
    if tracees
        .get(&tid)
        .and_then(|state| state.pending_syscall.as_ref())
        .is_some()
    {
        collector.warning(
            tid,
            "syscall_pairing_lost",
            "new syscall entry arrived before the previous selected syscall exit was paired",
        );
        if let Some(state) = tracees.get_mut(&tid) {
            state.pending_syscall = None;
        }
    }

    let nr = nr as libc::c_long;

    if nr == libc::SYS_exit_group {
        let tgid = tracees.get(&tid).map(|state| state.tgid).unwrap_or(tid);
        for state in tracees.values_mut() {
            if state.tgid == tgid {
                state.exit_group_pending = true;
            }
        }
    }

    if nr == libc::SYS_execve {
        record_exec_path(tid, libc::AT_FDCWD, args[0], tracees, collector);
        return;
    }
    if nr == libc::SYS_execveat {
        record_exec_path(tid, args[0] as i32, args[1], tracees, collector);
        return;
    }

    if nr == libc::SYS_open {
        record_open_entry(
            tid,
            libc::AT_FDCWD,
            FileOperation::Open,
            args[0],
            args[1],
            0,
            false,
            tracees,
            collector,
        );
        return;
    }
    if nr == libc::SYS_openat {
        record_open_entry(
            tid,
            args[0] as i32,
            FileOperation::Open,
            args[1],
            args[2],
            0,
            false,
            tracees,
            collector,
        );
        return;
    }
    if nr == libc::SYS_openat2 {
        match read_open_how(tid, args[2], args[3]) {
            Ok((flags, resolve)) => record_open_entry(
                tid,
                args[0] as i32,
                FileOperation::Open,
                args[1],
                flags,
                resolve,
                true,
                tracees,
                collector,
            ),
            Err(error) => collector.warning(tid, "openat2_how_unreadable", error.to_string()),
        }
        return;
    }
    if nr == libc::SYS_creat {
        let flags = (libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC) as u64;
        record_open_entry(
            tid,
            libc::AT_FDCWD,
            FileOperation::Create,
            args[0],
            flags,
            0,
            false,
            tracees,
            collector,
        );
        return;
    }

    if nr == libc::SYS_unlink {
        record_file_attempt(
            tid,
            libc::AT_FDCWD,
            FileOperation::Delete,
            args[0],
            None,
            collector,
        );
        return;
    }
    if nr == libc::SYS_unlinkat {
        record_file_attempt(
            tid,
            args[0] as i32,
            FileOperation::Delete,
            args[1],
            Some(args[2]),
            collector,
        );
        return;
    }

    if nr == libc::SYS_rename {
        record_rename_entry(
            tid,
            libc::AT_FDCWD,
            args[0],
            libc::AT_FDCWD,
            args[1],
            tracees,
            collector,
        );
        return;
    }
    if nr == libc::SYS_renameat || nr == libc::SYS_renameat2 {
        record_rename_entry(
            tid,
            args[0] as i32,
            args[1],
            args[2] as i32,
            args[3],
            tracees,
            collector,
        );
        return;
    }

    if is_read_syscall(nr) {
        set_pending(
            tracees,
            tid,
            PendingSyscall::Io {
                operation: FileOperation::Read,
                fd: args[0] as i32,
            },
        );
        return;
    }
    if is_write_syscall(nr) {
        set_pending(
            tracees,
            tid,
            PendingSyscall::Io {
                operation: FileOperation::Write,
                fd: args[0] as i32,
            },
        );
        return;
    }

    if nr == libc::SYS_sendfile {
        set_pending(
            tracees,
            tid,
            PendingSyscall::IoPair {
                read_fd: args[1] as i32,
                write_fd: args[0] as i32,
            },
        );
        return;
    }
    if nr == libc::SYS_copy_file_range {
        set_pending(
            tracees,
            tid,
            PendingSyscall::IoPair {
                read_fd: args[0] as i32,
                write_fd: args[2] as i32,
            },
        );
        return;
    }

    if nr == libc::SYS_close {
        set_pending(tracees, tid, PendingSyscall::Close { fd: args[0] as i32 });
        return;
    }
    if nr == libc::SYS_close_range {
        set_pending(
            tracees,
            tid,
            PendingSyscall::CloseRange {
                first: args[0] as u32,
                last: args[1] as u32,
            },
        );
        return;
    }

    if nr == libc::SYS_dup {
        set_pending(
            tracees,
            tid,
            PendingSyscall::Dup {
                old_fd: args[0] as i32,
                cloexec: false,
            },
        );
        return;
    }
    if nr == libc::SYS_dup2 {
        set_pending(
            tracees,
            tid,
            PendingSyscall::DupTo {
                old_fd: args[0] as i32,
                new_fd: args[1] as i32,
                cloexec: false,
            },
        );
        return;
    }
    if nr == libc::SYS_dup3 {
        set_pending(
            tracees,
            tid,
            PendingSyscall::DupTo {
                old_fd: args[0] as i32,
                new_fd: args[1] as i32,
                cloexec: args[2] as i32 & libc::O_CLOEXEC != 0,
            },
        );
        return;
    }

    if nr == libc::SYS_fcntl {
        let command = args[1] as i32;
        if command == libc::F_DUPFD || command == libc::F_DUPFD_CLOEXEC {
            set_pending(
                tracees,
                tid,
                PendingSyscall::Dup {
                    old_fd: args[0] as i32,
                    cloexec: command == libc::F_DUPFD_CLOEXEC,
                },
            );
        } else if command == libc::F_SETFD {
            set_pending(
                tracees,
                tid,
                PendingSyscall::SetFdFlags {
                    fd: args[0] as i32,
                    flags: args[2] as i32,
                },
            );
        }
        return;
    }

    if nr == libc::SYS_clone {
        set_pending(tracees, tid, PendingSyscall::Clone { flags: args[0] });
        return;
    }
    if nr == libc::SYS_clone3 {
        match read_clone3_flags(tid, args[0], args[1]) {
            Ok(flags) => set_pending(tracees, tid, PendingSyscall::Clone { flags }),
            Err(error) => collector.warning(tid, "clone3_flags_unreadable", error.to_string()),
        }
        return;
    }

    if nr == libc::SYS_connect {
        record_connect(tid, args[1], args[2], collector);
    }
}

fn handle_syscall_exit(
    tid: libc::pid_t,
    result: i64,
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
    fd_tables: &mut FdTables,
    collector: &mut Collector,
) {
    let Some(pending) = tracees
        .get_mut(&tid)
        .and_then(|state| state.pending_syscall.take())
    else {
        return;
    };
    let Some(table_id) = tracees.get(&tid).map(|state| state.fd_table_id) else {
        return;
    };

    match pending {
        PendingSyscall::Open { cloexec } if result >= 0 => {
            let fd = result as i32;
            match proc_fd_path(tid, fd) {
                Ok(path) => fd_tables.insert_fd(table_id, fd, FdEntry { path, cloexec }),
                Err(error) => collector.warning(
                    tid,
                    "opened_fd_path_unreadable",
                    format!("successful open returned fd {fd}, but its kernel fd path was unreadable: {error}"),
                ),
            }
        }
        PendingSyscall::Io { operation, fd } if result > 0 => {
            emit_fd_access(tid, table_id, fd, operation, fd_tables, collector);
        }
        PendingSyscall::IoPair { read_fd, write_fd } if result > 0 => {
            emit_fd_access(
                tid,
                table_id,
                read_fd,
                FileOperation::Read,
                fd_tables,
                collector,
            );
            emit_fd_access(
                tid,
                table_id,
                write_fd,
                FileOperation::Write,
                fd_tables,
                collector,
            );
        }
        PendingSyscall::Close { fd } if result == 0 => {
            fd_tables.remove_fd(table_id, fd);
        }
        PendingSyscall::CloseRange { first, last } if result == 0 => {
            fd_tables.close_range(table_id, first, last);
        }
        PendingSyscall::Dup { old_fd, cloexec } if result >= 0 => {
            fd_tables.duplicate(table_id, old_fd, result as i32, cloexec);
        }
        PendingSyscall::DupTo {
            old_fd,
            new_fd,
            cloexec,
        } if result >= 0 => {
            if old_fd != new_fd {
                fd_tables.duplicate(table_id, old_fd, result as i32, cloexec);
            }
        }
        PendingSyscall::SetFdFlags { fd, flags } if result == 0 => {
            fd_tables.set_cloexec(table_id, fd, flags & libc::FD_CLOEXEC != 0);
        }
        PendingSyscall::Rename { from, to } if result == 0 => {
            fd_tables.rename_paths(&from, &to);
        }
        PendingSyscall::Clone { .. }
        | PendingSyscall::Open { .. }
        | PendingSyscall::Io { .. }
        | PendingSyscall::IoPair { .. }
        | PendingSyscall::Close { .. }
        | PendingSyscall::CloseRange { .. }
        | PendingSyscall::Dup { .. }
        | PendingSyscall::DupTo { .. }
        | PendingSyscall::SetFdFlags { .. }
        | PendingSyscall::Rename { .. } => {}
    }
}

fn emit_fd_access(
    tid: libc::pid_t,
    table_id: u64,
    fd: i32,
    operation: FileOperation,
    fd_tables: &FdTables,
    collector: &mut Collector,
) {
    let Some(entry) = fd_tables.fd(table_id, fd) else {
        return;
    };
    collector.event(
        tid,
        RawEventKind::FileDescriptorAccess {
            operation,
            fd,
            path: entry.path.clone(),
        },
    );
}

fn set_pending(
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
    tid: libc::pid_t,
    pending: PendingSyscall,
) {
    if let Some(state) = tracees.get_mut(&tid) {
        state.pending_syscall = Some(pending);
    }
}

fn record_exec_path(
    tid: libc::pid_t,
    dirfd: i32,
    address: u64,
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
    collector: &mut Collector,
) {
    match read_c_string(tid, address, MAX_PATH_BYTES)
        .and_then(|path| resolve_user_path(tid, dirfd, path))
    {
        Ok(path) => {
            tracees
                .entry(tid)
                .or_insert_with(|| TraceeState::root(1, tid))
                .pending_exec = Some(path);
        }
        Err(error) => collector.warning(tid, "exec_path_unreadable", error.to_string()),
    }
}

#[allow(clippy::too_many_arguments)]
fn record_open_entry(
    tid: libc::pid_t,
    dirfd: i32,
    operation: FileOperation,
    address: u64,
    flags: u64,
    resolve: u64,
    openat2: bool,
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
    collector: &mut Collector,
) {
    match read_c_string(tid, address, MAX_PATH_BYTES)
        .and_then(|path| resolve_user_path(tid, dirfd, path))
    {
        Ok(path) => {
            if openat2 {
                collector.event(
                    tid,
                    RawEventKind::FileOpenAt2 {
                        path,
                        flags,
                        resolve,
                    },
                );
            } else {
                collector.event(
                    tid,
                    RawEventKind::FilePathAccess {
                        operation,
                        path,
                        flags: Some(flags),
                    },
                );
            }
            set_pending(
                tracees,
                tid,
                PendingSyscall::Open {
                    cloexec: flags as i32 & libc::O_CLOEXEC != 0,
                },
            );
        }
        Err(error) => collector.warning(tid, "file_path_unreadable", error.to_string()),
    }
}

fn record_file_attempt(
    tid: libc::pid_t,
    dirfd: i32,
    operation: FileOperation,
    address: u64,
    flags: Option<u64>,
    collector: &mut Collector,
) {
    match read_c_string(tid, address, MAX_PATH_BYTES)
        .and_then(|path| resolve_user_path(tid, dirfd, path))
    {
        Ok(path) => collector.event(
            tid,
            RawEventKind::FilePathAccess {
                operation,
                path,
                flags,
            },
        ),
        Err(error) => collector.warning(tid, "file_path_unreadable", error.to_string()),
    }
}

fn record_rename_entry(
    tid: libc::pid_t,
    from_dirfd: i32,
    from_address: u64,
    to_dirfd: i32,
    to_address: u64,
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
    collector: &mut Collector,
) {
    let from = read_c_string(tid, from_address, MAX_PATH_BYTES)
        .and_then(|path| resolve_user_path(tid, from_dirfd, path));
    let to = read_c_string(tid, to_address, MAX_PATH_BYTES)
        .and_then(|path| resolve_user_path(tid, to_dirfd, path));

    match (from, to) {
        (Ok(from), Ok(to)) => {
            collector.event(
                tid,
                RawEventKind::FileRename {
                    from: from.clone(),
                    to: to.clone(),
                },
            );
            set_pending(tracees, tid, PendingSyscall::Rename { from, to });
        }
        (Err(error), _) | (_, Err(error)) => {
            collector.warning(tid, "rename_path_unreadable", error.to_string())
        }
    }
}

fn resolve_user_path(tid: libc::pid_t, dirfd: i32, path: String) -> Result<String, ObserveError> {
    if path.starts_with('/') {
        return Ok(path);
    }
    if path.is_empty() && dirfd != libc::AT_FDCWD {
        return proc_fd_path(tid, dirfd);
    }

    let base = if dirfd == libc::AT_FDCWD {
        proc_cwd_path(tid)?
    } else {
        proc_fd_path(tid, dirfd)?
    };
    Ok(join_lexical(&base, &path))
}

fn join_lexical(base: &str, path: &str) -> String {
    if base == "/" {
        format!("/{path}")
    } else {
        format!("{}/{path}", base.trim_end_matches('/'))
    }
}

fn proc_cwd_path(tid: libc::pid_t) -> Result<String, ObserveError> {
    read_proc_link(PathBuf::from(format!("/proc/{tid}/cwd")))
}

fn proc_fd_path(tid: libc::pid_t, fd: i32) -> Result<String, ObserveError> {
    let path = read_proc_link(PathBuf::from(format!("/proc/{tid}/fd/{fd}")))?;
    let tgid = tracee_tgid(tid).unwrap_or(tid);
    Ok(normalize_own_proc_path(&path, tid, tgid))
}

fn tracee_tgid(tid: libc::pid_t) -> Result<libc::pid_t, ObserveError> {
    let status = fs::read_to_string(format!("/proc/{tid}/status"))?;
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("Tgid:")
                .and_then(|value| value.trim().parse::<libc::pid_t>().ok())
        })
        .ok_or_else(|| ObserveError::Protocol(format!("missing Tgid in /proc/{tid}/status")))
}

fn normalize_own_proc_path(path: &str, tid: libc::pid_t, tgid: libc::pid_t) -> String {
    let Some(rest) = path.strip_prefix("/proc/") else {
        return path.to_owned();
    };
    let Some((pid_text, suffix)) = rest.split_once('/') else {
        return path.to_owned();
    };
    let Ok(pid) = pid_text.parse::<libc::pid_t>() else {
        return path.to_owned();
    };

    if pid != tid && pid != tgid {
        return path.to_owned();
    }

    if let Some(task_rest) = suffix.strip_prefix("task/") {
        if let Some((task_tid_text, task_suffix)) = task_rest.split_once('/') {
            if task_tid_text.parse::<libc::pid_t>().ok() == Some(tid) {
                return format!("/proc/thread-self/{task_suffix}");
            }
        }
    }

    format!("/proc/self/{suffix}")
}

fn read_proc_link(path: PathBuf) -> Result<String, ObserveError> {
    fs::read_link(path)
        .map(|target| target.to_string_lossy().into_owned())
        .map_err(ObserveError::from)
}

fn read_open_how(tid: libc::pid_t, address: u64, size: u64) -> Result<(u64, u64), ObserveError> {
    let size = usize::try_from(size)
        .unwrap_or(OPEN_HOW_BYTES)
        .min(OPEN_HOW_BYTES);
    if size < 8 {
        return Err(ObserveError::Protocol(
            "open_how is shorter than the flags field".to_owned(),
        ));
    }
    let bytes = read_memory(tid, address, size)?;
    let flags = u64::from_ne_bytes(bytes[0..8].try_into().expect("slice length"));
    let resolve = if bytes.len() >= 24 {
        u64::from_ne_bytes(bytes[16..24].try_into().expect("slice length"))
    } else {
        0
    };
    Ok((flags, resolve))
}

fn read_clone3_flags(tid: libc::pid_t, address: u64, size: u64) -> Result<u64, ObserveError> {
    if size < 8 {
        return Err(ObserveError::Protocol(
            "clone_args is shorter than the flags field".to_owned(),
        ));
    }
    let bytes = read_memory(tid, address, 8)?;
    Ok(u64::from_ne_bytes(
        bytes[0..8].try_into().expect("slice length"),
    ))
}

fn is_read_syscall(nr: libc::c_long) -> bool {
    nr == libc::SYS_read || nr == libc::SYS_pread64 || nr == libc::SYS_readv
}

fn is_write_syscall(nr: libc::c_long) -> bool {
    nr == libc::SYS_write || nr == libc::SYS_pwrite64 || nr == libc::SYS_writev
}

fn record_connect(tid: libc::pid_t, address: u64, length: u64, collector: &mut Collector) {
    let length = usize::try_from(length)
        .unwrap_or(MAX_SOCKADDR_BYTES)
        .min(MAX_SOCKADDR_BYTES);

    match read_memory(tid, address, length).and_then(|bytes| parse_sockaddr(&bytes)) {
        Ok(endpoint) => collector.event(tid, RawEventKind::NetworkConnectAttempt { endpoint }),
        Err(error) => collector.warning(tid, "connect_target_unreadable", error.to_string()),
    }
}

fn syscall_info(tid: libc::pid_t) -> Result<PtraceSyscallInfo, ObserveError> {
    let mut info = MaybeUninit::<PtraceSyscallInfo>::zeroed();
    let result = unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO_REQUEST,
            tid,
            size_of::<PtraceSyscallInfo>() as *mut c_void,
            info.as_mut_ptr() as *mut c_void,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { info.assume_init() })
}

fn get_event_message(tid: libc::pid_t) -> Result<u64, ObserveError> {
    let mut value: libc::c_ulong = 0;
    ptrace_call(
        libc::PTRACE_GETEVENTMSG,
        tid,
        ptr::null_mut(),
        (&mut value as *mut libc::c_ulong).cast::<c_void>(),
    )?;
    Ok(value as u64)
}

fn resume_syscall(tid: libc::pid_t, signal: libc::c_int) -> Result<(), ObserveError> {
    ptrace_call(
        libc::PTRACE_SYSCALL,
        tid,
        ptr::null_mut(),
        signal as usize as *mut c_void,
    )
}

fn ptrace_call(
    request: libc::c_uint,
    tid: libc::pid_t,
    address: *mut c_void,
    data: *mut c_void,
) -> Result<(), ObserveError> {
    let result = unsafe { libc::ptrace(request, tid, address, data) };
    if result == -1 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

fn read_c_string(tid: libc::pid_t, address: u64, max_len: usize) -> Result<String, ObserveError> {
    if address == 0 {
        return Err(ObserveError::Protocol("null string pointer".to_owned()));
    }

    let mut bytes = Vec::new();

    while bytes.len() < max_len {
        let word = peek_word(tid, address + bytes.len() as u64)?;
        for byte in word.to_ne_bytes() {
            if byte == 0 {
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
            bytes.push(byte);
            if bytes.len() == max_len {
                break;
            }
        }
    }

    Err(ObserveError::Protocol(format!(
        "string exceeded metadata limit of {max_len} bytes"
    )))
}

fn read_memory(tid: libc::pid_t, address: u64, len: usize) -> Result<Vec<u8>, ObserveError> {
    if address == 0 {
        return Err(ObserveError::Protocol("null memory pointer".to_owned()));
    }
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        let word = peek_word(tid, address + bytes.len() as u64)?;
        let word_bytes = word.to_ne_bytes();
        let remaining = len - bytes.len();
        bytes.extend_from_slice(&word_bytes[..remaining.min(word_bytes.len())]);
    }
    Ok(bytes)
}

fn peek_word(tid: libc::pid_t, address: u64) -> Result<libc::c_long, ObserveError> {
    set_errno(0);
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_PEEKDATA,
            tid,
            address as usize as *mut c_void,
            ptr::null_mut::<c_void>(),
        )
    };
    let error = io::Error::last_os_error();
    if result == -1 && error.raw_os_error() != Some(0) {
        return Err(error.into());
    }
    Ok(result)
}

fn set_errno(value: libc::c_int) {
    unsafe {
        *libc::__errno_location() = value;
    }
}

fn parse_sockaddr(bytes: &[u8]) -> Result<NetworkEndpoint, ObserveError> {
    if bytes.len() < 2 {
        return Err(ObserveError::Protocol(
            "sockaddr shorter than address-family field".to_owned(),
        ));
    }

    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match family as libc::c_int {
        libc::AF_INET => {
            if bytes.len() < 8 {
                return Err(ObserveError::Protocol(
                    "AF_INET sockaddr is truncated".to_owned(),
                ));
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Ok(NetworkEndpoint::Inet {
                ip: ip.to_string(),
                port,
            })
        }
        libc::AF_INET6 => {
            if bytes.len() < 24 {
                return Err(ObserveError::Protocol(
                    "AF_INET6 sockaddr is truncated".to_owned(),
                ));
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            Ok(NetworkEndpoint::Inet6 {
                ip: Ipv6Addr::from(octets).to_string(),
                port,
            })
        }
        libc::AF_UNIX => {
            let path_bytes = bytes
                .get(2..)
                .unwrap_or_default()
                .iter()
                .copied()
                .take_while(|byte| *byte != 0)
                .collect::<Vec<_>>();
            let path = if path_bytes.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&path_bytes).into_owned())
            };
            Ok(NetworkEndpoint::Unix { path })
        }
        _ => Ok(NetworkEndpoint::Other { family }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_sockaddr_without_payload_data() {
        let bytes = [2, 0, 0x01, 0xbb, 127, 0, 0, 1];
        assert_eq!(
            parse_sockaddr(&bytes).expect("parse"),
            NetworkEndpoint::Inet {
                ip: "127.0.0.1".to_owned(),
                port: 443,
            }
        );
    }

    #[test]
    fn parses_ipv6_sockaddr_without_payload_data() {
        let mut bytes = vec![0_u8; 28];
        bytes[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&443_u16.to_be_bytes());
        bytes[23] = 1;
        assert_eq!(
            parse_sockaddr(&bytes).expect("parse"),
            NetworkEndpoint::Inet6 {
                ip: "::1".to_owned(),
                port: 443,
            }
        );
    }

    #[test]
    fn lexical_join_preserves_parent_traversal_for_later_canonical_review() {
        assert_eq!(
            join_lexical("/tmp/work", "../secret"),
            "/tmp/work/../secret"
        );
    }

    #[test]
    fn c1_a_clone_free_certificate_is_trivially_exact() {
        let certificate = CloneFdCertification::default();
        assert!(certificate.fully_certified());
        assert_eq!(certificate.clone_events, 0);
        assert_eq!(certificate.shared_fd_transitions, 0);
        assert_eq!(certificate.cloned_fd_transitions, 0);
    }

    #[test]
    fn c1_b_private_clone_is_classified_exactly_once() {
        let mut certificate = CloneFdCertification::default();
        certificate.record_clone(Some(0));
        assert!(certificate.fully_certified());
        assert_eq!(certificate.clone_events, 1);
        assert_eq!(certificate.correlated_clone_flags, 1);
        assert_eq!(certificate.shared_fd_transitions, 0);
        assert_eq!(certificate.cloned_fd_transitions, 1);
        assert_eq!(certificate.clone_thread_transitions, 0);
    }

    #[test]
    fn c1_cde_shared_and_thread_bits_remain_independent() {
        let mut shared = CloneFdCertification::default();
        shared.record_clone(Some(libc::CLONE_FILES as u64));
        assert!(shared.fully_certified());
        assert_eq!(shared.shared_fd_transitions, 1);
        assert_eq!(shared.clone_thread_transitions, 0);

        let mut thread_only = CloneFdCertification::default();
        thread_only.record_clone(Some(libc::CLONE_THREAD as u64));
        assert!(thread_only.fully_certified());
        assert_eq!(thread_only.shared_fd_transitions, 0);
        assert_eq!(thread_only.cloned_fd_transitions, 1);
        assert_eq!(thread_only.clone_thread_transitions, 1);

        let mut both = CloneFdCertification::default();
        both.record_clone(Some((libc::CLONE_THREAD | libc::CLONE_FILES) as u64));
        assert!(both.fully_certified());
        assert_eq!(both.shared_fd_transitions, 1);
        assert_eq!(both.clone_thread_transitions, 1);
    }

    #[test]
    fn c1_f_missing_clone_flags_fail_certification() {
        let mut certificate = CloneFdCertification::default();
        certificate.record_clone(None);
        assert!(!certificate.fully_certified());
        assert_eq!(certificate.clone_events, 1);
        assert_eq!(certificate.correlated_clone_flags, 0);
    }

    #[test]
    fn c1_g_clone3_unreadable_warning_invalidates_certification() {
        let mut collector = Collector::new(128);
        collector.warning(42, "clone3_flags_unreadable", "controlled test");
        assert!(!collector.clone_fd_certification.fully_certified());
        assert!(!collector.observation.complete);
    }

    #[test]
    fn c1_i_exec_cloexec_unshares_from_other_shared_table_users() {
        let mut tables = FdTables::new();
        let shared_id = tables.root_id();
        tables.insert_fd(
            shared_id,
            7,
            FdEntry {
                path: "/tmp/c1-cloexec".to_owned(),
                cloexec: true,
            },
        );

        let mut tracees = HashMap::new();
        tracees.insert(100, TraceeState::root(shared_id, 100));
        tracees.insert(101, TraceeState::child(shared_id, 100));
        apply_exec_fd_semantics(101, &mut tracees, &mut tables);

        let exec_table = tracees.get(&101).expect("execing task").fd_table_id;
        assert_ne!(exec_table, shared_id);
        assert!(tables.fd(exec_table, 7).is_none());
        assert!(tables.fd(shared_id, 7).is_some());
    }

    #[test]
    fn c1_jk_shared_mutation_and_fd_reuse_never_leave_stale_identity() {
        let mut tables = FdTables::new();
        let shared_id = tables.root_id();
        tables.insert_fd(
            shared_id,
            9,
            FdEntry {
                path: "/tmp/c1-old".to_owned(),
                cloexec: false,
            },
        );
        tables.duplicate(shared_id, 9, 10, false);
        assert_eq!(
            tables.fd(shared_id, 10).expect("dup fd").path,
            "/tmp/c1-old"
        );

        tables.remove_fd(shared_id, 9);
        tables.insert_fd(
            shared_id,
            9,
            FdEntry {
                path: "/tmp/c1-new".to_owned(),
                cloexec: false,
            },
        );
        assert_eq!(
            tables.fd(shared_id, 9).expect("reused fd").path,
            "/tmp/c1-new"
        );
        assert_eq!(
            tables.fd(shared_id, 10).expect("old dup remains").path,
            "/tmp/c1-old"
        );

        tables.close_range(shared_id, 9, 10);
        assert!(tables.fd(shared_id, 9).is_none());
        assert!(tables.fd(shared_id, 10).is_none());
    }

    #[test]
    #[ignore = "C1 real ptrace concurrency harness; run in the dedicated Linux gate"]
    fn c1_real_ptrace_clone_modes_are_certified() {
        use std::process::Command;

        let root =
            std::env::temp_dir().join(format!("execsurface-c1-real-clone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create C1 harness directory");
        let source = root.join("clone_modes.c");
        let binary = root.join("clone_modes");
        std::fs::write(
            &source,
            r#"#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int child_main(void *unused) {
    (void)unused;
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int flags = 0;
    if (strcmp(argv[1], "shared") == 0) {
        flags |= CLONE_FILES;
    } else if (strcmp(argv[1], "private") != 0) {
        return 3;
    }

    const size_t stack_size = 1u << 20;
    char *stack = malloc(stack_size);
    if (!stack) return 4;
    pid_t child = clone(child_main, stack + stack_size, flags, NULL);
    if (child < 0) {
        perror("clone");
        free(stack);
        return 5;
    }

    int status = 0;
    if (waitpid(child, &status, __WCLONE) < 0) {
        perror("waitpid");
        free(stack);
        return 6;
    }
    free(stack);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 7;
}
"#,
        )
        .expect("write C1 clone harness");

        let compile = Command::new("cc")
            .arg("-O2")
            .arg("-Wall")
            .arg("-Wextra")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .expect("invoke cc for C1 harness");
        assert!(compile.success(), "C1 clone harness must compile");

        let private = observe(
            &CommandSpec::new(binary.as_os_str()).arg("private"),
            ObserveOptions::default(),
        )
        .expect("observe private clone harness");
        assert_eq!(private.observation.outcome.exit_code, Some(0));
        assert!(private.clone_fd_certification.fully_certified());
        assert!(private.clone_fd_certification.clone_events >= 1);
        assert_eq!(private.clone_fd_certification.shared_fd_transitions, 0);
        assert!(private.clone_fd_certification.cloned_fd_transitions >= 1);
        assert_eq!(
            private
                .observation
                .warnings
                .iter()
                .filter(|warning| warning.code == "clone_flags_unavailable")
                .count(),
            0
        );

        let shared = observe(
            &CommandSpec::new(binary.as_os_str()).arg("shared"),
            ObserveOptions::default(),
        )
        .expect("observe CLONE_FILES harness");
        assert_eq!(shared.observation.outcome.exit_code, Some(0));
        assert!(shared.clone_fd_certification.fully_certified());
        assert!(shared.clone_fd_certification.clone_events >= 1);
        assert!(shared.clone_fd_certification.shared_fd_transitions >= 1);
        assert_eq!(shared.clone_fd_certification.cloned_fd_transitions, 0);
        assert_eq!(
            shared
                .observation
                .warnings
                .iter()
                .filter(|warning| warning.code == "clone_flags_unavailable")
                .count(),
            0
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    #[ignore = "C3 live clone-origin event-routing harness; run in the dedicated Linux gate"]
    fn c3_clone_sigchld_fork_event_keeps_clone_fd_authority() {
        use std::process::Command;

        let root = std::env::temp_dir().join(format!(
            "execsurface-c3-clone-sigchld-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create C3 SIGCHLD harness directory");
        let source = root.join("clone_sigchld.c");
        let binary = root.join("clone_sigchld");
        std::fs::write(
            &source,
            r#"#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int child_main(void *unused) {
    (void)unused;
    _exit(0);
}

int main(void) {
    const size_t stack_size = 1u << 20;
    char *stack = malloc(stack_size);
    if (!stack) return 2;
    int flags = CLONE_FILES | SIGCHLD;
    pid_t child = clone(child_main, stack + stack_size, flags, NULL);
    if (child < 0) {
        perror("clone");
        free(stack);
        return 3;
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        free(stack);
        return 4;
    }
    free(stack);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 5;
}
"#,
        )
        .expect("write C3 SIGCHLD clone harness");

        let compile = Command::new("cc")
            .arg("-O2")
            .arg("-Wall")
            .arg("-Wextra")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .expect("compile C3 SIGCHLD clone harness");
        assert!(compile.success());

        let observed = observe(
            &CommandSpec::new(binary.as_os_str()),
            ObserveOptions::default(),
        )
        .expect("observe C3 SIGCHLD clone harness");
        assert_eq!(observed.observation.outcome.exit_code, Some(0));
        assert!(observed.clone_fd_certification.fully_certified());
        assert!(observed.clone_fd_certification.shared_fd_transitions >= 1);
        assert!(
            observed.clone_fd_certification.clone_origin_fork_events >= 1,
            "Linux should route clone(..., CLONE_FILES|SIGCHLD) through PTRACE_EVENT_FORK under the declared options"
        );
        assert!(observed.observation.events.iter().any(|event| matches!(
            &event.kind,
            RawEventKind::ProcessSpawn {
                mechanism: SpawnMechanism::Fork,
                ..
            }
        )));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    #[ignore = "C3 live clone-origin VFORK routing harness; run in the dedicated Linux gate"]
    fn c3_clone_vfork_event_keeps_clone_fd_authority() {
        use std::process::Command;

        let root =
            std::env::temp_dir().join(format!("execsurface-c3-clone-vfork-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create C3 VFORK harness directory");
        let source = root.join("clone_vfork.c");
        let binary = root.join("clone_vfork");
        std::fs::write(
            &source,
            r#"#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int child_main(void *unused) {
    (void)unused;
    _exit(0);
}

int main(void) {
    const size_t stack_size = 1u << 20;
    char *stack = malloc(stack_size);
    if (!stack) return 2;
    int flags = CLONE_FILES | CLONE_VM | CLONE_VFORK | SIGCHLD;
    pid_t child = clone(child_main, stack + stack_size, flags, NULL);
    if (child < 0) {
        perror("clone");
        free(stack);
        return 3;
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        free(stack);
        return 4;
    }
    free(stack);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 5;
}
"#,
        )
        .expect("write C3 VFORK clone harness");

        let compile = Command::new("cc")
            .arg("-O2")
            .arg("-Wall")
            .arg("-Wextra")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .expect("compile C3 VFORK clone harness");
        assert!(compile.success());

        let observed = observe(
            &CommandSpec::new(binary.as_os_str()),
            ObserveOptions::default(),
        )
        .expect("observe C3 VFORK clone harness");
        assert_eq!(observed.observation.outcome.exit_code, Some(0));
        assert!(observed.clone_fd_certification.fully_certified());
        assert!(observed.clone_fd_certification.shared_fd_transitions >= 1);
        assert!(
            observed.clone_fd_certification.clone_origin_vfork_events >= 1,
            "Linux should route CLONE_VFORK clone origin through PTRACE_EVENT_VFORK under the declared options"
        );
        assert!(observed.observation.events.iter().any(|event| matches!(
            &event.kind,
            RawEventKind::ProcessSpawn {
                mechanism: SpawnMechanism::Vfork,
                ..
            }
        )));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn normalizes_only_the_tracees_own_proc_identity() {
        assert_eq!(
            normalize_own_proc_path("/proc/123/maps", 123, 123),
            "/proc/self/maps"
        );
        assert_eq!(
            normalize_own_proc_path("/proc/100/maps", 101, 100),
            "/proc/self/maps"
        );
        assert_eq!(
            normalize_own_proc_path("/proc/100/task/101/status", 101, 100),
            "/proc/thread-self/status"
        );
        assert_eq!(
            normalize_own_proc_path("/proc/999/maps", 101, 100),
            "/proc/999/maps"
        );
        assert_eq!(
            normalize_own_proc_path("/proc/100/task/102/status", 101, 100),
            "/proc/self/task/102/status"
        );
    }
}

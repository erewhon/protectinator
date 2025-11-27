//! Process listing and analysis

use serde::{Deserialize, Serialize};
use sysinfo::{Pid, Process, System, Users};
use std::collections::HashMap;

/// Information about a running process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: Option<u32>,
    /// Process name
    pub name: String,
    /// Full command line
    pub cmdline: String,
    /// Executable path
    pub exe: Option<String>,
    /// Current working directory
    pub cwd: Option<String>,
    /// User running the process
    pub user: Option<String>,
    /// User ID
    pub uid: Option<u32>,
    /// CPU usage percentage
    pub cpu_usage: f32,
    /// Memory usage in bytes
    pub memory: u64,
    /// Start time (Unix timestamp)
    pub start_time: u64,
    /// Risk assessment
    pub risk: ProcessRisk,
    /// Risk reasons
    pub risk_reasons: Vec<String>,
}

/// Risk level for a process
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProcessRisk {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl ProcessRisk {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProcessRisk::Low => "low",
            ProcessRisk::Medium => "medium",
            ProcessRisk::High => "high",
            ProcessRisk::Critical => "critical",
        }
    }
}

/// Get all running processes
pub fn get_processes() -> Vec<ProcessInfo> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let users = Users::new_with_refreshed_list();

    let mut processes = Vec::new();

    for (pid, process) in sys.processes() {
        let mut info = process_to_info(pid, process, &users);
        assess_process_risk(&mut info);
        processes.push(info);
    }

    processes
}

/// Get a specific process by PID
pub fn get_process(pid: u32) -> Option<ProcessInfo> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let users = Users::new_with_refreshed_list();

    sys.process(Pid::from_u32(pid)).map(|p| {
        let mut info = process_to_info(&Pid::from_u32(pid), p, &users);
        assess_process_risk(&mut info);
        info
    })
}

fn process_to_info(pid: &Pid, process: &Process, users: &Users) -> ProcessInfo {
    let cmdline = process
        .cmd()
        .iter()
        .map(|s| s.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(" ");

    let user = process.user_id().and_then(|uid| {
        users
            .iter()
            .find(|u| u.id() == uid)
            .map(|u| u.name().to_string())
    });

    let uid = process.user_id().map(|uid| {
        // Convert Uid to u32
        #[cfg(unix)]
        {
            **uid
        }
        #[cfg(not(unix))]
        {
            0u32
        }
    });

    ProcessInfo {
        pid: pid.as_u32(),
        ppid: process.parent().map(|p| p.as_u32()),
        name: process.name().to_string_lossy().to_string(),
        cmdline,
        exe: process.exe().map(|p| p.to_string_lossy().to_string()),
        cwd: process.cwd().map(|p| p.to_string_lossy().to_string()),
        user,
        uid,
        cpu_usage: process.cpu_usage(),
        memory: process.memory(),
        start_time: process.start_time(),
        risk: ProcessRisk::Low,
        risk_reasons: Vec::new(),
    }
}

/// Assess risk level for a process
fn assess_process_risk(process: &mut ProcessInfo) {
    let mut risk = ProcessRisk::Low;
    let mut reasons = Vec::new();

    let cmdline_lower = process.cmdline.to_lowercase();
    let name_lower = process.name.to_lowercase();

    // Suspicious command patterns
    let suspicious_patterns = [
        ("base64", "Base64 encoding/decoding"),
        ("curl", "Network download"),
        ("wget", "Network download"),
        ("nc ", "Netcat"),
        ("netcat", "Netcat"),
        ("/dev/tcp", "Bash network redirection"),
        ("bash -i", "Interactive bash"),
        ("python -c", "Inline Python"),
        ("perl -e", "Inline Perl"),
        ("powershell", "PowerShell"),
        ("-enc", "Encoded command"),
        ("iex(", "PowerShell IEX"),
        ("invoke-expression", "PowerShell Invoke-Expression"),
        ("/tmp/", "Execution from /tmp"),
        ("/dev/shm", "Execution from shared memory"),
        ("socat", "Socket relay"),
        ("ncat", "Nmap netcat"),
        ("cryptominer", "Cryptominer"),
        ("xmrig", "XMRig miner"),
        ("minerd", "CPU miner"),
    ];

    for (pattern, reason) in &suspicious_patterns {
        if cmdline_lower.contains(pattern) || name_lower.contains(pattern) {
            reasons.push(reason.to_string());
            risk = std::cmp::max(risk, ProcessRisk::Medium);
        }
    }

    // High-risk patterns
    let high_risk_patterns = [
        ("reverse", "Reverse shell indicator"),
        ("shell", "Shell in command"),
        ("backdoor", "Backdoor indicator"),
        ("exploit", "Exploit indicator"),
        ("meterpreter", "Meterpreter"),
        ("cobalt", "Cobalt Strike indicator"),
        ("beacon", "C2 beacon indicator"),
    ];

    for (pattern, reason) in &high_risk_patterns {
        if cmdline_lower.contains(pattern) {
            reasons.push(reason.to_string());
            risk = std::cmp::max(risk, ProcessRisk::High);
        }
    }

    // Check for unusual execution locations
    if let Some(ref exe) = process.exe {
        let exe_lower = exe.to_lowercase();
        if exe_lower.starts_with("/tmp/")
            || exe_lower.starts_with("/dev/shm")
            || exe_lower.starts_with("/var/tmp")
            || exe_lower.contains("/.")
        {
            reasons.push("Executing from suspicious location".to_string());
            risk = std::cmp::max(risk, ProcessRisk::High);
        }
    }

    // Check for hidden processes (name starting with .)
    if process.name.starts_with('.') {
        reasons.push("Hidden process name".to_string());
        risk = std::cmp::max(risk, ProcessRisk::Medium);
    }

    // Root processes that shouldn't be root
    if process.uid == Some(0) {
        let normal_root_procs = [
            "init", "systemd", "sshd", "cron", "rsyslogd", "dockerd", "containerd",
            "kthreadd", "ksoftirqd", "migration", "watchdog", "kworker",
        ];

        let is_normal = normal_root_procs
            .iter()
            .any(|n| name_lower.starts_with(n));

        if !is_normal && !name_lower.starts_with('[') {
            // Not a kernel thread
            reasons.push("Unusual root process".to_string());
            risk = std::cmp::max(risk, ProcessRisk::Medium);
        }
    }

    process.risk = risk;
    process.risk_reasons = reasons;
}

/// Get process tree (parent-child relationships)
pub fn get_process_tree() -> HashMap<u32, Vec<u32>> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut tree: HashMap<u32, Vec<u32>> = HashMap::new();

    for (pid, process) in sys.processes() {
        if let Some(ppid) = process.parent() {
            tree.entry(ppid.as_u32())
                .or_default()
                .push(pid.as_u32());
        }
    }

    tree
}

/// Summary of process scan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessSummary {
    pub total_processes: usize,
    pub root_processes: usize,
    pub user_processes: usize,
    pub critical_risk: usize,
    pub high_risk: usize,
    pub medium_risk: usize,
    pub low_risk: usize,
}

impl ProcessSummary {
    pub fn from_processes(processes: &[ProcessInfo]) -> Self {
        let mut summary = Self::default();
        summary.total_processes = processes.len();

        for proc in processes {
            if proc.uid == Some(0) {
                summary.root_processes += 1;
            } else {
                summary.user_processes += 1;
            }

            match proc.risk {
                ProcessRisk::Critical => summary.critical_risk += 1,
                ProcessRisk::High => summary.high_risk += 1,
                ProcessRisk::Medium => summary.medium_risk += 1,
                ProcessRisk::Low => summary.low_risk += 1,
            }
        }

        summary
    }

    pub fn has_suspicious(&self) -> bool {
        self.critical_risk > 0 || self.high_risk > 0
    }
}

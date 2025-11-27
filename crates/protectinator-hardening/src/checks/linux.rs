//! Linux-specific hardening checks

use super::common::*;
use super::{CheckCategory, CheckRegistry, CheckResult, HardeningCheck, RunnableCheck};
use protectinator_core::Severity;
use std::path::Path;

/// Register all Linux hardening checks
pub fn register_checks(registry: &mut CheckRegistry) {
    // SSH checks
    registry.register(Box::new(SshRootLoginCheck));
    registry.register(Box::new(SshPasswordAuthCheck));
    registry.register(Box::new(SshPermitEmptyPasswordsCheck));
    registry.register(Box::new(SshProtocolCheck));
    registry.register(Box::new(SshX11ForwardingCheck));

    // Kernel checks
    registry.register(Box::new(AslrCheck));
    registry.register(Box::new(ExecShieldCheck));
    registry.register(Box::new(KernelPointerRestrictionCheck));
    registry.register(Box::new(DmesgRestrictionCheck));
    registry.register(Box::new(SuidDumpableCheck));
    registry.register(Box::new(PtraceRestrictionCheck));

    // Network checks
    registry.register(Box::new(IpForwardingCheck));
    registry.register(Box::new(IcmpRedirectCheck));
    registry.register(Box::new(SynCookiesCheck));
    registry.register(Box::new(FirewallActiveCheck));

    // Filesystem checks
    registry.register(Box::new(SuidBinaryAuditCheck));
    registry.register(Box::new(WorldWritableFilesCheck));
    registry.register(Box::new(TmpNoexecCheck));
    registry.register(Box::new(HomeDirectoryPermissionsCheck));

    // Service checks
    registry.register(Box::new(UnnecessaryServicesCheck));

    // Audit checks
    registry.register(Box::new(AuditdEnabledCheck));
}

// ============================================================================
// SSH Checks
// ============================================================================

struct SshRootLoginCheck;

impl RunnableCheck for SshRootLoginCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-ssh-root-login",
                "SSH Root Login Disabled",
                "Root login via SSH should be disabled to prevent direct root access",
                CheckCategory::Authentication,
                Severity::High,
            )
            .with_cis_reference("CIS 5.2.10")
            .with_remediation("Set 'PermitRootLogin no' in /etc/ssh/sshd_config")
            .with_reference("https://www.ssh.com/academy/ssh/sshd_config")
        })
    }

    fn run(&self) -> CheckResult {
        let sshd_config = Path::new("/etc/ssh/sshd_config");
        if !file_exists(sshd_config) {
            return CheckResult::skipped("SSH server not installed");
        }

        let config = parse_ssh_config(sshd_config);
        match config.get("permitrootlogin") {
            Some(value) if value == "no" => {
                CheckResult::pass("Root login via SSH is disabled")
            }
            Some(value) if value == "prohibit-password" || value == "without-password" => {
                CheckResult::pass("Root login via SSH requires key authentication only")
            }
            Some(value) => CheckResult::fail_with_remediation(
                format!("Root login via SSH is set to '{}' - should be 'no'", value),
                Severity::High,
                "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no', then restart sshd",
            ),
            None => CheckResult::fail_with_remediation(
                "PermitRootLogin not explicitly set (defaults may allow root login)",
                Severity::Medium,
                "Add 'PermitRootLogin no' to /etc/ssh/sshd_config",
            ),
        }
    }

    fn is_applicable(&self) -> bool {
        file_exists(Path::new("/etc/ssh/sshd_config"))
    }
}

struct SshPasswordAuthCheck;

impl RunnableCheck for SshPasswordAuthCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-ssh-password-auth",
                "SSH Password Authentication",
                "Password authentication should be disabled in favor of key-based authentication",
                CheckCategory::Authentication,
                Severity::Medium,
            )
            .with_cis_reference("CIS 5.2.12")
            .with_remediation("Set 'PasswordAuthentication no' in /etc/ssh/sshd_config")
        })
    }

    fn run(&self) -> CheckResult {
        let sshd_config = Path::new("/etc/ssh/sshd_config");
        if !file_exists(sshd_config) {
            return CheckResult::skipped("SSH server not installed");
        }

        let config = parse_ssh_config(sshd_config);
        match config.get("passwordauthentication") {
            Some(value) if value == "no" => {
                CheckResult::pass("Password authentication is disabled")
            }
            Some(_) | None => CheckResult::fail_with_remediation(
                "SSH password authentication is enabled",
                Severity::Medium,
                "Set 'PasswordAuthentication no' and ensure key-based auth is configured",
            ),
        }
    }

    fn is_applicable(&self) -> bool {
        file_exists(Path::new("/etc/ssh/sshd_config"))
    }
}

struct SshPermitEmptyPasswordsCheck;

impl RunnableCheck for SshPermitEmptyPasswordsCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-ssh-empty-passwords",
                "SSH Empty Passwords Disabled",
                "Empty passwords should never be permitted for SSH login",
                CheckCategory::Authentication,
                Severity::Critical,
            )
            .with_cis_reference("CIS 5.2.11")
            .with_remediation("Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config")
        })
    }

    fn run(&self) -> CheckResult {
        let sshd_config = Path::new("/etc/ssh/sshd_config");
        if !file_exists(sshd_config) {
            return CheckResult::skipped("SSH server not installed");
        }

        let config = parse_ssh_config(sshd_config);
        match config.get("permitemptypasswords") {
            Some(value) if value == "yes" => CheckResult::fail(
                "SSH permits empty passwords - critical security risk!",
                Severity::Critical,
            ),
            _ => CheckResult::pass("Empty passwords are not permitted"),
        }
    }

    fn is_applicable(&self) -> bool {
        file_exists(Path::new("/etc/ssh/sshd_config"))
    }
}

struct SshProtocolCheck;

impl RunnableCheck for SshProtocolCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-ssh-protocol",
                "SSH Protocol Version 2",
                "SSH should only use protocol version 2",
                CheckCategory::Authentication,
                Severity::High,
            )
            .with_cis_reference("CIS 5.2.4")
        })
    }

    fn run(&self) -> CheckResult {
        let sshd_config = Path::new("/etc/ssh/sshd_config");
        if !file_exists(sshd_config) {
            return CheckResult::skipped("SSH server not installed");
        }

        let config = parse_ssh_config(sshd_config);
        match config.get("protocol") {
            Some(value) if value.contains('1') => CheckResult::fail(
                "SSH protocol version 1 is enabled - this is insecure",
                Severity::High,
            ),
            _ => CheckResult::pass("SSH protocol version 2 only (or modern SSH which defaults to v2)"),
        }
    }

    fn is_applicable(&self) -> bool {
        file_exists(Path::new("/etc/ssh/sshd_config"))
    }
}

struct SshX11ForwardingCheck;

impl RunnableCheck for SshX11ForwardingCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-ssh-x11-forwarding",
                "SSH X11 Forwarding Disabled",
                "X11 forwarding should be disabled unless specifically needed",
                CheckCategory::Authentication,
                Severity::Low,
            )
            .with_cis_reference("CIS 5.2.6")
        })
    }

    fn run(&self) -> CheckResult {
        let sshd_config = Path::new("/etc/ssh/sshd_config");
        if !file_exists(sshd_config) {
            return CheckResult::skipped("SSH server not installed");
        }

        let config = parse_ssh_config(sshd_config);
        match config.get("x11forwarding") {
            Some(value) if value == "no" => {
                CheckResult::pass("X11 forwarding is disabled")
            }
            _ => CheckResult::fail_with_remediation(
                "X11 forwarding is enabled (or defaults to enabled)",
                Severity::Low,
                "Set 'X11Forwarding no' in /etc/ssh/sshd_config if not needed",
            ),
        }
    }

    fn is_applicable(&self) -> bool {
        file_exists(Path::new("/etc/ssh/sshd_config"))
    }
}

// ============================================================================
// Kernel Checks
// ============================================================================

struct AslrCheck;

impl RunnableCheck for AslrCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-kernel-aslr",
                "Address Space Layout Randomization (ASLR)",
                "ASLR should be enabled to make exploitation more difficult",
                CheckCategory::Kernel,
                Severity::High,
            )
            .with_cis_reference("CIS 1.5.2")
            .with_remediation("Set kernel.randomize_va_space = 2 in /etc/sysctl.conf")
        })
    }

    fn run(&self) -> CheckResult {
        match read_sysctl("kernel.randomize_va_space") {
            Some(value) => {
                let level: i32 = value.parse().unwrap_or(0);
                match level {
                    2 => CheckResult::pass("ASLR is fully enabled (level 2)"),
                    1 => CheckResult::fail_with_remediation(
                        "ASLR is only partially enabled (level 1)",
                        Severity::Medium,
                        "Set kernel.randomize_va_space = 2",
                    ),
                    _ => CheckResult::fail(
                        "ASLR is disabled - system is vulnerable to memory attacks",
                        Severity::High,
                    ),
                }
            }
            None => CheckResult::error("Could not read ASLR setting"),
        }
    }
}

struct ExecShieldCheck;

impl RunnableCheck for ExecShieldCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-kernel-exec-shield",
                "Exec-Shield Protection",
                "Exec-Shield helps prevent buffer overflow attacks",
                CheckCategory::Kernel,
                Severity::Medium,
            )
        })
    }

    fn run(&self) -> CheckResult {
        // exec-shield is legacy, modern kernels use NX bit
        // Check if NX is supported
        let cpuinfo = read_file(Path::new("/proc/cpuinfo")).unwrap_or_default();
        if cpuinfo.contains(" nx ") || cpuinfo.contains(" nx\n") {
            CheckResult::pass("NX (No-Execute) bit is supported by CPU")
        } else {
            CheckResult::fail(
                "NX bit not detected - hardware execute protection unavailable",
                Severity::Medium,
            )
        }
    }
}

struct KernelPointerRestrictionCheck;

impl RunnableCheck for KernelPointerRestrictionCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-kernel-kptr-restrict",
                "Kernel Pointer Restriction",
                "Kernel pointers should be hidden from unprivileged users",
                CheckCategory::Kernel,
                Severity::Medium,
            )
            .with_remediation("Set kernel.kptr_restrict = 1 or 2 in /etc/sysctl.conf")
        })
    }

    fn run(&self) -> CheckResult {
        match read_sysctl("kernel.kptr_restrict") {
            Some(value) => {
                let level: i32 = value.parse().unwrap_or(0);
                match level {
                    2 => CheckResult::pass("Kernel pointers hidden from all users"),
                    1 => CheckResult::pass("Kernel pointers hidden from unprivileged users"),
                    _ => CheckResult::fail_with_remediation(
                        "Kernel pointers are exposed to all users",
                        Severity::Medium,
                        "Set kernel.kptr_restrict = 1",
                    ),
                }
            }
            None => CheckResult::error("Could not read kptr_restrict setting"),
        }
    }
}

struct DmesgRestrictionCheck;

impl RunnableCheck for DmesgRestrictionCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-kernel-dmesg-restrict",
                "Dmesg Restriction",
                "Kernel log (dmesg) should be restricted to privileged users",
                CheckCategory::Kernel,
                Severity::Low,
            )
            .with_remediation("Set kernel.dmesg_restrict = 1 in /etc/sysctl.conf")
        })
    }

    fn run(&self) -> CheckResult {
        match read_sysctl("kernel.dmesg_restrict") {
            Some(value) if value == "1" => {
                CheckResult::pass("dmesg is restricted to privileged users")
            }
            Some(_) => CheckResult::fail_with_remediation(
                "dmesg is accessible to all users",
                Severity::Low,
                "Set kernel.dmesg_restrict = 1",
            ),
            None => CheckResult::error("Could not read dmesg_restrict setting"),
        }
    }
}

struct SuidDumpableCheck;

impl RunnableCheck for SuidDumpableCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-kernel-suid-dumpable",
                "SUID Core Dump Restriction",
                "Core dumps from SUID programs should be restricted",
                CheckCategory::Kernel,
                Severity::Medium,
            )
            .with_cis_reference("CIS 1.5.1")
            .with_remediation("Set fs.suid_dumpable = 0 in /etc/sysctl.conf")
        })
    }

    fn run(&self) -> CheckResult {
        match read_sysctl("fs.suid_dumpable") {
            Some(value) if value == "0" => {
                CheckResult::pass("SUID program core dumps are disabled")
            }
            Some(value) => CheckResult::fail_with_remediation(
                format!("SUID programs can create core dumps (value: {})", value),
                Severity::Medium,
                "Set fs.suid_dumpable = 0",
            ),
            None => CheckResult::error("Could not read suid_dumpable setting"),
        }
    }
}

struct PtraceRestrictionCheck;

impl RunnableCheck for PtraceRestrictionCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-kernel-ptrace-scope",
                "Ptrace Scope Restriction",
                "Ptrace should be restricted to prevent process memory inspection",
                CheckCategory::Kernel,
                Severity::Medium,
            )
            .with_remediation("Set kernel.yama.ptrace_scope = 1 or higher in /etc/sysctl.conf")
        })
    }

    fn run(&self) -> CheckResult {
        match read_sysctl("kernel.yama.ptrace_scope") {
            Some(value) => {
                let level: i32 = value.parse().unwrap_or(0);
                match level {
                    0 => CheckResult::fail_with_remediation(
                        "Ptrace is unrestricted - any process can trace any other",
                        Severity::Medium,
                        "Set kernel.yama.ptrace_scope = 1",
                    ),
                    1 => CheckResult::pass("Ptrace restricted to parent-child relationships"),
                    2 => CheckResult::pass("Ptrace restricted to CAP_SYS_PTRACE"),
                    3 => CheckResult::pass("Ptrace completely disabled"),
                    _ => CheckResult::pass("Ptrace is restricted"),
                }
            }
            None => CheckResult::skipped("Yama LSM not available"),
        }
    }
}

// ============================================================================
// Network Checks
// ============================================================================

struct IpForwardingCheck;

impl RunnableCheck for IpForwardingCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-network-ip-forward",
                "IP Forwarding Disabled",
                "IP forwarding should be disabled unless the system is a router",
                CheckCategory::Network,
                Severity::Medium,
            )
            .with_cis_reference("CIS 3.1.1")
            .with_remediation("Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf")
        })
    }

    fn run(&self) -> CheckResult {
        let ipv4_forward = read_sysctl("net.ipv4.ip_forward").unwrap_or_default();
        let ipv6_forward = read_sysctl("net.ipv6.conf.all.forwarding").unwrap_or_default();

        if ipv4_forward == "1" || ipv6_forward == "1" {
            CheckResult::fail_with_remediation(
                "IP forwarding is enabled - system may be used as a router",
                Severity::Medium,
                "Disable IP forwarding unless this is intentionally a router",
            )
        } else {
            CheckResult::pass("IP forwarding is disabled")
        }
    }
}

struct IcmpRedirectCheck;

impl RunnableCheck for IcmpRedirectCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-network-icmp-redirect",
                "ICMP Redirect Acceptance Disabled",
                "ICMP redirects should not be accepted to prevent routing manipulation",
                CheckCategory::Network,
                Severity::Medium,
            )
            .with_cis_reference("CIS 3.2.2")
        })
    }

    fn run(&self) -> CheckResult {
        let accept_redirects = read_sysctl("net.ipv4.conf.all.accept_redirects").unwrap_or_default();
        let secure_redirects = read_sysctl("net.ipv4.conf.all.secure_redirects").unwrap_or_default();

        if accept_redirects == "0" && secure_redirects == "0" {
            CheckResult::pass("ICMP redirects are rejected")
        } else {
            CheckResult::fail_with_remediation(
                "System accepts ICMP redirects which can be used for attacks",
                Severity::Medium,
                "Set net.ipv4.conf.all.accept_redirects = 0",
            )
        }
    }
}

struct SynCookiesCheck;

impl RunnableCheck for SynCookiesCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-network-syn-cookies",
                "TCP SYN Cookies Enabled",
                "SYN cookies should be enabled to protect against SYN flood attacks",
                CheckCategory::Network,
                Severity::Medium,
            )
            .with_cis_reference("CIS 3.2.8")
        })
    }

    fn run(&self) -> CheckResult {
        match read_sysctl("net.ipv4.tcp_syncookies") {
            Some(value) if value == "1" => {
                CheckResult::pass("SYN cookies are enabled")
            }
            _ => CheckResult::fail_with_remediation(
                "SYN cookies are disabled - system vulnerable to SYN flood attacks",
                Severity::Medium,
                "Set net.ipv4.tcp_syncookies = 1",
            ),
        }
    }
}

struct FirewallActiveCheck;

impl RunnableCheck for FirewallActiveCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-network-firewall",
                "Firewall Active",
                "A firewall should be active and configured",
                CheckCategory::Network,
                Severity::High,
            )
            .with_cis_reference("CIS 3.5")
        })
    }

    fn run(&self) -> CheckResult {
        // Check for various firewall solutions

        // Check UFW
        if command_exists("ufw") {
            if let Ok(status) = run_command("ufw", &["status"]) {
                if status.contains("Status: active") {
                    return CheckResult::pass("UFW firewall is active");
                }
            }
        }

        // Check firewalld
        if is_service_active("firewalld") {
            return CheckResult::pass("firewalld is active");
        }

        // Check iptables rules
        if let Ok(rules) = run_command("iptables", &["-L", "-n"]) {
            let rule_count = rules.lines().count();
            if rule_count > 10 {
                return CheckResult::pass("iptables has rules configured");
            }
        }

        // Check nftables
        if let Ok(rules) = run_command("nft", &["list", "ruleset"]) {
            if !rules.trim().is_empty() && rules.contains("chain") {
                return CheckResult::pass("nftables has rules configured");
            }
        }

        CheckResult::fail_with_remediation(
            "No active firewall detected",
            Severity::High,
            "Enable a firewall: 'ufw enable' or 'systemctl enable --now firewalld'",
        )
    }
}

// ============================================================================
// Filesystem Checks
// ============================================================================

struct SuidBinaryAuditCheck;

impl RunnableCheck for SuidBinaryAuditCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-fs-suid-audit",
                "SUID/SGID Binary Audit",
                "System should have minimal SUID/SGID binaries",
                CheckCategory::Filesystem,
                Severity::Medium,
            )
            .with_cis_reference("CIS 6.1.13")
        })
    }

    fn run(&self) -> CheckResult {
        // Known legitimate SUID binaries
        let known_suid = [
            "/usr/bin/passwd",
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/usr/bin/newgrp",
            "/usr/bin/chsh",
            "/usr/bin/chfn",
            "/usr/bin/gpasswd",
            "/usr/bin/mount",
            "/usr/bin/umount",
            "/usr/bin/pkexec",
            "/usr/bin/crontab",
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
            "/usr/lib/openssh/ssh-keysign",
            "/usr/libexec/openssh/ssh-keysign",
        ];

        let mut unusual_suid = Vec::new();

        // Search common directories for SUID binaries
        let search_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"];

        for search_path in &search_paths {
            let path = Path::new(search_path);
            if !path.exists() {
                continue;
            }

            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if let Some(mode) = get_file_mode(&entry_path) {
                        // Check for SUID (0o4000) or SGID (0o2000) bits
                        if mode & 0o6000 != 0 {
                            let path_str = entry_path.to_string_lossy().to_string();
                            if !known_suid.iter().any(|k| path_str.ends_with(k) || *k == path_str) {
                                unusual_suid.push(path_str);
                            }
                        }
                    }
                }
            }
        }

        if unusual_suid.is_empty() {
            CheckResult::pass("No unusual SUID/SGID binaries found")
        } else if unusual_suid.len() <= 5 {
            CheckResult::fail_with_remediation(
                format!(
                    "Found {} unusual SUID/SGID binaries: {}",
                    unusual_suid.len(),
                    unusual_suid.join(", ")
                ),
                Severity::Medium,
                "Review these binaries and remove SUID/SGID if not needed",
            )
        } else {
            CheckResult::fail_with_remediation(
                format!(
                    "Found {} unusual SUID/SGID binaries (showing first 5): {}",
                    unusual_suid.len(),
                    unusual_suid[..5].join(", ")
                ),
                Severity::High,
                "Review and audit all SUID/SGID binaries",
            )
        }
    }
}

struct WorldWritableFilesCheck;

impl RunnableCheck for WorldWritableFilesCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-fs-world-writable",
                "World-Writable Files",
                "System directories should not contain world-writable files without sticky bit",
                CheckCategory::Filesystem,
                Severity::Medium,
            )
            .with_cis_reference("CIS 6.1.10")
        })
    }

    fn run(&self) -> CheckResult {
        // Check key system directories
        let check_paths = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"];
        let mut world_writable = Vec::new();

        for check_path in &check_paths {
            let path = Path::new(check_path);
            if !path.exists() {
                continue;
            }

            for entry in walkdir::WalkDir::new(path)
                .max_depth(2)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path();
                if let Some(mode) = get_file_mode(entry_path) {
                    // Check for world-writable (0o002) without sticky bit (0o1000)
                    if (mode & 0o002 != 0) && (mode & 0o1000 == 0) && entry_path.is_file() {
                        world_writable.push(entry_path.display().to_string());
                        if world_writable.len() >= 10 {
                            break;
                        }
                    }
                }
            }
        }

        if world_writable.is_empty() {
            CheckResult::pass("No world-writable files found in system directories")
        } else {
            CheckResult::fail_with_remediation(
                format!(
                    "Found {} world-writable files: {}{}",
                    world_writable.len(),
                    world_writable[..std::cmp::min(5, world_writable.len())].join(", "),
                    if world_writable.len() > 5 { "..." } else { "" }
                ),
                Severity::Medium,
                "Remove world-writable permission: chmod o-w <file>",
            )
        }
    }
}

struct TmpNoexecCheck;

impl RunnableCheck for TmpNoexecCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-fs-tmp-noexec",
                "/tmp Mounted with noexec",
                "/tmp should be mounted with noexec to prevent execution of malicious files",
                CheckCategory::Filesystem,
                Severity::Medium,
            )
            .with_cis_reference("CIS 1.1.4")
        })
    }

    fn run(&self) -> CheckResult {
        let mounts = read_file(Path::new("/proc/mounts")).unwrap_or_default();

        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[1] == "/tmp" {
                let options = parts[3];
                if options.contains("noexec") {
                    return CheckResult::pass("/tmp is mounted with noexec");
                } else {
                    return CheckResult::fail_with_remediation(
                        "/tmp is not mounted with noexec",
                        Severity::Medium,
                        "Add noexec option to /tmp mount in /etc/fstab",
                    );
                }
            }
        }

        // /tmp might not be a separate mount
        CheckResult::fail_with_remediation(
            "/tmp is not a separate mount point",
            Severity::Low,
            "Consider using a separate partition for /tmp with noexec,nosuid,nodev options",
        )
    }
}

struct HomeDirectoryPermissionsCheck;

impl RunnableCheck for HomeDirectoryPermissionsCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-fs-home-perms",
                "Home Directory Permissions",
                "User home directories should not be world-readable",
                CheckCategory::Filesystem,
                Severity::Medium,
            )
            .with_cis_reference("CIS 6.2.8")
        })
    }

    fn run(&self) -> CheckResult {
        let home_path = Path::new("/home");
        if !home_path.exists() {
            return CheckResult::skipped("/home does not exist");
        }

        let mut insecure_homes = Vec::new();

        if let Ok(entries) = std::fs::read_dir(home_path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    if let Some(mode) = get_file_mode(&entry_path) {
                        // Check if world-readable (0o004) or world-executable (0o001)
                        if mode & 0o007 != 0 {
                            insecure_homes.push(entry_path.display().to_string());
                        }
                    }
                }
            }
        }

        if insecure_homes.is_empty() {
            CheckResult::pass("All home directories have secure permissions")
        } else {
            CheckResult::fail_with_remediation(
                format!("Insecure home directories: {}", insecure_homes.join(", ")),
                Severity::Medium,
                "Set permissions: chmod 700 /home/username or chmod 750 /home/username",
            )
        }
    }
}

// ============================================================================
// Service Checks
// ============================================================================

struct UnnecessaryServicesCheck;

impl RunnableCheck for UnnecessaryServicesCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-svc-unnecessary",
                "Unnecessary Services Disabled",
                "Unnecessary network services should be disabled",
                CheckCategory::Services,
                Severity::Medium,
            )
            .with_cis_reference("CIS 2.2")
        })
    }

    fn run(&self) -> CheckResult {
        let risky_services = [
            ("telnet.socket", "Telnet is unencrypted"),
            ("rsh.socket", "RSH is unencrypted and insecure"),
            ("rlogin.socket", "Rlogin is unencrypted"),
            ("rexec.socket", "Rexec is unencrypted"),
            ("tftp.socket", "TFTP has no authentication"),
            ("xinetd", "Legacy super-server"),
            ("avahi-daemon", "mDNS can leak information"),
            ("cups", "Print server if not needed"),
            ("nfs-server", "NFS server if not needed"),
        ];

        let mut active_risky = Vec::new();

        for (service, reason) in &risky_services {
            if is_service_active(service) || is_service_enabled(service) {
                active_risky.push(format!("{} ({})", service, reason));
            }
        }

        if active_risky.is_empty() {
            CheckResult::pass("No unnecessary risky services detected")
        } else {
            CheckResult::fail_with_remediation(
                format!("Potentially unnecessary services: {}", active_risky.join(", ")),
                Severity::Medium,
                "Disable services with: systemctl disable --now <service>",
            )
        }
    }
}

// ============================================================================
// Audit Checks
// ============================================================================

struct AuditdEnabledCheck;

impl RunnableCheck for AuditdEnabledCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "linux-audit-auditd",
                "Auditd Enabled",
                "The audit daemon should be enabled for security logging",
                CheckCategory::Audit,
                Severity::Medium,
            )
            .with_cis_reference("CIS 4.1.1.1")
        })
    }

    fn run(&self) -> CheckResult {
        if is_service_active("auditd") {
            CheckResult::pass("auditd is active")
        } else if is_service_enabled("auditd") {
            CheckResult::fail_with_remediation(
                "auditd is enabled but not running",
                Severity::Medium,
                "Start auditd: systemctl start auditd",
            )
        } else {
            CheckResult::fail_with_remediation(
                "auditd is not enabled",
                Severity::Medium,
                "Enable auditd: systemctl enable --now auditd",
            )
        }
    }
}

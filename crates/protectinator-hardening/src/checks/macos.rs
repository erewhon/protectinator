//! macOS-specific hardening checks

use super::common::*;
use super::{CheckCategory, CheckRegistry, CheckResult, HardeningCheck, RunnableCheck};
use protectinator_core::Severity;
use std::path::Path;

/// Register all macOS hardening checks
pub fn register_checks(registry: &mut CheckRegistry) {
    // System integrity checks
    registry.register(Box::new(SipStatusCheck));
    registry.register(Box::new(GatekeeperStatusCheck));

    // Encryption checks
    registry.register(Box::new(FileVaultStatusCheck));

    // Network checks
    registry.register(Box::new(MacFirewallCheck));
    registry.register(Box::new(StealthModeCheck));

    // Remote access checks
    registry.register(Box::new(SshRemoteLoginCheck));
    registry.register(Box::new(ScreenSharingCheck));
    registry.register(Box::new(RemoteManagementCheck));
    registry.register(Box::new(RemoteAppleEventsCheck));

    // Privacy/Security checks
    registry.register(Box::new(AutomaticLoginCheck));
    registry.register(Box::new(GuestAccountCheck));
    registry.register(Box::new(ScreenLockCheck));
    registry.register(Box::new(SecureBootCheck));
}

// ============================================================================
// System Integrity Checks
// ============================================================================

struct SipStatusCheck;

impl RunnableCheck for SipStatusCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-sip-enabled",
                "System Integrity Protection (SIP) Enabled",
                "SIP protects critical system files and directories from modification",
                CheckCategory::Integrity,
                Severity::Critical,
            )
            .with_remediation("Enable SIP by booting into Recovery Mode and running 'csrutil enable'")
            .with_reference("https://support.apple.com/en-us/HT204899")
        })
    }

    fn run(&self) -> CheckResult {
        match run_command("csrutil", &["status"]) {
            Ok(output) => {
                if output.contains("enabled") {
                    CheckResult::pass("System Integrity Protection is enabled")
                } else if output.contains("disabled") {
                    CheckResult::fail(
                        "System Integrity Protection is DISABLED - critical security feature missing",
                        Severity::Critical,
                    )
                } else {
                    CheckResult::fail_with_remediation(
                        format!("SIP status unclear: {}", output),
                        Severity::High,
                        "Boot into Recovery Mode and run 'csrutil enable'",
                    )
                }
            }
            Err(e) => CheckResult::error(format!("Could not check SIP status: {}", e)),
        }
    }
}

struct GatekeeperStatusCheck;

impl RunnableCheck for GatekeeperStatusCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-gatekeeper-enabled",
                "Gatekeeper Enabled",
                "Gatekeeper protects against malware by verifying app signatures",
                CheckCategory::Malware,
                Severity::High,
            )
            .with_remediation("Enable Gatekeeper: sudo spctl --master-enable")
            .with_reference("https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df")
        })
    }

    fn run(&self) -> CheckResult {
        match run_command("spctl", &["--status"]) {
            Ok(output) => {
                if output.contains("assessments enabled") {
                    CheckResult::pass("Gatekeeper is enabled")
                } else if output.contains("assessments disabled") {
                    CheckResult::fail(
                        "Gatekeeper is disabled - apps will not be verified",
                        Severity::High,
                    )
                } else {
                    CheckResult::fail_with_remediation(
                        format!("Gatekeeper status unclear: {}", output),
                        Severity::Medium,
                        "Run: sudo spctl --master-enable",
                    )
                }
            }
            Err(e) => CheckResult::error(format!("Could not check Gatekeeper status: {}", e)),
        }
    }
}

// ============================================================================
// Encryption Checks
// ============================================================================

struct FileVaultStatusCheck;

impl RunnableCheck for FileVaultStatusCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-filevault-enabled",
                "FileVault Disk Encryption Enabled",
                "FileVault provides full-disk encryption to protect data at rest",
                CheckCategory::Encryption,
                Severity::High,
            )
            .with_remediation("Enable FileVault in System Preferences > Security & Privacy > FileVault")
            .with_reference("https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785")
        })
    }

    fn run(&self) -> CheckResult {
        match run_command("fdesetup", &["status"]) {
            Ok(output) => {
                if output.contains("FileVault is On") {
                    CheckResult::pass("FileVault disk encryption is enabled")
                } else if output.contains("FileVault is Off") {
                    CheckResult::fail_with_remediation(
                        "FileVault disk encryption is disabled - data is not encrypted at rest",
                        Severity::High,
                        "Enable FileVault in System Preferences > Security & Privacy > FileVault",
                    )
                } else {
                    CheckResult::fail_with_remediation(
                        format!("FileVault status unclear: {}", output),
                        Severity::Medium,
                        "Check FileVault status in System Preferences",
                    )
                }
            }
            Err(e) => CheckResult::error(format!("Could not check FileVault status: {}", e)),
        }
    }
}

// ============================================================================
// Network Checks
// ============================================================================

struct MacFirewallCheck;

impl RunnableCheck for MacFirewallCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-firewall-enabled",
                "Application Firewall Enabled",
                "The macOS application firewall should be enabled to control incoming connections",
                CheckCategory::Network,
                Severity::High,
            )
            .with_remediation("Enable: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on")
        })
    }

    fn run(&self) -> CheckResult {
        let fw_cmd = "/usr/libexec/ApplicationFirewall/socketfilterfw";
        if !file_exists(Path::new(fw_cmd)) {
            return CheckResult::skipped("Application firewall not found");
        }

        match run_command(fw_cmd, &["--getglobalstate"]) {
            Ok(output) => {
                if output.contains("enabled") {
                    CheckResult::pass("Application firewall is enabled")
                } else {
                    CheckResult::fail_with_remediation(
                        "Application firewall is disabled",
                        Severity::High,
                        "Enable with: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                    )
                }
            }
            Err(e) => CheckResult::error(format!("Could not check firewall status: {}", e)),
        }
    }
}

struct StealthModeCheck;

impl RunnableCheck for StealthModeCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-stealth-mode",
                "Firewall Stealth Mode Enabled",
                "Stealth mode prevents the system from responding to probe requests",
                CheckCategory::Network,
                Severity::Medium,
            )
            .with_remediation("Enable: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on")
        })
    }

    fn run(&self) -> CheckResult {
        let fw_cmd = "/usr/libexec/ApplicationFirewall/socketfilterfw";
        if !file_exists(Path::new(fw_cmd)) {
            return CheckResult::skipped("Application firewall not found");
        }

        match run_command(fw_cmd, &["--getstealthmode"]) {
            Ok(output) => {
                if output.contains("enabled") {
                    CheckResult::pass("Stealth mode is enabled")
                } else {
                    CheckResult::fail_with_remediation(
                        "Stealth mode is disabled - system responds to network probes",
                        Severity::Medium,
                        "Enable with: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
                    )
                }
            }
            Err(e) => CheckResult::error(format!("Could not check stealth mode: {}", e)),
        }
    }
}

// ============================================================================
// Remote Access Checks
// ============================================================================

struct SshRemoteLoginCheck;

impl RunnableCheck for SshRemoteLoginCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-remote-login",
                "Remote Login (SSH) Status",
                "Remote Login should be disabled unless specifically needed",
                CheckCategory::Authentication,
                Severity::Medium,
            )
            .with_remediation("Disable: sudo systemsetup -setremotelogin off")
        })
    }

    fn run(&self) -> CheckResult {
        match run_command("systemsetup", &["-getremotelogin"]) {
            Ok(output) => {
                if output.to_lowercase().contains("off") {
                    CheckResult::pass("Remote Login (SSH) is disabled")
                } else if output.to_lowercase().contains("on") {
                    CheckResult::fail_with_remediation(
                        "Remote Login (SSH) is enabled",
                        Severity::Medium,
                        "Disable with: sudo systemsetup -setremotelogin off (if not needed)",
                    )
                } else {
                    CheckResult::pass("Remote Login status could not be determined")
                }
            }
            Err(_) => {
                // Try alternative method via launchctl
                match run_command("launchctl", &["print", "system/com.openssh.sshd"]) {
                    Ok(_) => CheckResult::fail_with_remediation(
                        "SSH daemon appears to be running",
                        Severity::Medium,
                        "Disable if not needed: sudo systemsetup -setremotelogin off",
                    ),
                    Err(_) => CheckResult::pass("SSH daemon does not appear to be running"),
                }
            }
        }
    }
}

struct ScreenSharingCheck;

impl RunnableCheck for ScreenSharingCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-screen-sharing",
                "Screen Sharing Disabled",
                "Screen Sharing should be disabled unless specifically needed",
                CheckCategory::Services,
                Severity::Medium,
            )
            .with_remediation("Disable in System Preferences > Sharing > Screen Sharing")
        })
    }

    fn run(&self) -> CheckResult {
        match run_command("launchctl", &["print", "system/com.apple.screensharing"]) {
            Ok(output) => {
                if output.contains("state = running") {
                    CheckResult::fail_with_remediation(
                        "Screen Sharing is enabled",
                        Severity::Medium,
                        "Disable in System Preferences > Sharing > Screen Sharing",
                    )
                } else {
                    CheckResult::pass("Screen Sharing is not running")
                }
            }
            Err(_) => CheckResult::pass("Screen Sharing is disabled"),
        }
    }
}

struct RemoteManagementCheck;

impl RunnableCheck for RemoteManagementCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-remote-management",
                "Remote Management Disabled",
                "Remote Management (ARD) should be disabled unless specifically needed",
                CheckCategory::Services,
                Severity::Medium,
            )
            .with_remediation("Disable: sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate")
        })
    }

    fn run(&self) -> CheckResult {
        // Check if ARD agent is running
        match run_command("ps", &["aux"]) {
            Ok(output) => {
                if output.contains("ARDAgent") {
                    CheckResult::fail_with_remediation(
                        "Remote Management (ARD) agent is running",
                        Severity::Medium,
                        "Disable in System Preferences > Sharing > Remote Management",
                    )
                } else {
                    CheckResult::pass("Remote Management is not running")
                }
            }
            Err(e) => CheckResult::error(format!("Could not check ARD status: {}", e)),
        }
    }
}

struct RemoteAppleEventsCheck;

impl RunnableCheck for RemoteAppleEventsCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-remote-apple-events",
                "Remote Apple Events Disabled",
                "Remote Apple Events should be disabled for security",
                CheckCategory::Services,
                Severity::Medium,
            )
            .with_remediation("Disable: sudo systemsetup -setremoteappleevents off")
        })
    }

    fn run(&self) -> CheckResult {
        match run_command("systemsetup", &["-getremoteappleevents"]) {
            Ok(output) => {
                if output.to_lowercase().contains("off") {
                    CheckResult::pass("Remote Apple Events are disabled")
                } else if output.to_lowercase().contains("on") {
                    CheckResult::fail_with_remediation(
                        "Remote Apple Events are enabled",
                        Severity::Medium,
                        "Disable with: sudo systemsetup -setremoteappleevents off",
                    )
                } else {
                    CheckResult::pass("Remote Apple Events status unclear")
                }
            }
            Err(_) => CheckResult::skipped("Could not determine Remote Apple Events status"),
        }
    }
}

// ============================================================================
// Privacy/Security Checks
// ============================================================================

struct AutomaticLoginCheck;

impl RunnableCheck for AutomaticLoginCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-auto-login",
                "Automatic Login Disabled",
                "Automatic login should be disabled to require authentication at boot",
                CheckCategory::Authentication,
                Severity::High,
            )
            .with_remediation("Disable in System Preferences > Users & Groups > Login Options")
        })
    }

    fn run(&self) -> CheckResult {
        let plist_path = Path::new("/Library/Preferences/com.apple.loginwindow.plist");

        if file_exists(plist_path) {
            match run_command("defaults", &["read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]) {
                Ok(user) if !user.trim().is_empty() => {
                    CheckResult::fail_with_remediation(
                        format!("Automatic login is enabled for user: {}", user.trim()),
                        Severity::High,
                        "Disable in System Preferences > Users & Groups > Login Options",
                    )
                }
                _ => CheckResult::pass("Automatic login is disabled"),
            }
        } else {
            CheckResult::pass("Automatic login is disabled (no configuration found)")
        }
    }
}

struct GuestAccountCheck;

impl RunnableCheck for GuestAccountCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-guest-account",
                "Guest Account Disabled",
                "The guest account should be disabled to prevent unauthorized access",
                CheckCategory::Authentication,
                Severity::Medium,
            )
            .with_remediation("Disable in System Preferences > Users & Groups > Guest User")
        })
    }

    fn run(&self) -> CheckResult {
        match run_command("defaults", &["read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"]) {
            Ok(output) => {
                if output.trim() == "0" {
                    CheckResult::pass("Guest account is disabled")
                } else if output.trim() == "1" {
                    CheckResult::fail_with_remediation(
                        "Guest account is enabled",
                        Severity::Medium,
                        "Disable in System Preferences > Users & Groups > Guest User",
                    )
                } else {
                    CheckResult::pass("Guest account appears to be disabled")
                }
            }
            Err(_) => CheckResult::pass("Guest account is not configured (likely disabled)"),
        }
    }
}

struct ScreenLockCheck;

impl RunnableCheck for ScreenLockCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-screen-lock",
                "Screen Lock Requires Password",
                "Password should be required immediately when screen lock activates",
                CheckCategory::Authentication,
                Severity::High,
            )
            .with_remediation("Set in System Preferences > Security & Privacy > General")
        })
    }

    fn run(&self) -> CheckResult {
        // Check screensaver password requirement
        // This needs to check the current user's preferences
        match run_command("defaults", &["-currentHost", "read", "com.apple.screensaver", "askForPassword"]) {
            Ok(output) => {
                if output.trim() == "1" {
                    // Check delay
                    match run_command("defaults", &["-currentHost", "read", "com.apple.screensaver", "askForPasswordDelay"]) {
                        Ok(delay) => {
                            let delay_val: i32 = delay.trim().parse().unwrap_or(300);
                            if delay_val <= 5 {
                                CheckResult::pass("Screen lock requires password immediately")
                            } else {
                                CheckResult::fail_with_remediation(
                                    format!("Screen lock password delay is {} seconds", delay_val),
                                    Severity::Medium,
                                    "Set to require password immediately in Security & Privacy settings",
                                )
                            }
                        }
                        Err(_) => CheckResult::pass("Screen lock requires password"),
                    }
                } else {
                    CheckResult::fail_with_remediation(
                        "Screen lock does not require password",
                        Severity::High,
                        "Enable in System Preferences > Security & Privacy > General",
                    )
                }
            }
            Err(_) => CheckResult::fail_with_remediation(
                "Could not verify screen lock password requirement",
                Severity::Medium,
                "Ensure password is required in Security & Privacy settings",
            ),
        }
    }
}

struct SecureBootCheck;

impl RunnableCheck for SecureBootCheck {
    fn definition(&self) -> &HardeningCheck {
        static CHECK: std::sync::OnceLock<HardeningCheck> = std::sync::OnceLock::new();
        CHECK.get_or_init(|| {
            HardeningCheck::new(
                "macos-secure-boot",
                "Secure Boot Enabled",
                "Secure Boot should be set to Full Security on Apple Silicon Macs",
                CheckCategory::Integrity,
                Severity::High,
            )
            .with_remediation("Set in Recovery Mode > Startup Security Utility")
        })
    }

    fn run(&self) -> CheckResult {
        // Check if this is an Apple Silicon Mac
        match run_command("sysctl", &["-n", "machdep.cpu.brand_string"]) {
            Ok(cpu) => {
                if cpu.contains("Apple") {
                    // Apple Silicon - check secure boot status
                    match run_command("bputil", &["-d"]) {
                        Ok(output) => {
                            if output.contains("Full Security") {
                                CheckResult::pass("Secure Boot is set to Full Security")
                            } else if output.contains("Reduced Security") {
                                CheckResult::fail_with_remediation(
                                    "Secure Boot is set to Reduced Security",
                                    Severity::Medium,
                                    "Set to Full Security in Recovery Mode > Startup Security Utility",
                                )
                            } else {
                                CheckResult::pass("Secure Boot status could not be fully determined")
                            }
                        }
                        Err(_) => CheckResult::skipped("Could not check Secure Boot status"),
                    }
                } else {
                    // Intel Mac - check for T2 chip
                    match run_command("system_profiler", &["SPiBridgeDataType"]) {
                        Ok(output) => {
                            if output.contains("T2") {
                                CheckResult::pass("T2 security chip detected (provides secure boot)")
                            } else {
                                CheckResult::skipped("No T2 chip - Secure Boot not available on this Mac")
                            }
                        }
                        Err(_) => CheckResult::skipped("Could not determine secure boot capability"),
                    }
                }
            }
            Err(_) => CheckResult::skipped("Could not determine CPU type"),
        }
    }
}

//! System information command

use protectinator_platform::{detect_os, get_system_info, is_elevated};

pub fn run() -> anyhow::Result<()> {
    let sys_info = get_system_info();
    let os_info = detect_os();

    println!("Protectinator System Information");
    println!("================================\n");

    println!("Operating System: {} {}", sys_info.os_name, sys_info.os_version);
    println!("Architecture: {}", sys_info.architecture);
    println!("Hostname: {}", sys_info.hostname);

    if let Some(kernel) = &sys_info.kernel_version {
        println!("Kernel: {}", kernel);
    }

    if let Some(distro) = &os_info.distribution {
        println!("Distribution: {}", distro);
    }

    println!("\nPrivileges: {}", if sys_info.is_elevated { "Elevated (root)" } else { "Normal user" });

    // Platform-specific info
    #[cfg(target_os = "linux")]
    {
        println!("\nLinux-specific:");
        if protectinator_platform::linux::has_systemd() {
            println!("  - systemd: Available");
        }
        if protectinator_platform::linux::has_auditd() {
            println!("  - auditd: Available");
        }
        if protectinator_platform::linux::selinux_enabled() {
            println!("  - SELinux: Enforcing");
        }
        if protectinator_platform::linux::apparmor_enabled() {
            println!("  - AppArmor: Enabled");
        }
        if let Some(aslr) = protectinator_platform::linux::aslr_status() {
            println!("  - ASLR: {}", match aslr {
                0 => "Disabled",
                1 => "Conservative",
                2 => "Full",
                _ => "Unknown",
            });
        }
    }

    #[cfg(target_os = "macos")]
    {
        println!("\nmacOS-specific:");
        if let Some(sip) = protectinator_platform::macos::sip_enabled() {
            println!("  - SIP: {}", if sip { "Enabled" } else { "Disabled" });
        }
        if let Some(gk) = protectinator_platform::macos::gatekeeper_enabled() {
            println!("  - Gatekeeper: {}", if gk { "Enabled" } else { "Disabled" });
        }
        if let Some(fv) = protectinator_platform::macos::filevault_enabled() {
            println!("  - FileVault: {}", if fv { "Enabled" } else { "Disabled" });
        }
        if let Some(fw) = protectinator_platform::macos::firewall_enabled() {
            println!("  - Firewall: {}", if fw { "Enabled" } else { "Disabled" });
        }
    }

    Ok(())
}

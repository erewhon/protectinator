//! Linux persistence mechanism detection

// Linux persistence locations to check:
// - /etc/cron.*, /var/spool/cron/
// - /etc/systemd/system/, ~/.config/systemd/user/
// - /etc/init.d/, /etc/rc.local
// - ~/.bashrc, ~/.profile, ~/.bash_profile
// - /etc/ld.so.preload

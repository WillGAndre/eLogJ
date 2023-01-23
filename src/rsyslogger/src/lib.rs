use std::process::Command;
use cmd_lib::run_cmd;

// https://docs.rs/syslog/latest/syslog/

// Add auto config to rsyslog file: https://wazuh.com/blog/how-to-configure-rsyslog-client-to-send-events-to-wazuh/

// TODO: check if rsyslog installed; install & set config (remote/local)

pub struct Rsysloggerd {
    log_type: String
}

pub fn __init_rsysloggerd(log_type: String) -> Rsysloggerd {
    Rsysloggerd {
        log_type: log_type
    }.__config_base()
}

impl Rsysloggerd {
    fn __config_base(self) -> Self {
        let boot = "rsyslogger/config.sh";
        if run_cmd! {
            sh ${boot}
        }.is_err() {
            println!("error running rsyslog config");
        }
        self
    }

    pub fn __purge(&self) {
        if run_cmd! {
            rm /etc/rsyslog.d/0-filefwd.conf
        }.is_err() {
            println!("error purging");
        }
    }
}

pub fn remote_log() {
    Command::new("logger")
        .arg("{\"app\":\"core\",\"message\":\"Login failed: 'admin' (Remote IP: '127.0.0.1', X-Forwarded-For: '')\",\"level\":2,\"time\":\"2015-06-09T08:16:29+00:00\",\"@source\":\"ownCloud\"}")
        .spawn()
        .expect("sh command failed to start");
}

pub fn local_info_log(log: String) {
    if run_cmd! {
        logger -i -t elogj.info -p local6.info ${log}
    }.is_err() {
        println!("error local info log");
    }
}

use std::process::Command;

// https://docs.rs/syslog/latest/syslog/

// Add auto config to rsyslog file: https://wazuh.com/blog/how-to-configure-rsyslog-client-to-send-events-to-wazuh/

pub fn remote_log() {
    Command::new("logger")
        .arg("{\"app\":\"core\",\"message\":\"Login failed: 'admin' (Remote IP: '127.0.0.1', X-Forwarded-For: '')\",\"level\":2,\"time\":\"2015-06-09T08:16:29+00:00\",\"@source\":\"ownCloud\"}")
        .spawn()
        .expect("sh command failed to start");
}

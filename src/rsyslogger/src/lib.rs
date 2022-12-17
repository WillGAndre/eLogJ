extern crate syslog;

// https://docs.rs/syslog/latest/syslog/

#[cfg(test)]
mod tests {
    use syslog::{Facility, Formatter3164};

    #[test]
    fn logger_test() {
        let formatter = Formatter3164 {
            facility: Facility::LOG_USER,
            hostname: None,
            process: "myprogram".into(),
            pid: 42,
          };
        
        match syslog::unix(formatter) {
            Err(e)         => println!("impossible to connect to syslog: {:?}", e),
            Ok(mut writer) => {
              writer.err("hello world").expect("could not write error message");
              println!("message to logger sent")
            }
        }
    }
}
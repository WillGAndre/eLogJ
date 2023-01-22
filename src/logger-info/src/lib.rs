use std::{fs::File, io::Write};
use ascii_converter::string_to_decimals;
use serde::{Serialize, Deserialize};
use serde_yaml::{self};

// --- RuleSet yml ---
#[derive(Debug, Serialize, Deserialize)]
struct TrafficType {
    traffic_type: String,
    medium: String,
    block_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RuleSet {
    log_type: String,
    jndi_payload_header: String,
    block: Vec<TrafficType>
}
// ---


// HTTP Headers: default and custom headers from HTTP GET sent to SprinBoot
trait DefHdrs {
    fn set_default_headers(self) -> Self;
    fn set_template_headers(self, payloadkey: &str) -> Self;
}

impl DefHdrs for http::request::Builder {
    fn set_default_headers(self) -> Self {
        self.header("Host", "127.0.0.1:8080")
            .header("User-agent", "curl/7.81.0")
            .header("Accept", "*/*")
            .header("X-Api-Version", "payload")
    }
    fn set_template_headers(self, payloadkey: &str) -> Self {
        self.header("Host", "127.0.0.1:8080")
            .header("User-agent", "curl/7.81.0")
            .header("Accept", "*/*")
            .header(payloadkey, "payload")
    }
}

// Main configuation file: parses yaml to the necessary config files:
// rule-set.dat, header-dec-seq.dat and header-offset.dat
pub fn __config_logger_yml(file: &str) {
    let mut f = File::open(file).expect("Could not open file.");
    let rules: RuleSet = serde_yaml::from_reader(f).expect("Could not read values.");
    let mut ruleset = [0u8; 4usize];
    let payloadkey = rules.jndi_payload_header;
    f = File::create("trf-common/rule-set.dat").unwrap();

    for action in &rules.block {
        if action.traffic_type == "Inbound" {
            if action.medium == "JNDI" {
                if action.block_type == "lookup" {
                    ruleset[2] = 1;
                } else if action.block_type == "request" {
                    ruleset[2] = 2;
                }
            } else if action.medium == "JNDI:LDAP" {
                if action.block_type == "lookup" {
                    ruleset[3] = 1;
                } else if action.block_type == "request" {
                    ruleset[3] = 2;
                }
            }
        } else if action.traffic_type == "Outbound" {
            if action.medium == "TCP" {
                ruleset[0] = 1;
            } else if action.medium == "HTTP" {
                ruleset[0] = 2;
            } else if action.medium == "LDAP" {
                ruleset[1] = 1;
            }
        }
    }
    
    write!(f, "{:?}", ruleset).expect("write header offset to file");
    __config_logger_payload(Some(&payloadkey));
}

/** Logger config files:
 * Writes header name length and the header
 * name offset relative to the HTTP packet to the 
 * header-offset.dat file.
 * 
 * Writes the ascii_convert'ed header name
 * to the header-dec-seq.dat file.
**/
pub fn __config_logger_payload(payloadkey: Option<&str>) {
    if payloadkey == None {
        let hdrn_offset = get_default_header_offset().0;
        let res: Vec<u8> = vec!["X-Api-Version".len() as u8, hdrn_offset];
        write_header(res, None);   
    } else {
        let hdrn_offset = get_template_header_offset(payloadkey.unwrap()).0 as u8;
        let res: Vec<u8> = vec![payloadkey.unwrap().len() as u8, hdrn_offset];
        write_header(res, payloadkey);
    }
}

// Write header key (byte) sequence in: header-seq.dat
// Write header key length and off-set in: header-offset.dat
fn write_header(offsets: Vec<u8>, payloadkey: Option<&str>) {
    let mut res = format!("{:?}", offsets);
    let mut f = File::create("trf-common/header-offset.dat").unwrap();
    write!(f, "{}", res).expect("write header offset to file");
    if payloadkey == None {
        let header_dec: Vec<u8> = string_to_decimals("X-Api-Version").unwrap();
        res = format!("{:?}", header_dec);
        f = File::create("trf-common/header-seq.dat").unwrap();
        write!(f, "{}", res).expect("write header sequence to file");
    } else {
        let header_dec: Vec<u8> = string_to_decimals(payloadkey.unwrap()).unwrap();
        res = format!("{:?}", header_dec);
        f = File::create("trf-common/header-seq.dat").unwrap();
        write!(f, "{}", res).expect("write header sequence to file");
    }
}

/** Header offset:
 * Both functions work the same,
 * each count the HTTP size realtive
 * to the header sequences above (baseline)
 * and return the offsets where the payload
 * will be injected/where logging is performed,
 * this includes the header name and header value
 * offsets.
**/

pub fn get_template_header_offset(payloadkey: &str) -> (usize, usize) {
    let (mut nameoff, mut valueoff): (usize, usize) = (0,0);
    let req = http::Request::builder().set_template_headers(payloadkey);
    let mut hdrlen: usize = "GET / HTTP1./1".len() + 2;
    for (k, v) in req.headers_ref().unwrap() {
        if k.to_string() == payloadkey.to_lowercase() {
            (nameoff = hdrlen, valueoff = hdrlen + 2 + k.to_string().len());
        }
        hdrlen += k.to_string().len() + v.len() + 4; // +2 - :Space ; +2 - \r\n
    }
    hdrlen += 2;
    println!("HTTP header logger entry name and payload offsets: {:#?}\nbaseline HTTP len: {}", (nameoff, valueoff), hdrlen);

    (nameoff, valueoff)
}

pub fn get_default_header_offset() -> (u8, u8) {
    let (mut nameoff, mut valueoff): (usize, usize) = (0,0);
    let req = http::Request::builder().set_default_headers();
    let mut hdrlen: usize = "GET / HTTP1./1".len() + 2;
    for (k, v) in req.headers_ref().unwrap() {
        if k == "x-api-version" {
            (nameoff = hdrlen, valueoff = hdrlen + 2 + k.to_string().len());
        }
        hdrlen += k.to_string().len() + v.len() + 4; // +2 - :Space ; +2 - \r\n
    }
    hdrlen += 2;
    println!("HTTP header logger entry name and payload offsets: {:#?}\nbaseline HTTP header len: {}", (nameoff, valueoff), hdrlen);
    (nameoff.try_into().unwrap(), valueoff.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use crate::{get_default_header_offset, get_template_header_offset, write_header, 
        __config_logger_payload, __config_logger_yml};
    use ascii_converter::string_to_decimals;
    use std::{fs::File, io::Write};

    #[test]
    fn boot_config_test() {
        __config_logger_yml("src/draft-rule-set-default.yml")
    }

    // #[test]
    // fn headers_test() {
    //     get_default_header_offset();
    //     get_template_header_offset("payloadkey");
    // }

    // #[test]
    // fn write_test() {
    //     let header_dec: Vec<u8> = string_to_decimals("X-Api-Version").unwrap();
    //     let res = format!("{:?}", header_dec);
    //     let mut f = File::create("header-seq.dat").unwrap();
    //     write!(f, "{}", res).expect("write to file");
    // }

    // #[test]
    // fn write_header_test() {
    //     let hdrn_offset = get_default_header_offset().0;
    //     let res: Vec<u8> = vec!["X-Api-Version".len() as u8, hdrn_offset];
    //     write_header(res, None);
    // }
}
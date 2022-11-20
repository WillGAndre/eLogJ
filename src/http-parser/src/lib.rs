use std::io::Write;
use ascii_converter::string_to_decimals;

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

    // let header_dec: Vec<u8> = string_to_decimals(payloadkey).unwrap();
    // let mut f = std::fs::File::create("header-seq.dat").unwrap();
    // f.write_all(&header_dec[..]).expect("write header to file");

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
    use crate::{get_default_header_offset, get_template_header_offset};

    #[test]
    fn headers_test() {
        get_default_header_offset();
        get_template_header_offset("payloadkey");
    }
}
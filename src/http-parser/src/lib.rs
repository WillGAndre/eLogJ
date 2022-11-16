// use reqwest::header; // OpenSSL dependency
// use std::collections::HashMap;

// // Logger address + header field that is logged
// // returns offset relative to where payload will be

// trait DefHdrs {
//     fn set_default_headers(self) -> Self;
// }

// impl DefHdrs for http::request::Builder {
//     fn set_default_headers(self) -> Self {
//         self.header("Host", "127.0.0.1:8080")
//             .header("User-agent", "curl/7.81.0")
//             .header("Accept", "*/*")
//     }
// }

// pub async fn parse_header(addr: String, hfield: String) -> Result<(), Box<dyn std::error::Error>> {
//     let req = http::Request::builder()
//         .method("GET")
//         .uri(addr)
//         .set_default_headers()
//         .header(hfield, "payload");

//     let headers = req.headers_ref().unwrap();
//     let mut hdrlen = 0;
//     for (k,v) in headers {
//         hdrlen += len(k) + len(v) + 2;
//     }
//     hdrlen += 2;
//     println!("{:#?} len: {}", headers, hdrlen);

//     Ok(())
// }
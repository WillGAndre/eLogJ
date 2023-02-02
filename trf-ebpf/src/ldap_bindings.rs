pub struct LdapBindgs {
    protocol_req_op_pool: [u8; 3],  // (Request) Protocol Operations
    protocol_res_op_pool: [u8; 3],  // (Response) Protocol Operations
}

impl LdapBindgs {
    pub fn new() -> Self {
        LdapBindgs {
            protocol_req_op_pool: [96, 66, 99],
            protocol_res_op_pool: [97, 100, 101],
        }
    }

    // Verify if protocol op within (response) boundaries
    pub fn check_protocol_op_type(&self, fbyte: u8) -> bool {
        if self.protocol_res_op_pool.iter().all(|op| op != &fbyte) {
            return false
        }
        true
    }

    pub fn get_protocol_op_pool(&self) -> [u8; 3] {
        self.protocol_res_op_pool
    }
}
/*
            Every LDAP packet data starts with the character '0' (byte - 48, ref: ascii table).
            Assuming that LDAP is running on a native port, using both conditions, shallow/medium
            packet inspection can occur.

            LDAP Data Format:
                48 X   -- Beginning of LDAP msg
                   X X Y'   -- MessageID (Y') 
                   Y'' X     -- ProtocolOp (Y'')

            Protocol Operations fields are spaced by two bytes. These operations are identifiable
            by their ID, i.e. 
                bindRequest - 96 , bindResponse - 97 , unbindRequest - 66
                searchRequest - 99 , searchResEntry - 100 , searchResDone - 101
                (as bytes - decimal)
                
            In most cases the offset for the ProtocolOp will always be the same (+5), although
            from testing, it was observable that LDAP searchResEntry packets (with size = 275 bytes)
            had a +1 offset.    (**1)
*/

// TODO: implement struct for each protocol op / LdapBindgs as trait

struct bindResponse {
    byte_id: u8,
    resultCode: u8
}

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
    pub fn check_protocol_op_type(&self, byte: u8) -> bool {
        if self.protocol_res_op_pool.iter().all(|op| op != &byte) {
            return false
        }
        true
    }

    pub fn get_protocol_op_pool(&self) -> [u8; 3] {
        self.protocol_res_op_pool
    }
}
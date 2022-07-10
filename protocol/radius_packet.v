module protocol


// Allowed types of RADIUS messages/packets
//
// Mainly used in RADIUS Server implementation to distinguish between sockets and functions, that should
// process RADIUS packets
pub enum RadiusMsgType {
    // Authentication packet
    auth
    // Accounting packet
    acct
    // Change of Authorisation packet
    coa
}

// Contains all supported Codes of RADIUS message/packet
// as defined in RFC 2865 & RFC 3576
pub enum TypeCode {
    // AccessRequest      = 1
    access_request
    // AccessAccept       = 2
    access_accept
    // AccessReject       = 3
    acces_sreject
    // AccountingRequest  = 4
    accountin_grequest
    // AccountingResponse = 5
    accounting_response
    // AccessChallenge    = 11
    access_challenge
    // StatusServer       = 12
    status_server
    // StatusClient       = 13
    status_client
    // DisconnectRequest  = 40
    disconnect_request
    // DisconnectACK      = 41
    disconnect_ack
    // DisconnectNAK      = 42
    disconnect_nak
    // CoARequest         = 43
    coa_request
    // CoAACK             = 44
    coa_ack
    // CoANAK             = 45
    coa_nak
}

// Represents an attribute, which would be sent to RADIUS Server/client as a part of RadiusPacket
pub struct RadiusAttribute {
    id    u8
    name  string
    value []u8
}

// Represents RADIUS packet
pub struct RadiusPacket {
    id            u8
    code          TypeCode
    authenticator []u8
    attributes    []RadiusAttribute
}


// Implement functions for TypeCode struct
// Convert integer(u8) value into corresponding TypeCode enum
pub fn (type_code TypeCode) from_u8(code u8) -> ?TypeCode {
    match code {
        1u8  { return TypeCode.access_request }
        2u8  { return TypeCode.access_accept }
        3u8  { return TypeCode.access_reject }
        4u8  { return TypeCode.accounting_request }
        5u8  { return TypeCode.accounting_response }
        11u8 { return TypeCode.access_challenge }
        12u8 { return TypeCode.status_server }
        13u8 { return TypeCode.status_client }
        40u8 { return TypeCode.disconnect_request }
        41u8 { return TypeCode.disconnect_ack }
        42u8 { return TypeCode.disconnect_nak }
        43u8 { return TypeCode.coa_request }
        44u8 { return TypeCode.coa_ack }
        45u8 { return TypeCode.coa_nak }
        else { error: format!("Unknown RADIUS code: {}", code) }
    }
}

// Convert TypeCode enum value into corresponding integer(u8)
pub fn to_u8(&self) -> u8 {
    match self {
        TypeCode.access_request      { return 1u8 }
        TypeCode.access_accept       { return 2u8 }
        TypeCode.access_reject       { return 3u8 }
        TypeCode.accounting_request  { return 4u8 }
        TypeCode.accounting_response { return 5u8 }
        TypeCode.access_challenge    { return 11u8 }
        TypeCode.status_server       { return 12u8 }
        TypeCode.status_client       { return 13u8 }
        TypeCode.disconnect_request  { return 40u8 }
        TypeCode.disconnect_ack      { return 41u8 }
        TypeCode.disconnect_nak      { return 42u8 }
        TypeCode.coa_request         { return 43u8 }
        TypeCode.coa_ack             { return 44u8 }
        TypeCode.coa_nak             { return 45u8 }
    }
}
// ====================================


// Implement functions for RadiusAttribute struct
// Creates RadiusAttribute with given name
// Returns None, if ATTRIBUTE with such name is not found in Dictionary
pub fn create_by_name(dictionary Dictionary, attribute_name string, value []u8) ?RadiusAttribute {
    for attribute in dictionary.attributes() {
      if attribute.name() == attribute_name {
        return RadiusAttribute {
            id:    attr.code()
            name:  attr.name()
            value: value
        }
      }
    }

    return error('Attribute with name $attribute_name is not present in dictionary')
}

// Creates RadiusAttribute with given id
//
// Returns None, if ATTRIBUTE with such id is not found in Dictionary
pub fn create_by_id(dictionary Dictionary, attribute_code: u8, value []u8) ?RadiusAttribute {
    for attribute in dictionary.attributes() {
      if attribute.code() == attribute_code {
        return RadiusAttribute {
            id:    attribute_code
            name:  attr.name()
            value: value
        }
      }
    }

    return error('Attribute with code $attribute_code is not present in dictionary')
}

// Overriddes RadiusAttribute value
// Mainly used when building Message-Authenticator
pub fn (rad_attr RadiusAttribute) override_value(new_value []u8) {
    rad_attr.value = new_value
}

/// Returns RadiusAttribute id
pub fn (rad_attr RadiusAttribute) id() u8 {
    rad_attr.id
}

/// Returns RadiusAttribute value
pub fn (rad_attr RadiusAttribute) value() []u8 {
    rad_attr.value
}

/// Returns RadiusAttribute name
pub fn (rad_attr RadiusAttribute) name() string {
    rad_attr.name
}

// Verifies RadiusAttribute value, based on the ATTRIBUTE code type
pub fn (rad_attr RadiusAttribute) verify_original_value(allowed_type SupportedAttributeTypes) bool {
    match allowed_type {
        SupportedAttributeTypes.ascii_string {
          if value := 
        }
        SupportedAttributeTypes.ipv4_addr    { }
        SupportedAttributeTypes.ipv6_addr    { }
        SupportedAttributeTypes.ipv6_prefix  { }
        SupportedAttributeTypes.integer      { }
        SupportedAttributeTypes.date         { }
    }

    match allowed_type {
        Some() => {
            match String::from_utf8(self.value().to_vec()) {
                Ok(_) => Ok(()),
                _     => Err( RadiusError::MalformedAttributeError {error: String::from("invalid ASCII bytes")} )
            }
        },
        Some(SupportedAttributeTypes::IPv4Addr)    => {
            match bytes_to_ipv4_string(self.value()) {
                Ok(_) => Ok(()),
                _     => Err( RadiusError::MalformedAttributeError {error: String::from("invalid IPv4 bytes")} )
            }
        },
        Some(SupportedAttributeTypes::IPv6Addr)    => {
            match bytes_to_ipv6_string(self.value()) {
                Ok(_) => Ok(()),
                _     => Err( RadiusError::MalformedAttributeError {error: String::from("invalid IPv6 bytes")} )
            }
        },
        Some(SupportedAttributeTypes::IPv6Prefix)  => {
            match bytes_to_ipv6_string(self.value()) {
                Ok(_) => Ok(()),
                _     => Err( RadiusError::MalformedAttributeError {error: String::from("invalid IPv6 bytes")} )
            }
        },
        Some(SupportedAttributeTypes::Integer)     => {
            match self.value().try_into() {
                Ok(value) => {
                    bytes_to_integer(value);
                    Ok(())
                },
                _         => Err( RadiusError::MalformedAttributeError {error: String::from("invalid Integer bytes")} )
            }
        } ,
        Some(SupportedAttributeTypes::Date)        => {
            match self.value().try_into() {
                Ok(value) => {
                    bytes_to_timestamp(value);
                    Ok(())
                },
                _         => Err( RadiusError::MalformedAttributeError {error: String::from("invalid Date bytes")} )
            }
        },
        _                                          => Err( RadiusError::MalformedAttributeError {error: String::from("unsupported attribute code type")} )
    }
}

/// Returns RadiusAttribute value, if the attribute is dictionary's ATTRIBUTE with code type string, ipaddr,
/// ipv6addr or aipv6prefix
pub fn original_string_value(&self, allowed_type: &Option<SupportedAttributeTypes>) -> Result<String, RadiusError> {
    match allowed_type {
        Some(SupportedAttributeTypes::AsciiString) => {
            match String::from_utf8(self.value().to_vec()) {
                Ok(value) => Ok(value),
                _         => Err( RadiusError::MalformedAttributeError {error: String::from("invalid ASCII bytes")} )
            }
        },
        Some(SupportedAttributeTypes::IPv4Addr)    => {
            match bytes_to_ipv4_string(self.value()) {
                Ok(value) => Ok(value),
                _         => Err( RadiusError::MalformedAttributeError {error: String::from("invalid IPv4 bytes")} )
            }
        },
        Some(SupportedAttributeTypes::IPv6Addr)    => {
            match bytes_to_ipv6_string(self.value()) {
                Ok(value) => Ok(value),
                _         => Err( RadiusError::MalformedAttributeError {error: String::from("invalid IPv6 bytes")} )
            }
        },
        Some(SupportedAttributeTypes::IPv6Prefix)  => {
            match bytes_to_ipv6_string(self.value()) {
                Ok(value) => Ok(value),
                _         => Err( RadiusError::MalformedAttributeError {error: String::from("invalid IPv6 bytes")} )
            }
        },
        _                                          => Err( RadiusError::MalformedAttributeError {error: String::from("not a String data type")} )
    }
}

/// Returns RadiusAttribute value, if the attribute is dictionary's ATTRIBUTE with code type
/// integer of date
pub fn original_integer_value(&self, allowed_type: &Option<SupportedAttributeTypes>) -> Result<u64, RadiusError> {
    match allowed_type {
        Some(SupportedAttributeTypes::Integer) => {
            match self.value().try_into() {
                Ok(value) => Ok(bytes_to_integer(value) as u64),
                _         => Err( RadiusError::MalformedAttributeError {error: String::from("invalid Integer bytes")} )
            }
        } ,
        Some(SupportedAttributeTypes::Date)    => {
            match self.value().try_into() {
                Ok(value) => Ok(bytes_to_timestamp(value) as u64),
                _         => Err( RadiusError::MalformedAttributeError {error: String::from("invalid Date bytes")} )
            }
        },
        _                                      => Err( RadiusError::MalformedAttributeError {error: String::from("not an Integer data type")} )
    }
}

fn to_bytes(&self) -> Vec<u8> {
    /*
     *    
     *         0               1              2
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
       |     Type      |    Length     |  Value ...
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    *  Taken from https://tools.ietf.org/html/rfc2865#page-23 
    */
    [ &[self.id], &[(2 + self.value.len()) as u8], self.value.as_slice() ].concat()
}
// ====================================


// Implement functions for RadiusPacket struct
// Initialises RADIUS packet with random ID and authenticator
pub fn initialise_packet(code: TypeCode) -> RadiusPacket {
    RadiusPacket {
        id:            RadiusPacket::create_id(),
        code:          code,
        authenticator: RadiusPacket::create_authenticator(),
        attributes:    Vec::new()
    }
}

// Initialises RADIUS packet from raw bytes
pub fn initialise_packet_from_bytes(dictionary: &Dictionary, bytes: &[u8]) -> Result<RadiusPacket, RadiusError> {
    let code           = TypeCode::from_u8(bytes[0])?;
    let id             = bytes[1];
    let authenticator  = bytes[4..20].to_vec();
    let mut attributes = Vec::new();

    let mut last_index = 20;

    while last_index != bytes.len() {
        let attr_id     = bytes[last_index];
        let attr_length = bytes[last_index + 1] as usize;
        let attr_value  = &bytes[(last_index + 2)..=(last_index + attr_length - 1)];

        match RadiusAttribute::create_by_id(dictionary, attr_id, attr_value.to_vec()) {
            Some(attr) => {
                attributes.push(attr);
                last_index += attr_length;
            },
            _          => return Err( RadiusError::MalformedPacketError {error:format!("attribute with ID: {} is not found in dictionary", attr_id)} )
        }
    }

    let mut packet = RadiusPacket{
        id:            id,
        code:          code,
        authenticator: authenticator,
        attributes:    Vec::new()
    };
    packet.set_attributes(attributes);

    Ok(packet)
}

/// Sets attrbiutes
pub fn set_attributes(&mut self, attributes: Vec<RadiusAttribute>) {
    self.attributes = attributes;
}

/// Overrides RadiusPacket id
pub fn override_id(&mut self, new_id: u8) {
    self.id = new_id
}

/// Overrides RadiusPacket authenticator
pub fn override_authenticator(&mut self, new_authenticator: Vec<u8>) {
    self.authenticator = new_authenticator
}

/// Overrides RadiusPacket Message-Authenticator
///
/// Note: would fail if RadiusPacket has no Message-Authenticator attribute defined
pub fn override_message_authenticator(&mut self, new_message_authenticator: Vec<u8>) -> Result<(), RadiusError> {
    match self.attributes.iter_mut().find(|attr| attr.name() == "Message-Authenticator") {
        Some(attr) => {
            attr.override_value(new_message_authenticator);
            Ok(())
        },
        _          => Err( RadiusError::MalformedPacketError {error:String::from("Message-Authenticator attribute not found in packet")} )
    }
}

/// Returns Message-Authenticator value, if exists in RadiusPacket
pub fn message_authenticator(&self) -> Result<&[u8], RadiusError> {
    match self.attributes.iter().find(|attr| attr.name() == "Message-Authenticator") {
        Some(attr) => {
            Ok(attr.value())
        },
        _          => Err( RadiusError::MalformedPacketError {error: String::from("Message-Authenticator attribute not found in packet")} )
    }
}

/// Returns RadiusPacket id
pub fn id(&self) -> u8 {
    self.id
}

/// Returns RadiusPacket authenticator
pub fn authenticator(&self) -> &[u8] {
    &self.authenticator
}

/// Returns RadiusPacket code
pub fn code(&self) -> &TypeCode {
    &self.code
}

/// Returns RadiusPacket attributes
pub fn attributes(&self) -> &[RadiusAttribute] {
    &self.attributes
}

/// Returns RadiusAttribute with given name
pub fn attribute_by_name(&self, name: &str) -> Option<&RadiusAttribute> {
    self.attributes.iter().find(|&attr| attr.name() == name)
}

/// Returns RadiusAttribute with given id
pub fn attribute_by_id(&self, id: u8) -> Option<&RadiusAttribute> {
    self.attributes.iter().find(|&attr| attr.id() == id)
}

/// Converts RadiusPacket into ready-to-be-sent bytes vector
pub fn to_bytes(&mut self) -> Vec<u8> {
    /* Prepare packet for a transmission to server/client
     *
     *          0               1               2         3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Code      |  Identifier   |            Length             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       |                         Authenticator                         |
       |                                                               |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Attributes ...
       +-+-+-+-+-+-+-+-+-+-+-+-+-
     * Taken from https://tools.ietf.org/html/rfc2865#page-14
     * 
     */

    let mut packet_bytes = Vec::new();
    let mut packet_attr  = Vec::new();

    if self.authenticator.is_empty() {
        self.authenticator = Self::create_authenticator();
    }

    for attr in self.attributes.iter() {
        packet_attr.extend(&attr.to_bytes());
    }

    packet_bytes.push(self.code.to_u8());
    packet_bytes.push(self.id);
    packet_bytes.append(&mut Self::packet_length_to_bytes(((20 + packet_attr.len()) as u16).to_be()).to_vec());
    packet_bytes.append(&mut self.authenticator.as_slice().to_vec());
    packet_bytes.append(&mut packet_attr);

    packet_bytes
}

fn create_id() -> u8 {
    rand::thread_rng().gen_range(0u8, 255u8)
}

fn create_authenticator() -> Vec<u8> {
    let mut authenticator: Vec<u8> = Vec::with_capacity(16);
    for _ in 0..16 {
        authenticator.push(rand::thread_rng().gen_range(0u8, 255u8))
    }

    authenticator
}

fn packet_length_to_bytes(length: u16) -> [u8; 2] {
    RadiusPacket::u16_to_u8(length)
}

fn u16_to_u8(u16_data: u16) -> [u8;2] {
    [u16_data as u8, (u16_data >> 8) as u8]
}
// ====================================


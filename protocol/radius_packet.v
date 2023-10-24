module protocol

import encoding.utf8
import rand
import strings
import tools


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
    access_reject
    // AccountingRequest  = 4
    accounting_request
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
    mut:
      value []u8
}

// Represents RADIUS packet
pub struct RadiusPacket {
    code          TypeCode
    mut:
      id            u8
      authenticator []u8
      attributes    []RadiusAttribute
}


// Implement functions for TypeCode struct
// Convert integer(u8) value into corresponding TypeCode enum
pub fn type_code_from_u8(code u8) !TypeCode {
    match code {
        1  { return TypeCode.access_request }
        2  { return TypeCode.access_accept }
        3  { return TypeCode.access_reject }
        4  { return TypeCode.accounting_request }
        5  { return TypeCode.accounting_response }
        11 { return TypeCode.access_challenge }
        12 { return TypeCode.status_server }
        13 { return TypeCode.status_client }
        40 { return TypeCode.disconnect_request }
        41 { return TypeCode.disconnect_ack }
        42 { return TypeCode.disconnect_nak }
        43 { return TypeCode.coa_request }
        44 { return TypeCode.coa_ack }
        45 { return TypeCode.coa_nak }
        else { return error ('Unknown RADIUS code: $code') }
    }
}

// Convert TypeCode enum value into corresponding integer(u8)
pub fn (type_code TypeCode) to_u8() u8 {
    match type_code {
        .access_request      { return 1 }
        .access_accept       { return 2 }
        .access_reject       { return 3 }
        .accounting_request  { return 4 }
        .accounting_response { return 5 }
        .access_challenge    { return 11 }
        .status_server       { return 12 }
        .status_client       { return 13 }
        .disconnect_request  { return 40 }
        .disconnect_ack      { return 41 }
        .disconnect_nak      { return 42 }
        .coa_request         { return 43 }
        .coa_ack             { return 44 }
        .coa_nak             { return 45 }
    }
}
// ====================================


// Implement functions for RadiusAttribute struct
// Creates RadiusAttribute with given name
// Returns None, if ATTRIBUTE with such name is not found in Dictionary
pub fn create_radius_attribute_by_name(dictionary Dictionary, attribute_name string, value []u8) !RadiusAttribute {
    for attribute in dictionary.attributes() {
      if attribute.name() == attribute_name {
        return RadiusAttribute {
            id:    attribute.code()
            name:  attribute.name()
            value: value
        }
      }
    }

    return error('Attribute with name $attribute_name is not present in dictionary')
}

// Creates RadiusAttribute with given id
//
// Returns None, if ATTRIBUTE with such id is not found in Dictionary
pub fn create_radius_attribute_by_id(dictionary Dictionary, attribute_code u8, value []u8) !RadiusAttribute {
    for attribute in dictionary.attributes() {
      if attribute.code() == attribute_code {
        return RadiusAttribute {
            id:    attribute_code
            name:  attribute.name()
            value: value
        }
      }
    }

    return error('Attribute with code $attribute_code is not present in dictionary')
}

// Overriddes RadiusAttribute value
// Mainly used when building Message-Authenticator
pub fn (mut rad_attr RadiusAttribute) override_value(new_value []u8) {
    rad_attr.value = new_value
}

/// Returns RadiusAttribute id
pub fn (rad_attr RadiusAttribute) id() u8 {
    return rad_attr.id
}

/// Returns RadiusAttribute value
pub fn (rad_attr RadiusAttribute) value() []u8 {
    return rad_attr.value
}

/// Returns RadiusAttribute name
pub fn (rad_attr RadiusAttribute) name() string {
    return rad_attr.name
}

// Verifies RadiusAttribute value, based on the ATTRIBUTE code type
pub fn (rad_attr RadiusAttribute) verify_original_value(allowed_type SupportedAttributeTypes) !bool {
    match allowed_type {
        .ascii_string {
          mut builder := strings.new_builder(10)
          builder.write(rad_attr.value()) or { return error('invalid ASCII bytes') }
          act_value := builder.str()
          if utf8.validate_str(act_value) {
              return true
          } else {
              return error('invalid ASCII bytes')
          }
        }
        .ipv4_addr    {
            if _valid := tools.bytes_to_ipv4_string(rad_attr.value()) {
                return true
            } else {
                return error('invalid IPv4 bytes')
            }
        }
        .ipv6_addr    {
            if _valid := tools.bytes_to_ipv6_string(rad_attr.value()) {
                return true
            } else {
                return error('invalid IPv6 bytes')
            }
        }
        .ipv6_prefix  {
            if _valid := tools.bytes_to_ipv6_string(rad_attr.value()) {
                return true
            } else {
                return error('invalid IPv6 bytes')
            }
        }
        .integer      {
            valid := tools.bytes_to_integer(rad_attr.value())
            return true
        }
        .date         {
            valid := tools.bytes_to_timestamp(rad_attr.value())
            return true
        }
    }
}

// Returns RadiusAttribute value, if the attribute is dictionary's ATTRIBUTE with code type string, ipaddr,
// ipv6addr or aipv6prefix
pub fn (rad_attr RadiusAttribute) original_string_value(allowed_type SupportedAttributeTypes) !string {
    match allowed_type {
        .ascii_string {
          mut builder := strings.new_builder(10)
          builder.write(rad_attr.value()) or { return error('invalid ASCII bytes') }
          act_value := builder.str()
          if utf8.validate_str(act_value) {
              return act_value
          } else {
              return error('invalid ASCII bytes')
          }
        }
        .ipv4_addr    {
            if valid := tools.bytes_to_ipv4_string(rad_attr.value()) {
                return valid
            } else {
                return error('invalid IPv4 bytes')
            }
        }
        .ipv6_addr    {
            if valid := tools.bytes_to_ipv6_string(rad_attr.value()) {
                return valid
            } else {
                return error('invalid IPv6 bytes')
            }
        }
        .ipv6_prefix  {
            if valid := tools.bytes_to_ipv6_string(rad_attr.value()) {
                return valid
            } else {
                return error('invalid IPv6 bytes')
            }
        }
        else { return error('not a String data type') }
    }
}

/// Returns RadiusAttribute value, if the attribute is dictionary's ATTRIBUTE with code type
/// integer of date
pub fn (rad_attr RadiusAttribute) original_integer_value(allowed_type SupportedAttributeTypes) !u64 {
    match allowed_type {
        .integer      {
            valid := tools.bytes_to_integer(rad_attr.value())
            return u64(valid)
        }
        .date         {
            valid := tools.bytes_to_timestamp(rad_attr.value())
            return valid
        }
        else { return error('not an Integer data type') }
    }
}

fn (rad_attr RadiusAttribute) to_bytes() []u8 {
    /*
     *    
     *         0               1              2
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
       |     Type      |    Length     |  Value ...
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    *  Taken from https://tools.ietf.org/html/rfc2865#page-23 
    */
    mut bytes := []u8{}
    bytes << rad_attr.id
    bytes << u8(2 + rad_attr.value.len)
    bytes << rad_attr.value
    return bytes
}
// ====================================


// Implement functions for RadiusPacket struct
// Initialises RADIUS packet with random ID and authenticator
pub fn initialise_radius_packet(code TypeCode) RadiusPacket {
    return RadiusPacket {
        id:            create_id()
        code:          code
        authenticator: create_authenticator()
        attributes:    []RadiusAttribute{}
    }
}

// Initialises RADIUS packet from raw bytes
pub fn initialise_radius_packet_from_bytes(dictionary Dictionary, bytes []u8) !RadiusPacket {
    code           := type_code_from_u8(bytes[0]) or { return error('Invalid TypeCode: $bytes[0]') }
    id             := bytes[1]
    authenticator  := bytes[4..20]
    mut attributes := []RadiusAttribute{}

    mut last_index := 20

    for {
        attr_id     := bytes[last_index]
        attr_length := bytes[last_index + 1]
        attr_value  := bytes[(last_index + 2)..(last_index + attr_length)]

        if rad_attribute := create_radius_attribute_by_id(dictionary, attr_id, attr_value) {
            attributes << rad_attribute
            last_index += attr_length
        } else {
            return error('attribute with ID: $attr_id is not found in dictionary')
        }

        if last_index == bytes.len { break }
    }

    mut packet := RadiusPacket{
        id:            id
        code:          code
        authenticator: authenticator
        attributes:    []RadiusAttribute{}
    }
    packet.set_attributes(attributes)

    return packet
}

// Sets attrbiutes
pub fn (mut rad_packet RadiusPacket) set_attributes(attributes []RadiusAttribute) {
    rad_packet.attributes = attributes
}

// Overrides RadiusPacket id
pub fn (mut rad_packet RadiusPacket) override_id(new_id u8) {
    rad_packet.id = new_id
}

// Overrides RadiusPacket authenticator
pub fn (mut rad_packet RadiusPacket) override_authenticator(new_authenticator []u8) {
    rad_packet.authenticator = new_authenticator
}

// Overrides RadiusPacket Message-Authenticator
//
// Note: would fail if RadiusPacket has no Message-Authenticator attribute defined
pub fn (mut rad_packet RadiusPacket) override_message_authenticator(new_message_authenticator []u8) !bool {
    for mut attribute in rad_packet.attributes {
        if attribute.name() == "Message-Authenticator" {
            attribute.override_value(new_message_authenticator)
            return true
        }
    }

    return error('Message-Authenticator attribute not found in packet')
}

// Returns Message-Authenticator value, if exists in RadiusPacket
pub fn (rad_packet RadiusPacket) message_authenticator() ![]u8 {
    for attribute in rad_packet.attributes {
        if attribute.name() == "Message-Authenticator" {
            return attribute.value()
        }
    }

    return error('Message-Authenticator attribute not found in packet')
}

// Returns RadiusPacket id
pub fn (rad_packet RadiusPacket) id() u8 {
    return rad_packet.id
}

// Returns RadiusPacket authenticator
pub fn (rad_packet RadiusPacket) authenticator() []u8 {
    return rad_packet.authenticator
}

// Returns RadiusPacket code
pub fn (rad_packet RadiusPacket) code() TypeCode {
    return rad_packet.code
}

// Returns RadiusPacket attributes
pub fn (rad_packet RadiusPacket) attributes() []RadiusAttribute {
    return rad_packet.attributes
}

// Returns RadiusAttribute with given name
pub fn (rad_packet RadiusPacket) attribute_by_name(name string) !RadiusAttribute {
    for attribute in rad_packet.attributes {
        if attribute.name() == name {
            return attribute
        }
    }

    return error('Attribute with name: $name not found in packet')
}

// Returns RadiusAttribute with given id
pub fn (rad_packet RadiusPacket) attribute_by_id(id u8) !RadiusAttribute {
    for attribute in rad_packet.attributes {
        if attribute.id() == id {
            return attribute
        }
    }

    return error('Attribute with id: $id not found in packet')
}

// Converts RadiusPacket into ready-to-be-sent bytes vector
pub fn (mut rad_packet RadiusPacket) to_bytes() []u8 {
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

    mut packet_bytes := []u8{}
    mut packet_attr  := []u8{}

    if rad_packet.authenticator.len == 0 {
        rad_packet.authenticator = create_authenticator()
    }

    for attr in rad_packet.attributes {
        packet_attr << attr.to_bytes()
    }

    packet_bytes << rad_packet.code.to_u8()
    packet_bytes << rad_packet.id
    packet_bytes << packet_length_to_bytes(u16(20 + packet_attr.len))
    packet_bytes << rad_packet.authenticator
    packet_bytes << packet_attr

    return packet_bytes
}
// ====================================


// Helpers
fn create_id() u8 {
    id := rand.u32_in_range(0, 256) or { 0 }
    return u8(id)
}

fn create_authenticator() []u8 {
    mut authenticator := []u8{cap: 16}
    for _ in 0..16 {
        id := rand.u32_in_range(0, 256) or { 0 }
        authenticator << u8(id)
    }

    return authenticator
}

fn packet_length_to_bytes(length u16) []u8 {
    return u16_to_u8(length)
}

fn u16_to_u8(u16_data u16) []u8 {
    return [u8(u16_data >> 8), u8(u16_data >> 0)]
}
// ====================================

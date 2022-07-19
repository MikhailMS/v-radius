//! Shared base for RADIUS Client & Server implementations
module protocol

import crypto.hmac
import crypto.md5


// Generic struct that holds Server & Client common functions and attributes
pub struct Host {
  mut:
    auth_port  u16
    acct_port  u16
    coa_port   u16
    dictionary Dictionary
}

// Implement functions for Host struct
// 
// Initialises host instance with all required fields
pub fn initialise_host(auth_port u16, acct_port u16, coa_port u16, dictionary Dictionary) Host {
    return Host { auth_port, acct_port, coa_port, dictionary }
}

// Initialises host instance only with Dictionary (ports should be set through *set_port()*,
// otherwise default to 0)
pub fn initialise_host_with_dictionary(dictionary Dictionary) Host {
    return Host {
        auth_port:  0,
        acct_port:  0,
        coa_port:   0,
        dictionary: dictionary
    }
}

// Sets remote port, that responsible for specific RADIUS Message Type
pub fn (mut host Host) set_port(msg_type RadiusMsgType, port u16) {
    match msg_type {
        .auth { host.auth_port = port }
        .acct { host.acct_port = port }
        .coa  { host.coa_port  = port }
    }
}

// Creates RadiusAttribute with given name (name is checked against Dictionary)
pub fn (host Host) create_attribute_by_name(attribute_name string, value []u8) ?RadiusAttribute {
    return create_radius_attribute_by_name(host.dictionary, attribute_name, value)
}

// Creates RadiusAttribute with given id (id is checked against Dictionary)
pub fn (host Host) create_attribute_by_id(attribute_id u8, value []u8) ?RadiusAttribute {
    return create_radius_attribute_by_id(host.dictionary, attribute_id, value)
}

// Returns port of RADIUS server, that receives given type of RADIUS message/packet
pub fn (host Host) port(code TypeCode) ?u16 {
    match code {
        .access_request     { return host.auth_port }
        .accounting_request { return host.acct_port }
        .coa_request        { return host.coa_port }
        else                { return error('Incorrect TypeCode: $code') }
    }
}

// Returns host's dictionary instance
pub fn (host Host) dictionary() Dictionary {
    return host.dictionary
}

// Returns VALUE from dictionary with given attribute & value name
pub fn (host Host) dictionary_value_by_attr_and_value_name(attr_name string, value_name string) ?DictionaryValue {
    for value in host.dictionary.values() {
        if value.name() == value_name && value.attribute_name() == attr_name {
            return value
        }
    }
    return error('Value is not found: attr_name {$attr_name}, value_name {$value_name}')
}

// Returns ATTRIBUTE from dictionary with given id
pub fn (host Host) dictionary_attribute_by_id(packet_attr_id u8) ?DictionaryAttribute {
    for attr in host.dictionary.attributes() {
        if attr.code() == packet_attr_id {
            return attr
        }
    }
    return error('Attribute is not found: packet_attr_id {$packet_attr_id}')
}

// Returns ATTRIBUTE from dictionary with given name
pub fn (host Host) dictionary_attribute_by_name(packet_attr_name string) ?DictionaryAttribute {
    for attr in host.dictionary.attributes() {
        if attr.name() == packet_attr_name {
            return attr
        }
    }
    return error('Attribute is not found: packet_attr_name {$packet_attr_name}')
}

// Initialises RadiusPacket from bytes
pub fn (host Host) initialise_packet_from_bytes(packet []u8) ?RadiusPacket {
    return initialise_radius_packet_from_bytes(host.dictionary, packet)
}

// Verifies that RadiusPacket attributes have valid values
//
// Note: doesn't verify Message-Authenticator attribute, because it is HMAC-MD5 hash, not an
// ASCII string
pub fn (host Host) verify_packet_attributes(packet []u8) ?bool {
    ignore_attribute := "Message-Authenticator"
    packet_tmp       := initialise_radius_packet_from_bytes(host.dictionary, packet)?

    for packet_attr in packet_tmp.attributes() {
        if packet_attr.name() != ignore_attribute {
            dict_attr           := host.dictionary_attribute_by_id(packet_attr.id())?
            dict_attr_data_type := dict_attr.code_type()

            if _verify := packet_attr.verify_original_value(dict_attr_data_type) {
                continue
            } else {
                return err
            }
        }
    }
    return true
}

// Verifies Message-Authenticator value
pub fn (host Host) verify_message_authenticator(secret string, packet []u8) ?bool {
    packet_tmp      := initialise_radius_packet_from_bytes(host.dictionary, packet)?
    packet_msg_auth := packet_tmp.message_authenticator()?

    hash := hmac.new(secret.bytes(), packet, md5.sum, md5.block_size)

    if hash == packet_msg_auth {
        return true
    } else {
        return error('Packet Message-Authenticator mismatch')
    }
}
// ====================================

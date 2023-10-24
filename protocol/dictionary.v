module protocol

import os


const (
  comment_prefix = "#"
)


// Represents a list of supported data types
// as defined in RFC 2865
pub enum SupportedAttributeTypes {
    // V's String
    ascii_string
    // V's u32
    integer
    // V's u64
    date
    // V's [u8;4]
    ipv4_addr
    // V's [u8;16]
    ipv6_addr
    // V's V;18]
    ipv6_prefix
}

// Represents an ATTRIBUTE from RADIUS dictionary file
pub struct DictionaryAttribute {
    /*
     * |--------|   name  | code | code type |
     * ATTRIBUTE User-Name   1      string
     */
    name        string
    vendor_name string
    code        u8
    code_type   SupportedAttributeTypes
}

// Represents a VALUE from RADIUS dictionary file
pub struct DictionaryValue {
    attribute_name string
    value_name     string
    vendor_name    string
    value          string
}

// Represents a VENDOR from RADIUS dictionary file
pub struct DictionaryVendor {
    name string
    id   u16
}

// Represents RADIUS dictionary
pub struct Dictionary {
    attributes []DictionaryAttribute
    values     []DictionaryValue
    vendors    []DictionaryVendor
}


// Implement functions for DictionaryAttribute struct
pub fn (dict_attr DictionaryAttribute) name() string {
    return dict_attr.name
}

pub fn (dict_attr DictionaryAttribute) code() u8 {
    return dict_attr.code
}

pub fn (dict_attr DictionaryAttribute) code_type() SupportedAttributeTypes {
    return dict_attr.code_type
}
// ====================================


// Implement functions for DictionaryValue struct
pub fn (dict_value DictionaryValue) name() string {
    return dict_value.value_name
}

pub fn (dict_value DictionaryValue) attribute_name() string {
    return dict_value.attribute_name
}

pub fn (dict_value DictionaryValue) value() string {
    return dict_value.value
}
// ====================================


// Implement functions for Dictionary struct
// Creates Dictionary from a RADIUS dictionary file
pub fn dict_from_file(file_path string) !Dictionary {
    mut attributes  := []DictionaryAttribute{}
    mut values      := []DictionaryValue{}
    mut vendors     := []DictionaryVendor{}
    mut vendor_name := ""

    contents := os.read_lines(file_path)!

    lines := contents
      .filter(it.len_utf8() > 0)
      .filter(!it.contains(comment_prefix))

    for line in lines {
        parsed_line := line.split(" ").filter(it.len_utf8() > 0)
        match parsed_line[0] {
            "ATTRIBUTE"    { parse_attribute(parsed_line, vendor_name, mut &attributes) }
            "VALUE"        { parse_value(parsed_line, vendor_name, mut &values) }
            "VENDOR"       { parse_vendor(parsed_line, mut &vendors) }
            "BEGIN-VENDOR" { vendor_name = parsed_line[1] }
            "END-VENDOR"   { vendor_name = "" }
            else           { continue }
        }
    }
    return Dictionary { attributes, values, vendors }
}

// Returns parsed DictionaryAttributes
pub fn (dict Dictionary) attributes() []DictionaryAttribute {
    return dict.attributes
}

// Returns parsed DictionaryValues
pub fn (dict Dictionary) values() []DictionaryValue {
    return dict.values
}

// Returns parsed DictionaryVendors
pub fn (dict Dictionary) vendors() []DictionaryVendor {
    return dict.vendors
}
// ====================================


// Helper functions
fn assign_attribute_type(code_type string) ?SupportedAttributeTypes {
    match code_type {
        "string"     { return SupportedAttributeTypes.ascii_string }
        "integer"    { return SupportedAttributeTypes.integer }
        "date"       { return SupportedAttributeTypes.date }
        "ipaddr"     { return SupportedAttributeTypes.ipv4_addr }
        "ipv6addr"   { return SupportedAttributeTypes.ipv6_addr }
        "ipv6prefix" { return SupportedAttributeTypes.ipv6_prefix }
        else         { return none }
    }
}

fn parse_attribute(parsed_line []string, vendor_name string, mut attributes []DictionaryAttribute) {
    attributes << DictionaryAttribute {
        name:        parsed_line[1]
        vendor_name: vendor_name
        code:        parsed_line[2].u8()
        code_type:   assign_attribute_type(parsed_line[3]) or { return }
    }
}

fn parse_value(parsed_line []string, vendor_name string, mut values []DictionaryValue) {
    values << DictionaryValue {
        attribute_name: parsed_line[1]
        value_name:     parsed_line[2]
        vendor_name:    vendor_name
        value:          parsed_line[3]
    }
}

fn parse_vendor(parsed_line []string, mut vendors []DictionaryVendor) {
    vendors << DictionaryVendor {
        name: parsed_line[1]
        id:   parsed_line[2].u16()
    }
}
// ====================================

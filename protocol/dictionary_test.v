module protocol


fn test_from_file() {
    dictionary_path := "../dict_examples/test_dictionary_dict"

    dict := dict_from_file(dictionary_path) or { panic(err) }

    mut attributes := []DictionaryAttribute{}
    attributes << DictionaryAttribute {
        name:        "User-Name"
        vendor_name: ""
        code:        1
        code_type:   SupportedAttributeTypes.ascii_string
    }
    attributes << DictionaryAttribute {
        name:        "NAS-IP-Address"
        vendor_name: ""
        code:        4
        code_type:   SupportedAttributeTypes.ipv4_addr
    }
    attributes << DictionaryAttribute {
        name:        "NAS-Port-Id"
        vendor_name: ""
        code:        5
        code_type:   SupportedAttributeTypes.integer
    }
    attributes << DictionaryAttribute {
        name:        "Framed-Protocol"
        vendor_name: ""
        code:        7
        code_type:   SupportedAttributeTypes.integer
    }
    attributes << DictionaryAttribute {
        name:        "Somevendor-Name"
        vendor_name: "Somevendor"
        code:        1
        code_type:   SupportedAttributeTypes.ascii_string
    }
    attributes << DictionaryAttribute {
        name:        "Somevendor-Number"
        vendor_name: "Somevendor"
        code:        2
        code_type:   SupportedAttributeTypes.integer
    }
    attributes << DictionaryAttribute {
        name:        "Test-IP"
        vendor_name: ""
        code:        25
        code_type:   SupportedAttributeTypes.ipv4_addr
    }

    mut values := []DictionaryValue{}
    values << DictionaryValue {
        attribute_name: "Framed-Protocol"
        value_name:     "PPP"
        vendor_name:    ""
        value:          "1"
    }
    values << DictionaryValue {
        attribute_name: "Somevendor-Number"
        value_name:     "Two"
        vendor_name:    "Somevendor"
        value:          "2"
    }

    mut vendors := []DictionaryVendor{}
    vendors << DictionaryVendor {
        name: "Somevendor"
        id:   10
    }

    expected_dict := Dictionary { attributes, values, vendors }
    assert dict == expected_dict
}

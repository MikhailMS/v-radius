module protocol


fn test_get_dictionary_value_by_attr_and_value_name() {
    dictionary := dict_from_file("../dict_examples/integration_dict") or { panic(err) }
    host       := initialise_host(u8(1812), u8(1813), u8(3799), dictionary)

    dict_value := host.dictionary_value_by_attr_and_value_name("Service-Type", "Login-User") or { panic(err) }

    assert "Service-Type" == dict_value.attribute_name()
    assert "Login-User"   == dict_value.name()
    assert "1"            == dict_value.value()
}

fn test_get_dictionary_value_by_attr_and_value_name_error() {
    dictionary := dict_from_file("../dict_examples/integration_dict") or { panic(err) }
    host       := initialise_host(u8(1812), u8(1813), u8(3799), dictionary)

    if dict_value := host.dictionary_value_by_attr_and_value_name("Service-Type", "Lin-User") {
        assert false
    } else {
        assert true
    }
}

fn test_get_dictionary_attribute_by_id() {
    dictionary := dict_from_file("../dict_examples/integration_dict") or { panic(err) }
    host       := initialise_host(u8(1812), u8(1813), u8(3799), dictionary)

    dict_attr := host.dictionary_attribute_by_id(u8(80)) or { panic(err) }

    assert "Message-Authenticator"              == dict_attr.name()
    assert u8(80)                               == dict_attr.code()
    assert SupportedAttributeTypes.ascii_string == dict_attr.code_type()

}

fn test_get_dictionary_attribute_by_id_error() {
    dictionary := dict_from_file("../dict_examples/integration_dict") or { panic(err) }
    host       := initialise_host(u8(1812), u8(1813), u8(3799), dictionary)

    if dict_attr := host.dictionary_attribute_by_id(255) {
        assert false
    } else {
        assert true
    }
}

fn test_verify_packet_attributes() {
    dictionary := dict_from_file("../dict_examples/integration_dict") or { panic(err) }
    host       := initialise_host(u8(1812), u8(1813), u8(3799), dictionary)

    packet_bytes := [u8(4), 43, 0, 83, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100]

    if verify := host.verify_packet_attributes(packet_bytes) {
        assert true
    } else {
        assert false
    }
}

fn test_verify_packet_attributes_fail() {
    dictionary := dict_from_file("../dict_examples/integration_dict") or { panic(err) }
    host       := initialise_host(u8(1812), u8(1813), u8(3799), dictionary)

    packet_bytes := [u8(4), 43, 0, 82, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 5, 192, 168, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100]

    if verify := host.verify_packet_attributes(packet_bytes) {
        assert false
    } else {
        assert true
    }
}

module protocol

import tools


fn test_radius_attribute_create_by_name() {
    dictionary_path := "../dict_examples/test_dictionary_dict"
    dict            := dict_from_file(dictionary_path) or { panic(err) }

    expected := RadiusAttribute {
        id:      1
        name:  "User-Name"
        value: [u8(1),2,3]
    }

    if result := create_radius_attribute_by_name(dict, "User-Name", [u8(1),2,3]) {
        assert expected == result
    } else {
        assert false
    }
}
fn test_radius_attribute_create_by_id() {
    dictionary_path := "../dict_examples/test_dictionary_dict"
    dict            := dict_from_file(dictionary_path) or { panic(err) }

    expected := RadiusAttribute {
        id:    5
        name:  "NAS-Port-Id"
        value: [u8(1),2,3]
    }

    if result := create_radius_attribute_by_id(dict, 5, [u8(1),2,3]) {
      assert expected == result
    } else {
      assert false
    }
}

fn test_initialise_packet_from_bytes() {
    dictionary_path := "../dict_examples/test_dictionary_dict"
    dict            := dict_from_file(dictionary_path) or { panic(err) }

    nas_ip_addr_bytes    := tools.ipv4_string_to_bytes("192.168.1.10") or { []u8{} }
    framed_ip_addr_bytes := tools.ipv4_string_to_bytes("10.0.0.100")  or { []u8{} }
    attributes           := [
        create_radius_attribute_by_name(dict, "NAS-IP-Address",     nas_ip_addr_bytes) or { return },
        create_radius_attribute_by_name(dict, "NAS-Port-Id",        tools.integer_to_bytes(0)) or { return },
        create_radius_attribute_by_name(dict, "NAS-Identifier",     "trillian".bytes()) or { return },
        create_radius_attribute_by_name(dict, "Called-Station-Id",  "00-04-5F-00-0F-D1".bytes()) or { return },
        create_radius_attribute_by_name(dict, "Calling-Station-Id", "00-01-24-80-B3-9C".bytes()) or { return },
        create_radius_attribute_by_name(dict, "Framed-IP-Address",  framed_ip_addr_bytes) or { return }
    ]
    authenticator       := [u8(215), 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73]
    mut expected_packet := initialise_radius_packet(TypeCode.accounting_request)
    expected_packet.set_attributes(attributes)
    expected_packet.override_id(43)
    expected_packet.override_authenticator(authenticator)

    bytes             := [u8(4), 43, 0, 83, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100]
    packet_from_bytes := initialise_radius_packet_from_bytes(dict, bytes) or { return }

    assert expected_packet == packet_from_bytes
}

fn test_radius_packet_override_id() {
    attributes := []RadiusAttribute{}
    new_id     := u8(50)

    mut packet := initialise_radius_packet(TypeCode.accounting_request)
    packet.set_attributes(attributes)
    packet.override_id(new_id)

    assert new_id == packet.id()
}
fn test_radius_packet_override_authenticator() {
    attributes        := []RadiusAttribute{}
    new_authenticator := [u8(0), 25, 100, 56, 13]

    mut packet := initialise_radius_packet(TypeCode.access_request)
    packet.set_attributes(attributes)
    packet.override_authenticator(new_authenticator)

    assert new_authenticator == packet.authenticator()
}
fn test_radius_packet_to_bytes() {
    attributes        := []RadiusAttribute{}
    new_id            := u8(50)
    new_authenticator := [u8(0), 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3]

    exepcted_bytes := [u8(1), 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3]
    mut packet     := initialise_radius_packet(TypeCode.access_request)
    packet.set_attributes(attributes)
    packet.override_id(new_id)
    packet.override_authenticator(new_authenticator)

    assert exepcted_bytes == packet.to_bytes()
}

fn test_override_message_authenticator_fail() {
    dictionary_path := "../dict_examples/integration_dict"
    dict            := dict_from_file(dictionary_path) or { panic(err) }

    nas_ip_addr_bytes    := tools.ipv4_string_to_bytes("192.168.1.10") or { []u8{} }
    framed_ip_addr_bytes := tools.ipv4_string_to_bytes("10.0.0.100") or { []u8{} }
    attributes           := [
        create_radius_attribute_by_name(&dict, "NAS-IP-Address",     nas_ip_addr_bytes) or { return },
        create_radius_attribute_by_name(&dict, "NAS-Port-Id",        tools.integer_to_bytes(0)) or { return },
        create_radius_attribute_by_name(&dict, "NAS-Identifier",     "trillian".bytes()) or { return },
        create_radius_attribute_by_name(&dict, "Called-Station-Id",  "00-04-5F-00-0F-D1".bytes()) or { return },
        create_radius_attribute_by_name(&dict, "Calling-Station-Id", "00-01-24-80-B3-9C".bytes()) or { return },
        create_radius_attribute_by_name(&dict, "Framed-IP-Address",  framed_ip_addr_bytes) or { return }
    ]

    new_message_authenticator := [u8(1), 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153]
    mut packet                := initialise_radius_packet(TypeCode.accounting_request)
    packet.set_attributes(attributes)

    if status := packet.override_message_authenticator(new_message_authenticator) {
      assert false
    } else {
      assert "Message-Authenticator attribute not found in packet" == err.msg()
    }
}

fn test_override_message_authenticator_success() {
    dictionary_path := "../dict_examples/integration_dict"
    dict            := dict_from_file(dictionary_path) or { panic(err) }

    attributes := [
        create_radius_attribute_by_name(&dict, "Calling-Station-Id",    "00-01-24-80-B3-9C".bytes()) or { return },
        create_radius_attribute_by_name(&dict, "Message-Authenticator", [u8(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) or { return }
    ]

    new_message_authenticator := [u8(1), 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153]
    mut packet                := initialise_radius_packet(TypeCode.access_request)
    new_id                    := u8(50)
    new_authenticator         := [u8(0), 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3]

    packet.set_attributes(attributes)
    packet.override_id(new_id)
    packet.override_authenticator(new_authenticator)

    expected_packet_bytes := [u8(1), 50, 0, 57, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 80, 18, 1, 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153]

    if status := packet.override_message_authenticator(new_message_authenticator) {
      assert expected_packet_bytes == packet.to_bytes()
    } else {
      assert false
    }
}

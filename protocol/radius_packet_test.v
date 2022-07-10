module protocol

fn test_radius_attribute_create_by_name() {
    dictionary_path := "../dict_examples/test_dictionary_dict"
    dict            := dict_from_file(dictionary_path) or { panic(err) }

    expected := RadiusAttribute {
        id    1
        name  "User-Name"
        value [1,2,3]
    }

    assert expected == RadiusAttribute::create_by_name(&dict, "User-Name", [1,2,3])
}
fn test_radius_attribute_create_by_id() {
    dictionary_path := "../dict_examples/test_dictionary_dict"
    dict            := dict_from_file(dictionary_path) or { panic(err) }

    expected = RadiusAttribute {
        id:    5,
        name:  String::from("NAS-Port-Id"),
        value: vec![1,2,3]
    }

    assert expected == RadiusAttribute::create_by_id(&dict, 5, vec![1,2,3])
}

fn test_initialise_packet_from_bytes() {
    dictionary_path := "../dict_examples/test_dictionary_dict"
    dict            := dict_from_file(dictionary_path) or { panic(err) }

    nas_ip_addr_bytes    := ipv4_string_to_bytes("192.168.1.10")
    framed_ip_addr_bytes := ipv4_string_to_bytes("10.0.0.100")
    attributes           := [
        RadiusAttribute::create_by_name(&dict, "NAS-IP-Address",     nas_ip_addr_bytes),
        RadiusAttribute::create_by_name(&dict, "NAS-Port-Id",        integer_to_bytes(0)),
        RadiusAttribute::create_by_name(&dict, "NAS-Identifier",     "trillian"),
        RadiusAttribute::create_by_name(&dict, "Called-Station-Id",  "00-04-5F-00-0F-D1"),
        RadiusAttribute::create_by_name(&dict, "Calling-Station-Id", "00-01-24-80-B3-9C"),
        RadiusAttribute::create_by_name(&dict, "Framed-IP-Address",  framed_ip_addr_bytes).unwrap()
    ]
    authenticator       = [215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73]
    mut expected_packet = RadiusPacket::initialise_packet(TypeCode.accounting_request)
    expected_packet.set_attributes(attributes)
    expected_packet.override_id(43)
    expected_packet.override_authenticator(authenticator)

    bytes             = [4, 43, 0, 83, 215, 189, 213, 172, 57, 94, 141, 70, 134, 121, 101, 57, 187, 220, 227, 73, 4, 6, 192, 168, 1, 10, 5, 6, 0, 0, 0, 0, 32, 10, 116, 114, 105, 108, 108, 105, 97, 110, 30, 19, 48, 48, 45, 48, 52, 45, 53, 70, 45, 48, 48, 45, 48, 70, 45, 68, 49, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 8, 6, 10, 0, 0, 100]
    packet_from_bytes = RadiusPacket::initialise_packet_from_bytes(&dict, &bytes)

    assert expected_packet == packet_from_bytes
}

fn test_radius_packet_override_id() {
    attributes := []RadiusAttribute
    new_id     := 50

    mut packet = RadiusPacket::initialise_packet(TypeCode.accounting_request)
    packet.set_attributes(attributes)
    packet.override_id(new_id)

    assert new_id == packet.id()
}
fn test_radius_packet_override_authenticator() {
    attributes        := []RadiusAttribute
    new_authenticator := [0, 25, 100, 56, 13]

    mut packet = RadiusPacket::initialise_packet(TypeCode.access_request)
    packet.set_attributes(attributes)
    packet.override_authenticator(new_authenticator)

    assert new_authenticator == packet.authenticator()
}
fn test_radius_packet_to_bytes() {
    attributes        := []RadiusAttribute
    new_id            := 50
    new_authenticator := [0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3]

    exepcted_bytes := [1, 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3]
    mut packet = RadiusPacket::initialise_packet(TypeCode.access_request)
    packet.set_attributes(attributes)
    packet.override_id(new_id)
    packet.override_authenticator(new_authenticator)

    assert exepcted_bytes == packet.to_bytes()
}

fn test_override_message_authenticator_fail() {
    dictionary_path := "../dict_examples/integration_dict"
    dict            := dict_from_file(dictionary_path) or { panic(err) }

    nas_ip_addr_bytes    := ipv4_string_to_bytes("192.168.1.10")
    framed_ip_addr_bytes := ipv4_string_to_bytes("10.0.0.100")
    attributes           := [
        RadiusAttribute::create_by_name(&dict, "NAS-IP-Address",     nas_ip_addr_bytes),
        RadiusAttribute::create_by_name(&dict, "NAS-Port-Id",        integer_to_bytes(0)),
        RadiusAttribute::create_by_name(&dict, "NAS-Identifier",     "trillian"),
        RadiusAttribute::create_by_name(&dict, "Called-Station-Id",  "00-04-5F-00-0F-D1"),
        RadiusAttribute::create_by_name(&dict, "Calling-Station-Id", "00-01-24-80-B3-9C"),
        RadiusAttribute::create_by_name(&dict, "Framed-IP-Address",  framed_ip_addr_bytes)
    ]

    new_message_authenticator := [1, 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153]
    mut packet                := RadiusPacket::initialise_packet(TypeCode.accounting_request)
    packet.set_attributes(attributes)

    match packet.override_message_authenticator(new_message_authenticator) {
        Err(err) { assert "Radius packet is malformed" == err.to_string() }
        _        { assert false }
    }
}

fn test_override_message_authenticator_success() {
    dictionary_path := "../dict_examples/integration_dict"
    dict            := dict_from_file(dictionary_path) or { panic(err) }

    let attributes = vec![
        RadiusAttribute::create_by_name(&dict, "Calling-Station-Id",    "00-01-24-80-B3-9C"),
        RadiusAttribute::create_by_name(&dict, "Message-Authenticator", [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    ]

    new_message_authenticator := [1, 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153]
    mut packet                := RadiusPacket::initialise_packet(TypeCode.access_request)
    new_id                    := 50
    new_authenticator         := [0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3]

    packet.set_attributes(attributes)
    packet.override_id(new_id)
    packet.override_authenticator(new_authenticator)

    let expected_packet_bytes := [1, 50, 0, 57, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153, 0, 1, 2, 3, 31, 19, 48, 48, 45, 48, 49, 45, 50, 52, 45, 56, 48, 45, 66, 51, 45, 57, 67, 80, 18, 1, 50, 0, 20, 0, 25, 100, 56, 13, 0, 67, 34, 39, 12, 88, 153]

    match packet.override_message_authenticator(new_message_authenticator) {
        Err(_) => assert false,
        _      => assert expected_packet_bytes == packet.to_bytes()
    }
}

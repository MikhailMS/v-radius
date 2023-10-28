module tools

// fn test_ipv6_to_bytes_wo_subnet() {
//   ipv6_bytes := ipv6_string_to_bytes("fc66::1")?
//     assert ipv6_bytes == [252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
// }
// fn test_bytes_to_ipv6_string_wo_subnet() {
//     expected_ipv6_string := "fc66::1"
//     ipv6_bytes           := [252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

//     assert expected_ipv6_string == bytes_to_ipv6_string(ipv6_bytes)?
// }

// fn test_ipv6_to_bytes_w_subnet() {
//     ipv6_bytes := ipv6_string_to_bytes("fc66::1/64")?
//     assert ipv6_bytes == [0, 64, 252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
// }
// fn test_bytes_to_ipv6_string_w_subnet() {
//     expected_ipv6_string := "fc66::1/64"
//     ipv6_bytes           := [0, 64, 252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

//     assert expected_ipv6_string == bytes_to_ipv6_string(ipv6_bytes)?
// }

fn test_ipv4_string_to_bytes() {
    ipv4_bytes := ipv4_string_to_bytes("192.1.10.1") or { []u8{} }

    assert ipv4_bytes == [u8(192), 1, 10, 1]
}

fn test_ipv4_string_w_subnet_to_bytes() {
    ipv4_bytes := ipv4_string_to_bytes("192.1.10.1/32") or { []u8{} }

    assert ipv4_bytes == [u8(0), 32, 192, 1, 10, 1]
}

fn test_ipv4_string_w_negative_subnet_to_bytes() {
    if ipv4_bytes := ipv4_string_to_bytes("192.1.10.1/-1") {
      assert false
    } else {
      assert err.str() == "IPv4 Subnet must be in the range [0, 32], you provided -1"
    }
}

fn test_ipv4_string_w_big_subnet_to_bytes() {
    if ipv4_bytes := ipv4_string_to_bytes("192.1.10.1/33") {
      assert false
    } else {
      assert err.str() == "IPv4 Subnet must be in the range [0, 32], you provided 33"
    }
}


fn test_ipv4_bytes_to_string() {
    ipv4_string := bytes_to_ipv4_string([u8(192), 1, 10, 1]) or { "" }

    assert ipv4_string == "192.1.10.1"
}

fn test_encrypt_data() {
    secret        := "secret"
    authenticator := [u8(1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]

    encrypted_bytes := encrypt_data("password".bytes(), authenticator, secret.bytes())

    assert encrypted_bytes == [u8(135), 116, 155, 239, 226, 89, 90, 221, 62, 29, 218, 130, 102, 174, 191, 250]
}

fn test_encrypt_data_long() {
    secret        := "secret"
    authenticator := [u8(1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]

    encrypted_bytes := encrypt_data("a very long password, which will need multiple iterations".bytes(), authenticator, secret.bytes())
    assert encrypted_bytes == [u8(150), 53, 158, 249, 231, 79, 8, 213, 81, 115, 189, 162, 22, 207, 204, 137, 193,
                               149, 82, 147, 72, 149, 79, 48, 187, 199, 194, 200, 246, 6, 186, 182, 220, 19, 227, 32, 26, 20, 9, 152,
                               63, 40, 41, 91, 212, 22, 158, 54, 91, 247, 151, 67, 250,170, 105, 94, 20, 105, 120, 196, 237, 191, 99, 69]
}

fn test_encrypt_data_limit_long() {
    secret        := "secret"
    authenticator := [u8(1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    data          := "a very long password, which will need multiple iterations. a very long password, which will need multiple iterations. a very long password, which will need multiple iterations. a very long password, which will need multiple iterations. a very long passw"

    encrypted_bytes := encrypt_data(data.bytes(), authenticator, secret.bytes())
    assert encrypted_bytes == [u8(150), 53, 158, 249, 231, 79, 8, 213, 81, 115, 189, 162, 22, 207, 204, 137, 193, 149, 82, 147, 72, 149, 79, 48, 187, 199, 194, 200,
                               246, 6, 186, 182, 220, 19, 227, 32, 26, 20, 9, 152, 63, 40, 41, 91, 212, 22, 158, 54, 91, 247, 151, 67, 250, 170, 105, 94, 20, 71,
                               88, 165, 205, 201, 6, 55, 222, 205, 192, 227, 172, 93, 166, 15, 33, 86, 56, 181, 52, 4, 49, 190, 186, 17, 125, 50, 140, 52, 130, 194,
                               125, 93, 177, 65, 217, 195, 23, 75, 175, 219, 244, 156, 133, 145, 20, 176, 36, 90, 16, 77, 148, 221, 251, 155, 9, 107, 213, 140, 107,
                               112, 161, 99, 6, 108, 106, 33, 69, 192, 191, 98, 30, 147, 197, 72, 160, 234, 50, 243, 195, 62, 72, 225, 19, 63, 28, 221, 164, 43, 67,
                               63, 206, 208, 124, 254, 202, 118, 229, 58, 180, 210, 100, 149, 120, 97, 23, 203, 197, 139, 244, 241, 175, 232, 149, 77, 43, 231, 27, 56,
                               250, 58, 251, 6, 203, 197, 190, 78, 83, 127, 164, 31, 211, 52, 74, 92, 36, 250, 236, 210, 72, 52, 55, 248, 161, 160, 95, 102, 63, 190, 43,
                               253, 224, 114, 62, 23, 11, 242, 186, 91, 132, 14, 76, 171, 26, 1, 51, 78, 144, 50, 228, 212, 47, 104, 98, 60, 245, 1, 103, 217, 49, 105,
                               38, 108, 93, 85, 224, 227, 33, 50, 144, 0, 233, 54, 174, 67, 174, 101, 189, 41]
}

fn test_decrypt_data() {
    secret        := "secret"
    authenticator := [u8(1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]

    expected_data  := "password"
    encrypted_data := [u8(135), 116, 155, 239, 226, 89, 90, 221, 62, 29, 218, 130, 102, 174, 191, 250]

    decrypted_data := decrypt_data(encrypted_data, authenticator, secret.bytes())

    assert expected_data.bytes() == decrypted_data
}

fn test_descrypt_data_long() {
    secret        := "secret"
    authenticator := [u8(1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]

    expected_data  := "a very long password, which will need multiple iterations"
    encrypted_data := [u8(150), 53, 158, 249, 231, 79, 8, 213, 81, 115, 189, 162, 22, 207, 204, 137, 193,
                       149, 82, 147, 72, 149, 79, 48, 187, 199, 194, 200, 246, 6, 186, 182, 220, 19, 227, 32, 26, 20, 9, 152, 63,
                       40, 41, 91, 212, 22, 158, 54, 91, 247, 151, 67, 250,170, 105, 94, 20, 105, 120, 196, 237, 191, 99, 69]

    decrypted_data := decrypt_data(encrypted_data, authenticator, secret.bytes())
    assert expected_data.bytes() == decrypted_data
}

fn test_descrypt_data_limit_long() {
    secret        := "secret"
    authenticator := [u8(1), 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]

    expected_data  := "a very long password, which will need multiple iterations. a very long password, which will need multiple iterations. a very long password, which will need multiple iterations. a very long password, which will need multiple iterations. a very long passw"
    encrypted_data := [u8(150), 53, 158, 249, 231, 79, 8, 213, 81, 115, 189, 162, 22, 207, 204, 137, 193, 149, 82, 147, 72, 149, 79, 48, 187, 199, 194, 200,
                              246, 6, 186, 182, 220, 19, 227, 32, 26, 20, 9, 152, 63, 40, 41, 91, 212, 22, 158, 54, 91, 247, 151, 67, 250, 170, 105, 94, 20, 71,
                              88, 165, 205, 201, 6, 55, 222, 205, 192, 227, 172, 93, 166, 15, 33, 86, 56, 181, 52, 4, 49, 190, 186, 17, 125, 50, 140, 52, 130, 194,
                              125, 93, 177, 65, 217, 195, 23, 75, 175, 219, 244, 156, 133, 145, 20, 176, 36, 90, 16, 77, 148, 221, 251, 155, 9, 107, 213, 140, 107,
                              112, 161, 99, 6, 108, 106, 33, 69, 192, 191, 98, 30, 147, 197, 72, 160, 234, 50, 243, 195, 62, 72, 225, 19, 63, 28, 221, 164, 43, 67,
                              63, 206, 208, 124, 254, 202, 118, 229, 58, 180, 210, 100, 149, 120, 97, 23, 203, 197, 139, 244, 241, 175, 232, 149, 77, 43, 231, 27, 56,
                              250, 58, 251, 6, 203, 197, 190, 78, 83, 127, 164, 31, 211, 52, 74, 92, 36, 250, 236, 210, 72, 52, 55, 248, 161, 160, 95, 102, 63, 190, 43,
                              253, 224, 114, 62, 23, 11, 242, 186, 91, 132, 14, 76, 171, 26, 1, 51, 78, 144, 50, 228, 212, 47, 104, 98, 60, 245, 1, 103, 217, 49, 105,
                              38, 108, 93, 85, 224, 227, 33, 50, 144, 0, 233, 54, 174, 67, 174, 101, 189, 41]

    decrypted_data := decrypt_data(encrypted_data, authenticator, secret.bytes())
    assert expected_data.bytes() == decrypted_data
}

fn test_salt_encrypt_data() {
    secret        := "secret"
    authenticator := []u8{len: 16}

    plaintext      := "password"
    encrypted_data := [u8(0x85), 0x9a, 0xe3, 0x88, 0x34, 0x49, 0xf2, 0x1e, 0x14, 0x4c, 0x76, 0xc8, 0xb2, 0x1a, 0x1d, 0x4f, 0x0c, 0xdc]
    salt           := encrypted_data[..2]

    assert encrypted_data == salt_encrypt_data(plaintext.bytes(), authenticator, salt, secret.bytes())
}

fn test_salt_encrypt_data_long() {
    secret        := "secret"
    authenticator := []u8{len: 16}


    plaintext_long      := "a very long password, which will need multiple iterations"
    encrypted_data_long := [u8(0x85), 0xd9, 0x61, 0x72, 0x75, 0x37, 0xcf, 0x15, 0x20,
                            0x19, 0x3b, 0x38, 0x39, 0x0e, 0x42, 0x21, 0x9b, 0x5e, 0xcb, 0x93, 0x25, 0x7d, 0xb4, 0x07,
                            0x0c, 0xc1, 0x52, 0xcf, 0x38, 0x76, 0x29, 0x02, 0xc7, 0xb1, 0x29, 0xdf, 0x63, 0x96, 0x26,
                            0x1a, 0x27, 0xe5, 0xc3, 0x13, 0x78, 0xa7, 0x97, 0xd8, 0x97, 0x9a, 0x45, 0xc3, 0x70, 0xd3,
                            0xe4, 0xe2, 0xae, 0xd0, 0x55, 0x77, 0x19, 0xa5, 0xb6, 0x44, 0xe6, 0x8a]
    salt                := encrypted_data_long[..2]

    assert encrypted_data_long == salt_encrypt_data(plaintext_long.bytes(), authenticator, salt, secret.bytes())
}

fn test_salt_decrypt_data() {
    secret        := "secret"
    authenticator := []u8{len: 16}

    plaintext      := "password"
    encrypted_data := [u8(0x85), 0x9a, 0xe3, 0x88, 0x34, 0x49, 0xf2, 0x1e, 0x14, 0x4c, 0x76, 0xc8, 0xb2, 0x1a, 0x1d, 0x4f, 0x0c, 0xdc]

    assert plaintext.bytes()  == salt_decrypt_data(encrypted_data, authenticator, secret.bytes()) or { [] }
}

fn test_salt_decrypt_data_long() {
    secret        := "secret"
    authenticator := []u8{len: 16}

    plaintext_long      := "a very long password, which will need multiple iterations"
    encrypted_data_long := [u8(0x85), 0xd9, 0x61, 0x72, 0x75, 0x37, 0xcf, 0x15, 0x20,
                            0x19, 0x3b, 0x38, 0x39, 0x0e, 0x42, 0x21, 0x9b, 0x5e, 0xcb, 0x93, 0x25, 0x7d, 0xb4, 0x07,
                            0x0c, 0xc1, 0x52, 0xcf, 0x38, 0x76, 0x29, 0x02, 0xc7, 0xb1, 0x29, 0xdf, 0x63, 0x96, 0x26,
                            0x1a, 0x27, 0xe5, 0xc3, 0x13, 0x78, 0xa7, 0x97, 0xd8, 0x97, 0x9a, 0x45, 0xc3, 0x70, 0xd3,
                            0xe4, 0xe2, 0xae, 0xd0, 0x55, 0x77, 0x19, 0xa5, 0xb6, 0x44, 0xe6, 0x8a]

    assert plaintext_long.bytes() == salt_decrypt_data(encrypted_data_long, authenticator, secret.bytes()) or { [] }
}

fn test_integer_to_bytes() {
    integer := u32(10000)

    assert [u8(0), 0, 39, 16] == integer_to_bytes(integer)
}

fn test_bytes_to_integer() {
    integer_bytes := [u8(0), 0, 39, 16]

    assert u32(10000) == bytes_to_integer(integer_bytes)
}

fn test_timestamp_to_bytes() {
    timestamp := u64(1598523933)

    assert [u8(0), 0, 0, 0, 95, 71, 138, 29] == timestamp_to_bytes(timestamp)
}

fn test_bytes_to_timestamp() {
    timestamp_bytes := [u8(0), 0, 0, 0, 95, 71, 138, 29]

    assert u64(1598523933) == bytes_to_timestamp(timestamp_bytes)
}

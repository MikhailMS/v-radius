module tools

import arrays
import crypto.md5

// Converts IPv6 Address string into vector of bytes
//
// Should be used for any Attribute of type **ipv6addr** or **ipv6prefix** to ensure value is encoded correctly
pub fn ipv6_string_to_bytes(ipv6 string) ?[]u8 {
//     parsed_ipv6 := ipv6.split("/")
//     mut bytes   := [18]u8
//     ipv6_address           = Ipv6Addr::from_str(parsed_ipv6[0]).map_err(|error| RadiusError::MalformedIpAddrError { error: error.to_string() })?;

//     if parsed_ipv6.len() == 2 {
//         bytes.append( &mut u16_to_be_bytes(parsed_ipv6[1].parse::<u16>().unwrap()).to_vec() )
//     }
//     bytes.append(&mut ipv6_address.octets().to_vec());
//     Ok(bytes)
    return [u8(0)]
}


// Converts IPv6 bytes into IPv6 string
pub fn bytes_to_ipv6_string(ipv6 []u8) ?string {
//     if ipv6.len() == 18 {
//         // Case with subnet
//         let subnet = u16_from_be_bytes(&ipv6[0..2]);
//         let ipv6_string = Ipv6Addr::new(
//             u16_from_be_bytes(&ipv6[2..4]),
//             u16_from_be_bytes(&ipv6[4..6]),
//             u16_from_be_bytes(&ipv6[6..8]),
//             u16_from_be_bytes(&ipv6[8..10]),
//             u16_from_be_bytes(&ipv6[10..12]),
//             u16_from_be_bytes(&ipv6[12..14]),
//             u16_from_be_bytes(&ipv6[14..16]),
//             u16_from_be_bytes(&ipv6[16..]),
//             ).to_string();
//         Ok(format!("{}/{}",ipv6_string, subnet))
//     } else {
//         // Case without subnet
//         Ok(Ipv6Addr::new(
//             u16_from_be_bytes(&ipv6[0..2]),
//             u16_from_be_bytes(&ipv6[2..4]),
//             u16_from_be_bytes(&ipv6[4..6]),
//             u16_from_be_bytes(&ipv6[6..8]),
//             u16_from_be_bytes(&ipv6[8..10]),
//             u16_from_be_bytes(&ipv6[10..12]),
//             u16_from_be_bytes(&ipv6[12..14]),
//             u16_from_be_bytes(&ipv6[14..]),
//             ).to_string())
//     }
    return ""
}


// Converts IPv4 Address string into vector of bytes
//
// Should be used for any Attribute of type **ipaddr** to ensure value is encoded correctly
pub fn ipv4_string_to_bytes(ipv4 string) ?[]u8 {
    if ipv4.contains("/") {
        return error('Subnets are not supported for IPv4: $ipv4')
    }

    mut bytes := []u8{}
    mut index := 0
    for group in ipv4.trim_space().split(".").map(it.u8()) {
        bytes.insert(index, group)
        index += 1
    }

    return bytes
}

// Converts IPv4 bytes into IPv4 string
pub fn bytes_to_ipv4_string(ipv4 []u8) ?string {
    if ipv4.len != 4 {
        return error('Malformed IPv4: $ipv4')
    }

    return ipv4.map(it.str()).join(".")
}

// Converts u32 into vector of bytes
//
// Should be used for any Attribute of type **integer** to ensure value is encoded correctly
pub fn integer_to_bytes(integer u32) []u8 {
    b1 := u8((integer >> 24) & 0xff)
    b2 := u8((integer >> 16) & 0xff)
    b3 := u8((integer >> 8) & 0xff)
    b4 := u8(integer & 0xff)

    return [b1, b2, b3, b4]
}

// Converts integer bytes into u32
pub fn bytes_to_integer(integer []u8) ?u32 {
    mut result := u32(0)
    for i in 0..4 {
        result = (result << 8) | integer[i]
    }

    return result
}

// Converts timestamp (u64) into vector of bytes
//
// Should be used for any Attribute of type **date** to ensure value is encoded correctly
pub fn timestamp_to_bytes(timestamp u64) []u8 {
    b1 := u8((timestamp >> 56) & 0xff)
    b2 := u8((timestamp >> 48) & 0xff)
    b3 := u8((timestamp >> 40) & 0xff)
    b4 := u8((timestamp >> 32) & 0xff)
    b5 := u8((timestamp >> 24) & 0xff)
    b6 := u8((timestamp >> 16) & 0xff)
    b7 := u8((timestamp >> 8) & 0xff)
    b8 := u8(timestamp & 0xff)

    return [b1, b2, b3, b4, b5, b6, b7, b8]
}

// Converts timestamp bytes into u64
pub fn bytes_to_timestamp(timestamp []u8) ?u64 {
    mut result := u64(0)
    for i in 0..8 {
        result = (result << 8) | timestamp[i]
    }

    return result
}

// Encrypts data since RADIUS packet is sent in plain text
//
// Should be used to encrypt value of **User-Password** attribute (but could also be used to
// encrypt any data)
pub fn encrypt_data(data []u8, authenticator []u8, secret []u8) []u8 {
    /* Step 1. Ensure that data buffer's length is multiple of 16
    *  Step 2. Construct hash:
    *
    *  On each iteration:
    *   1. read 16 elements from data
    *   2. calculate MD5 hash for: provided secret + (authenticator(on 1st iteration) or 16 elements of result from previous iteration (2nd+ iteration))
    *   3. execute bitwise XOR between each of 16 elements of MD5 hash and data buffer and record it in results vector
    *
    * Step 3. Return result vector
    */
    mut hash := []u8{len: 16, cap: 16}
    padding  := 16 - data.len % 16

    mut initial_data := []u8{cap: data.len + padding}
    mut result       := []u8{cap: data.len + padding}
    initial_data << data
    initial_data << hash[..padding]

    encrypt_helper(mut result, mut initial_data, authenticator.clone(), mut hash, secret)

    return result
}

// Decrypts data since RADIUS packet is sent in plain text
//
// Should be used to decrypt value of **User-Password** attribute (but could also be used to
// decrypt any data)
pub fn decrypt_data(data []u8, authenticator []u8, secret []u8) []u8 {
    /* 
     * To decrypt the data, we need to apply the same algorithm as in encrypt_data()
     * but with small change
     *
     *  On each iteration:
     *   1. read 16 elements from data
     *   2. calculate MD5 hash for: provided secret + (authenticator(on 1st iteration) or 16 elements of data buffer from previous iteration (2nd+ iteration))
     *   3. execute bitwise XOR between each of 16 elements of MD5 hash and data buffer and record it in results vector
     *
     */
    mut result      := []u8{cap: data.len}
    mut hash        := []u8{len: 16, cap: 16}
    mut prev_result := authenticator.clone()

    for data_chunk in arrays.chunk(data, 16) {
        mut md5  := md5.new()
        md5.write(secret) or {}
        md5.write(prev_result) or {}

        hash = md5.checksum()

        for i in 0..16 {
          hash[i] ^= data_chunk[i]
        }

        result << hash
        prev_result = data_chunk.clone()
    }

    for {
        result.pop()
        if result[result.len-1] != 0 { break }
    }

    return result
}

// Encrypts data with salt since RADIUS packet is sent in plain text
//
// Should be used for RADIUS Tunnel-Password Attribute
pub fn salt_encrypt_data(data []u8, authenticator []u8, salt []u8, secret []u8) []u8 {
    if data.len == 0 {
        return []u8{}
    }

    padding := 15 - data.len % 16

    mut salted_authenticator := []u8{cap: 18}
    mut hash                 := []u8{len: 16, cap: 16}
    mut result               := []u8{cap: data.len + padding} // make buffer big enough to fit the salt & encrypted data
    mut initial_data         := []u8{cap: data.len + padding}

    result << salt

    initial_data << salt
    initial_data << u8(data.len)
    initial_data << data
    initial_data << hash[..padding]

    salted_authenticator << authenticator
    salted_authenticator << salt

    encrypt_helper(mut result, mut initial_data[2..], salted_authenticator, mut hash, secret)

    return result
}

/// Decrypts data with salt since RADIUS packet is sent in plain text
///
/// Should be used for RADIUS Tunnel-Password Attribute
pub fn salt_decrypt_data(data []u8, authenticator []u8, secret []u8) ?[]u8 {
    /*
     * The salt decryption behaves almost the same as normal Password encryption in RADIUS
     * The main difference is the presence of a two byte salt, which is appended to the authenticator
     */
    if data.len <= 1 {
        return error('salt encrypted attribute too short')
    }
    if data.len <= 3 {
        // There is a Salt or there is a salt & data.len(): Both cases mean "Password is empty"
        return []u8{}
    }

    mut salted_authenticator := []u8{cap: 18}
    salted_authenticator << authenticator
    salted_authenticator << data[..2]

    mut result      := []u8{cap: data.len-2}
    mut hash        := []u8{len: 16, cap: 16}
    mut prev_result := salted_authenticator.clone()

    for data_chunk in arrays.chunk(data[2..], 16) {
        mut md5 := md5.new()
        md5.write(secret)  or { 0 }
        md5.write(prev_result) or { 0 }
        hash = md5.checksum()

        for i in 0..16 {
          hash[i] ^= data_chunk[i]
        }

        result << hash
        prev_result = data_chunk.clone()
    }

    target_len := result.first()
    result.delete(0)

    if target_len > data.len - 3 {
        return error('Tunnel Password is too long (shared secret might be wrong)')
    }

    result.trim(target_len)
    return result[..]
}

// -----------------------------------------
fn encrypt_helper(mut output []u8, mut data []u8, authenticator []u8, mut hash []u8, secret []u8) {
    mut iteration := 1
    mut tmp       := []u8{}

    for {
        mut md5 := md5.new()
        md5.write(secret) or { 0 }
        if iteration == 1 {
          md5.write(authenticator) or { 0 }
        } else {
          md5.write(tmp) or { 0 }
        }
        hash = md5.checksum()

        iteration += 1

        for i in 0..16 {
          data[i] ^= hash[i]
        }

        if data.len == 16 {
          output << data[..16]
          tmp = data[..16]
          data.clear()
        } else {
          output << data[..16]
          tmp = data[..16]
          data   = data[16..]
        }

        if data.len == 0 { break }
    }
}

// fn u16_to_be_bytes(u16_data u16) -> [u8;2] {
//     u16_data.to_be_bytes()
// }

// fn u16_from_be_bytes(bytes: &[u8]) -> u16 {
//     u16::from_be_bytes(bytes.try_into().expect("slice with incorrect length"))
// }
// -----------------------------------------

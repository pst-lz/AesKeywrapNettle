using Test, AesKeywrap

function test_wrap_unwrap(kekstring, datastring, ivstring, cipherstring)
    test_correct :: Bool = false

    kek = hex2bytes(kekstring)
    data = hex2bytes(datastring)
    iv = hex2bytes(ivstring)
    cipherref = hex2bytes(cipherstring)
    
    # wrap
    cipher = aes_wrap_key(kek, data, iv) 
    test_correct =  lowercase(bytes2hex(cipher)) == lowercase(cipherstring)

    # unwrap
    plain = aes_unwrap_key(kek, cipherref, iv)
    test_correct = test_correct && lowercase(bytes2hex(plain)) == lowercase(datastring)
    return test_correct
end

@testset "tests from rfc3394" begin
    # tests from rfc3394
    # 4.1 
    name1 = "Wrap 128 bits of Key Data with a 128-bit KEK"
    kekstring1 = "000102030405060708090A0B0C0D0E0F"
    datastring1 = "00112233445566778899AABBCCDDEEFF"
    ivstring1 = "A6A6A6A6A6A6A6A6"
    cipherstring1 = "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"
    @test test_wrap_unwrap(kekstring1, datastring1, ivstring1, cipherstring1)

    # 4.2
    name2 = "Wrap 128 bits of Key Data with a 192-bit KEK"
    kekstring2 = "000102030405060708090A0B0C0D0E0F1011121314151617"
    datastring2 = "00112233445566778899AABBCCDDEEFF"
    ivstring2 = "A6A6A6A6A6A6A6A6"
    cipherstring2 = "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"
    @test test_wrap_unwrap(kekstring2, datastring2, ivstring2, cipherstring2)

    # 4.3
    name3 = "Wrap 128 bits of Key Data with a 256-bit KEK"
    kekstring3 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    datastring3 = "00112233445566778899AABBCCDDEEFF"
    ivstring3 = "A6A6A6A6A6A6A6A6"
    cipherstring3 = "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"
    @test test_wrap_unwrap(kekstring3, datastring3, ivstring3, cipherstring3)

    # 4.4
    name4 = "Wrap 192 bits of Key Data with a 192-bit KEK"
    kekstring4 = "000102030405060708090A0B0C0D0E0F1011121314151617"
    datastring4 = "00112233445566778899AABBCCDDEEFF0001020304050607"
    ivstring4 = "A6A6A6A6A6A6A6A6"
    cipherstring4 = "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"
    @test test_wrap_unwrap(kekstring4, datastring4, ivstring4, cipherstring4)

    # 4.5
    name5 = "Wrap 192 bits of Key Data with a 256-bit KEK"
    kekstring5 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    datastring5 = "00112233445566778899AABBCCDDEEFF0001020304050607"
    ivstring5 = "A6A6A6A6A6A6A6A6"
    cipherstring5 = "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"
    @test test_wrap_unwrap(kekstring5, datastring5, ivstring5, cipherstring5)

    # 4.6
    name6 = "Wrap 256 bits of Key Data with a 256-bit KEK"
    kekstring6 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    datastring6 = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"
    ivstring6 = "A6A6A6A6A6A6A6A6"
    cipherstring6 = "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    @test test_wrap_unwrap(kekstring6, datastring6, ivstring6, cipherstring6)
end

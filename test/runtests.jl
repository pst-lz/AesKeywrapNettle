using Test, AesKeywrapNettle

function test_wrap_unwrap_iv(kekstring, datastring, ivstring, cipherstring)
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

function test_wrap_unwrap(kekstring, datastring, cipherstring)
    test_correct :: Bool = false

    kek = hex2bytes(kekstring)
    data = hex2bytes(datastring)
    cipherref = hex2bytes(cipherstring)
    
    # wrap
    cipher = aes_wrap_key(kek, data) 
    test_correct =  lowercase(bytes2hex(cipher)) == lowercase(cipherstring)

    # unwrap
    plain = aes_unwrap_key(kek, cipherref)
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
    @test test_wrap_unwrap_iv(kekstring1, datastring1, ivstring1, cipherstring1)
    @test test_wrap_unwrap(kekstring1, datastring1, cipherstring1)

    # 4.2
    name2 = "Wrap 128 bits of Key Data with a 192-bit KEK"
    kekstring2 = "000102030405060708090A0B0C0D0E0F1011121314151617"
    datastring2 = "00112233445566778899AABBCCDDEEFF"
    ivstring2 = "A6A6A6A6A6A6A6A6"
    cipherstring2 = "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"
    @test test_wrap_unwrap_iv(kekstring2, datastring2, ivstring2, cipherstring2)
    @test test_wrap_unwrap(kekstring2, datastring2, cipherstring2)

    # 4.3
    name3 = "Wrap 128 bits of Key Data with a 256-bit KEK"
    kekstring3 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    datastring3 = "00112233445566778899AABBCCDDEEFF"
    ivstring3 = "A6A6A6A6A6A6A6A6"
    cipherstring3 = "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"
    @test test_wrap_unwrap_iv(kekstring3, datastring3, ivstring3, cipherstring3)
    @test test_wrap_unwrap(kekstring3, datastring3, cipherstring3)

    # 4.4
    name4 = "Wrap 192 bits of Key Data with a 192-bit KEK"
    kekstring4 = "000102030405060708090A0B0C0D0E0F1011121314151617"
    datastring4 = "00112233445566778899AABBCCDDEEFF0001020304050607"
    ivstring4 = "A6A6A6A6A6A6A6A6"
    cipherstring4 = "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"
    @test test_wrap_unwrap_iv(kekstring4, datastring4, ivstring4, cipherstring4)
    @test test_wrap_unwrap(kekstring4, datastring4, cipherstring4)

    # 4.5
    name5 = "Wrap 192 bits of Key Data with a 256-bit KEK"
    kekstring5 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    datastring5 = "00112233445566778899AABBCCDDEEFF0001020304050607"
    ivstring5 = "A6A6A6A6A6A6A6A6"
    cipherstring5 = "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"
    @test test_wrap_unwrap_iv(kekstring5, datastring5, ivstring5, cipherstring5)
    @test test_wrap_unwrap(kekstring5, datastring5, cipherstring5)

    # 4.6
    name6 = "Wrap 256 bits of Key Data with a 256-bit KEK"
    kekstring6 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    datastring6 = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"
    ivstring6 = "A6A6A6A6A6A6A6A6"
    cipherstring6 = "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    @test test_wrap_unwrap_iv(kekstring6, datastring6, ivstring6, cipherstring6)
    @test test_wrap_unwrap(kekstring6, datastring6, cipherstring6)
end

@testset "long key" begin
    name7 = "Wrap 4096 bits of Key Data with a 256-bit KEK"
    kekstring7 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    datastring7 = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"
    ivstring7 = "A6A6A6A6A6A6A6A6"
    cipherstring7 = "0cd47d1b501296187d893d813b0cf5911ce87fe75c5841f93c8e3b616cd9d638b1eb043da206af1bf52c186f9ff2270c2078deacb7992cc4782dc01f7594a46bbaeabc7003fc2b6295d27f9b345cddfc29de19f5b6d8a969121b7d2e49c4474e6eb6e965a0623f9e21305330122e6974beee87d345568260ec4c6606d3dc424819a9d5ab976bf952c02e141aa7fda07b14b2e4169bf49879dc2b6dc8ee6cc3aadc95ee2869a0ea9fa1bb62db3f09d1e1da8c13c1f70dc98fb1139296d45ac766364371008a688a9d992d62f9fd3a714212c9dfed285ad258387392ddaaffcdf3a0060c78970ae36d824007febff98d36c830c8010743e554c8ebe6eb79ccb2869267e129824e65210e39bf0f2f4191a858b89139b6babea64ef4b9b15bee4f0a9ef20417e01893cb380c6dbd140df82e8c3bb2d086e9510bb241f2731e73641e12c19abb680fc60efc035b7f5103eb0d6c609b0d1166e6a74907928c36930fa25e63bb8f522883e8c8af56f6efad4667ddf5c721f04ed9daedd5cf6c45c68ed5e1964f31f22e8208e0c12ccc34a8d72c2f73246d253872086a9ca485d346d93f14e90b1fa265decb74086170a87ab86b00739bcbeaa1ff27003cb2202cae43d8f7101460085741d540dc26480149e4b1b2fde4b07242d8398c885f5e4188291f92337332167db6a20f3c14a2f31ac7bd18430ad11d22b9431128561f8e38c912cff3f81f11e4782a"
    @test test_wrap_unwrap_iv(kekstring7, datastring7, ivstring7, cipherstring7)
    @test test_wrap_unwrap(kekstring7, datastring7, cipherstring7)
end


@testset "errors" begin
    # wrong iv
    @test_throws ErrorException aes_unwrap_key(hex2bytes("000102030405060708090A0B0C0D0E0F"), hex2bytes("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"), hex2bytes("A6A6A6A6A6A6A6A0"))

    # wrong kek length unwrap
    @test_throws ErrorException aes_unwrap_key(hex2bytes("000102030405060708090A0B0C0D0E0F0A"), hex2bytes("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"), hex2bytes("A6A6A6A6A6A6A6A6"))
    
    # wrong wrapped length unwrap
    @test_throws ErrorException aes_unwrap_key(hex2bytes("000102030405060708090A0B0C0D0E0F"), hex2bytes("AA1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"), hex2bytes("A6A6A6A6A6A6A6A6"))

    # wrong wrapped length unwrap (to short 1)
    @test_throws ErrorException aes_unwrap_key(hex2bytes("000102030405060708090A0B0C0D0E0F"), hex2bytes("1FA68B0A8112B447"), hex2bytes("A6A6A6A6A6A6A6A6"))

    # wrong wrapped length unwrap (to short 2)
    @test_throws ErrorException aes_unwrap_key(hex2bytes("000102030405060708090A0B0C0D0E0F"), hex2bytes(""), hex2bytes("A6A6A6A6A6A6A6A6"))

    # wrong iv length unwrap
    @test_throws ErrorException aes_unwrap_key(hex2bytes("000102030405060708090A0B0C0D0E0F"), hex2bytes("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"), hex2bytes("A6A6A6A6A6A6A6A6CA"))

    # wrong kek length wrap
    @test_throws ErrorException aes_wrap_key(hex2bytes("AA000102030405060708090A0B0C0D0E0F"), hex2bytes("00112233445566778899AABBCCDDEEFF"), hex2bytes("A6A6A6A6A6A6A6A6"))

    # wrong plaintext length wrap
    @test_throws ErrorException aes_wrap_key(hex2bytes("000102030405060708090A0B0C0D0E0F"), hex2bytes("FFAA00112233445566778899AABBCCDDEEFF"), hex2bytes("A6A6A6A6A6A6A6A6"))

    # wrong plaintext length wrap (to short)
    @test_throws ErrorException aes_wrap_key(hex2bytes("000102030405060708090A0B0C0D0E0F"), hex2bytes(""), hex2bytes("A6A6A6A6A6A6A6A6"))

    # wrong iv length wrap
    @test_throws ErrorException aes_wrap_key(hex2bytes("000102030405060708090A0B0C0D0E0F"), hex2bytes("00112233445566778899AABBCCDDEEFF"), hex2bytes("A6A6A6A6A6A6A6A6BB"))

end
"""
    AesKeywrapNettle

    AES keywrap in Julia 
    (uses https://github.com/JuliaCrypto/Nettle.jl for AES)
"""
module AesKeywrapNettle

export aes_wrap_key, aes_unwrap_key

using Nettle

"""
    aes_wrap_key(kek, plaintext[, iv])
Wraps the key "plaintext" using the key "kek" und the initial vector "iv" with the "Advanced Encryption Standard (AES) Key Wrap Algorithm"

# Arguments
- `kek::Array{UInt8}`: the key-encryption key, possible key lengths for "kek" are 128 bit, 192 bit, and 192 bit
- `plaintext::Array{UInt8}`: the key (or plaintext) to wrap, the length of "plaintext" must be a multiple of 64 bit
- `iv::Array{UInt8}`: the 64-bit initial value used during the wrapping process; If no iv is specified, the default iv [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6] from rfc3394 is used.

# Examples
```@meta
DocTestSetup = quote
    using AesKeywrapNettle
end
```


```jldoctest
julia> a = aes_wrap_key([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f], [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6])
24-element Vector{UInt8}:
 0x1f
 0xa6
 0x8b
 0x0a
 0x81
 0x12
 0xb4
 0x47
 0xae
 0xf3
    ⋮
 0x82
 0x9d
 0x3e
 0x86
 0x23
 0x71
 0xd2
 0xcf
 0xe5
```
"""
    function aes_wrap_key(kek::Array{UInt8}, plaintext::Array{UInt8}, iv::Array{UInt8}=[0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6])
        # for Byte-Array
        cryptalg = ""
        if length(kek) == 16
            cryptalg = "aes128"
        elseif length(kek) == 24
            cryptalg = "aes192"
        elseif length(kek) == 32
            cryptalg = "aes256"
        else
            error("wrong key length")
        end
        if length(iv) != 8
            error("wrong iv length")
        end
        if length(plaintext) % 8 != 0 || length(plaintext) == 0
            error("wrong plaintext length")
        end       
        n = length(plaintext) ÷ 8
        P = zeros(UInt8, n, 8)
        for i in 1:n, j in 1:8
            P[i, j] = plaintext[j + (i - 1) * 8]
        end
        R = zeros(UInt8, n +1, 8)
        A = copy(iv)
        for i in 1:n, j in 1:8
            R[i + 1, j] = P[i, j]
        end   
        for j in 0:5 
            for i in 1:n      
                for k in 1:8
                    push!(A, R[i + 1, k])
                end
                B = encrypt(cryptalg, kek, A)
                t :: UInt64 = 0
                t = (n * j) + i
                if t <= 255
                    A = B[1:8]
                    A[8] = A[8] ⊻ t
                else
                    BMSB :: UInt64 = 0
                    temp :: UInt64 = 0
                    for k in 1:8
                        temp = B[k]
                        BMSB += temp << (8 * (8 - k))
                    end
                    A64 :: UInt64 = 0
                    A64 = BMSB ⊻ t
                    A = hex2bytes(string(A64, base = 16, pad = 16))
                end
                for k in 1:8
                    R[i + 1, k] = B[8 + k]
                end
            end
        end
        C = zeros(UInt8, 8 * (n + 1))
        for i in 1:8
            C[i] = A[i]
        end
        for i in 1:8, j in 2:n+1
            C[i + (j - 1) * 8] = R[j, i]
        end
        return C
    end


"""
    aes_unwrap_key(kek, wrapped[, iv])
Unwraps the key "plaintext" using the key "kek" with the "Advanced Encryption Standard (AES) Key Wrap Algorithm"
The initial vector "iv" is used for integrity check.

# Arguments
- `kek::Array{UInt8}`: the key-encryption key, possible key lengths for "kek" are 128 bit, 192 bit, and 192 bit
- `wrapped::Array{UInt8}`: the wrapped key (or plaintext) to wrap, the length of "wrapped" must be a multiple of 64 bit
- `iv::Array{UInt8}`: the 64-bit initial value used during the wrapping process; If no iv is specified, the default iv [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6] from rfc3394 is used.

# Examples
```@meta
DocTestSetup = quote
    using AesKeywrapNettle
end
```

```jldoctest
julia> b = aes_unwrap_key([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f], [0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82, 0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5], [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6])
16-element Vector{UInt8}:
 0x00
 0x11
 0x22
 0x33
 0x44
 0x55
 0x66
 0x77
 0x88
 0x99
 0xaa
 0xbb
 0xcc
 0xdd
 0xee
 0xff
```
"""
    function aes_unwrap_key(kek::Array{UInt8}, wrapped::Array{UInt8}, iv::Array{UInt8}=[0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6])
        # for Byte-Array
        cryptalg = ""
        if length(kek) == 16
            cryptalg = "aes128"
        elseif length(kek) == 24
            cryptalg = "aes192"
        elseif length(kek) == 32
            cryptalg = "aes256"
        else
            error("wrong key length")
        end
        if length(iv) != 8
            error("wrong iv length")
        end
        if length(wrapped) % 8 !=0
            error("wrong wrapped length")
        end
        n = length(wrapped) ÷ 8 - 1
        if n <= 0
            error("wrong wrapped length")
        end
        C = zeros(UInt8, n + 1, 8)
        for i in 1:n+1, j in 1:8
            C[i, j] = wrapped[j + (i-1)*8]
        end
        A = zeros(UInt8, 8)
        for i in 1:8
            A[i] = C[1, i]
        end
        R = copy(C)
        for j in 5:-1:0
            for i in n:-1:1
                t :: UInt64 = 0
                t = (n * j) + i
                if t <= 255
                    A[8] = A[8] ⊻ t
                else
                    A64 :: UInt64 = 0
                    temp :: UInt64 = 0
                    for k in 1:8
                        temp = A[k]
                        A64 += temp << (8 * (8 - k))
                    end
                    A64 = A64 ⊻ t
                    A = hex2bytes(string(A64, base = 16, pad = 16))
                end
                for k in 1:8
                    push!(A, R[i + 1, k])
                end
                B = decrypt(cryptalg, kek, A)
                A = copy(B[1:8])
                for k in 1:8
                    R[i + 1, k] = B[8 + k]
                end
            end
        end
        if iv == A
            P = zeros(UInt8, 8*n)
            for i in 1:8, j in 1:n
                P[i + (j - 1) * 8] = R[j + 1, i]
            end
            return P
        else
            error("wrong intial vector")
        end
    end

end # module

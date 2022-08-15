module AesKeywrapNettle

export aes_wrap_key, aes_unwrap_key

using AES

    function aes_wrap_key(kek, plaintext, iv)
        # for Byte-Array
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
                B = AESECB(A, kek, true)
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

    function aes_unwrap_key(kek, wrapped, iv)
        # for Byte-Array
        n = length(wrapped) ÷ 8 - 1
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
                B = AESECB(A, kek, false)
                A = copy(B[1:8])
                for k in 1:8
                    R[i + 1, k] = B[8 + k]
                end
            end
        end
        #if iv == A
            P = zeros(UInt8, 8*n)
            #println(R)
            for i in 1:8, j in 1:n
                P[i + (j - 1) * 8] = R[j + 1, i]
            end
            return P
        # else
        #     return error?
        # end
    end

end # module

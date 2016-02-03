#!/usr/bin/python

#################################################################################
#                       YOUR CODE BELONGS INTO THIS FILE!                       #
#           INSERT YOUR NAME AND MatNr. INTO THE CORRESPONDING FIELDS           #
#                   YOU HAVE TO USE THE PROVIDED FUNCTIONS AND                  #
#               YOU ARE NOT ALLOWED TO MODIFY THE FUNCTION HEADERS              #
#                                                                               #
#   Author Mirko Budszuhn                                                        #
#                                                                               #
#################################################################################


class AES:

############## DO NOT MODIFY THESE VARIABLES ##############
    global AES_BIT_BLOCK_SIZE, AES_BYTE_BLOCK_SIZE, AES_128_KEY_BIT_LEN, AES_128_NUM_OF_ROUNDS, AES_128_NB, AES_192_KEY_BIT_LEN, AES_192_NUM_OF_ROUNDS, AES_192_NB, AES_256_KEY_BIT_LEN, AES_256_NUM_OF_ROUNDS, AES_256_NB
    AES_BIT_BLOCK_SIZE = 128
    AES_BYTE_BLOCK_SIZE = int(AES_BIT_BLOCK_SIZE / 8)

    AES_128_KEY_BIT_LEN = 128
    AES_128_NUM_OF_ROUNDS = 10
    AES_128_NB = 176

    AES_192_KEY_BIT_LEN = 192
    AES_192_NUM_OF_ROUNDS = 12
    AES_192_NB = 208

    AES_256_KEY_BIT_LEN = 256
    AES_256_NUM_OF_ROUNDS = 14
    AES_256_NB = 240

###########################################################

    global sbox, sboxInv, galois_log, galois_logExp, atable, ltable
    sbox = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]
    sboxInv  = [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125]
    rc = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    # see http://www.samiam.org/galois.html log tables for galois field arithmetics
    ltable =    [0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36,
                0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18,
                0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f,
                0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e,
                0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53,
                0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3,
                0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21,
                0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74,
                0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4,
                0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1,
                0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13,
                0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80,
                0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12,
                0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5,
                0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56,
                0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba,
                0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3,
                0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47,
                0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf,
                0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05,
                0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67,
                0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd,
                0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34,
                0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec,
                0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7,
                0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e,
                0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a,
                0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d,
                0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c,
                0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d,
                0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0,
                0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38 ]
    atable =   [0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12,
                0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36,
                0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a,
                0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee,
                0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29,
                0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b,
                0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d,
                0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c,
                0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f,
                0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a,
                0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85,
                0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94,
                0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7,
                0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2,
                0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d,
                0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17,
                0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39,
                0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b,
                0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd,
                0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c,
                0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84,
                0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97,
                0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2,
                0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd,
                0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c,
                0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24,
                0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c,
                0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4,
                0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7,
                0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52,
                0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6,
                0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01]
    def __init__(self):
        self.state = bytearray(b'\x00' * AES_BIT_BLOCK_SIZE)

    def gf_multiply(self, x, y):
        global ltable, atable
        p = ltable[x] + ltable[y]
        p %= 255
        p = atable[p]
        if x == 0 or y == 0:
            return 0
        return p

    def gf_inverse(self, x):
        if x == 0:
        	return 0
        else:
            return galois_log[(255 - galois_log[x])]

    #changed parameter Name because round is a reserved function
    def key_addition(self, state, k, round_count):
        state = self.xor_bytearray(state, k.round_keys[round_count])
        return state


    def subbytes(self,state):
        for i in range(len(state)):
            byte = state[i]
            state[i] = sbox[byte]
        return state


    def shiftrows(self, state):
        old_state = state.copy()
        for i in range(len(old_state)):
            row = i % 4
            state[i] = old_state[ (i + (row * 4)) % 16]
        return state


    def mixcolumns(self,state):
        start_matrix = [2, 3, 1, 1]
        old_state = state.copy()
        for i in range(0, len(state), 4):
            for i2 in range(4):
                state[i+i2] = self.gf_multiply(old_state[i], start_matrix[0]) ^ self.gf_multiply(old_state[i+1], start_matrix[1])
                state[i+i2] = state[i+i2] ^ self.gf_multiply(old_state[i+2], start_matrix[2])
                state[i+i2] = state[i+i2] ^ self.gf_multiply(old_state[i+3], start_matrix[3])
                start_matrix = self.shift(start_matrix, -1)
        return state


    def inv_subbytes(self,state):
        for i in range(len(state)):
            byte = state[i]
            state[i] = sboxInv[byte]
        return state


    def inv_shiftrows(self,state):
        old_state = state.copy()
        for i in range(len(old_state)):
            row = i % 4
            state[i] = old_state[ (i - (row * 4)) % 16]
        return state
    def print_state(self, state):
        stra = [str(hex(i)) for i in state]
        print(stra)
        return stra

    def inv_mixcolumns(self,state):
        start_matrix = [0x0E, 0x0B, 0x0D, 0x09]
        old_state = state.copy()
        for i in range(0, len(state), 4):
            for i2 in range(4):
                state[i+i2] = self.gf_multiply(old_state[i], start_matrix[0])
                state[i+i2] ^= self.gf_multiply(old_state[i+1], start_matrix[1])
                state[i+i2] ^=  self.gf_multiply(old_state[i+2], start_matrix[2])
                state[i+i2] ^=  self.gf_multiply(old_state[i+3], start_matrix[3])
                start_matrix = self.shift(start_matrix, -1)
        return state


    def block_encrypt(self,ptx, key):
        cipher = bytearray(b'\x00' * AES_BYTE_BLOCK_SIZE)
        if(len(ptx)!= AES_BYTE_BLOCK_SIZE):
            return bytearray(b'\x00' * AES_BYTE_BLOCK_SIZE)

        state = ptx.copy()
        num_of_rounds = 0

        if(key.key_bit_size==AES_128_KEY_BIT_LEN):
            num_of_rounds = AES_128_NUM_OF_ROUNDS
        elif(key.key_bit_size==AES_192_KEY_BIT_LEN):
            num_of_rounds = AES_192_NUM_OF_ROUNDS
        elif(key.key_bit_size==AES_256_KEY_BIT_LEN):
            num_of_rounds = AES_256_NUM_OF_ROUNDS

        if (num_of_rounds == 0):
            print("[error] : aes_block_encrypt() : key is not correctly initialized!\n")
            return bytearray(b'\x00' * AES_BYTE_BLOCK_SIZE)

        # Class should have gotten Key with roundkeys
        # round 0
        state = self.key_addition(state, key, 0)
        # rounds 1 - (num_of_rounds-1)
        for i in range(1, num_of_rounds):
            state = self.subbytes(state)
            state = self.shiftrows(state)
            state = self.mixcolumns(state)
            state = self.key_addition(state, key, i)
        #last round:
        state = self.subbytes(state)
        state = self.shiftrows(state)
        state = self.key_addition(state, key, num_of_rounds)

        cipher = state
        return cipher

    def block_decrypt(self, ctx, key):
        plain = bytearray(b'\x00' * AES_BYTE_BLOCK_SIZE)
        if(len(ctx)!= AES_BYTE_BLOCK_SIZE):
            return bytearray(b'\x00' * AES_BYTE_BLOCK_SIZE)

        state = ctx.copy()
        num_of_rounds = 0

        if(key.key_bit_size==AES_128_KEY_BIT_LEN):
            num_of_rounds = AES_128_NUM_OF_ROUNDS
        elif(key.key_bit_size==AES_192_KEY_BIT_LEN):
            num_of_rounds = AES_192_NUM_OF_ROUNDS
        elif(key.key_bit_size==AES_256_KEY_BIT_LEN):
            num_of_rounds = AES_256_NUM_OF_ROUNDS

        if (num_of_rounds == 0):
            print("[error] : aes_block_decrypt() : key is not correctly initialized!\n")
            return bytearray(b'\x00' * AES_BYTE_BLOCK_SIZE)

        # Class should have gotten Key with roundkeys

        # round 0
        state = self.key_addition(state, key, num_of_rounds)
        state = self.inv_shiftrows(state)
        state = self.inv_subbytes(state)
        # rounds 1 - (num_of_rounds-1)
        for i in range(num_of_rounds-1, 0, -1):
            state = self.key_addition(state, key, i)
            state = self.inv_mixcolumns(state)
            state = self.inv_shiftrows(state)
            state = self.inv_subbytes(state)
        #last round:
        state = self.key_addition(state, key, 0)
        plain = state

        return plain

    def gfunction(self, dword, rci):
        new_dword = self.shift(dword, 1)
        for i in range(len(new_dword)):
            new_dword[i] = sbox[new_dword[i]]
        new_dword[0] = new_dword[0] ^ self.rc[rci]
        return new_dword

    def set_key(self, key, keybytes, key_len):
        global AES_128_KEY_BIT_LEN, AES_192_KEY_BIT_LEN, AES_256_KEY_BIT_LEN
        global AES_128_NUM_OF_ROUNDS, AES_192_NUM_OF_ROUNDS, AES_256_NUM_OF_ROUNDS
        key.key_bit_size = key_len * 8

        num_of_keys = 0
        generator_rounds = 0

        if(key.key_bit_size==AES_128_KEY_BIT_LEN):
            num_of_keys = AES_128_NUM_OF_ROUNDS + 1
            generator_rounds = 11
        elif(key.key_bit_size==AES_192_KEY_BIT_LEN):
            num_of_keys = AES_192_NUM_OF_ROUNDS + 1
            generator_rounds = 9
        elif(key.key_bit_size==AES_256_KEY_BIT_LEN):
            num_of_keys = AES_256_NUM_OF_ROUNDS + 1
            generator_rounds = 8

        key_bytearray = bytearray(keybytes.copy())
        gen_round_keys = []
        gen_round_keys.append(keybytes.copy())
        #key_bytearray.extend(keybytes.copy())
        for i in range(1, generator_rounds):
            #gfun the last 4 Bytes
            dword1 = self.gfunction(gen_round_keys[i-1][-4:], i)
            dword1 = self.xor_bytearray(gen_round_keys[i-1][0:4], dword1)
            gen_round_keys.append(bytearray())
            gen_round_keys[i].extend(dword1)
            # For every DWORD
            for i2 in range(4, key_len, 4):
                #check if to apply h-function
                if key.key_bit_size == AES_256_KEY_BIT_LEN and  i2 == 16:
                    gen_round_keys[i].extend(self.xor_bytearray(gen_round_keys[i-1][i2:i2+4], self.subbytes(gen_round_keys[i][-4:])))
                    #print("round:",i ,"subbytes:", self.subbytes(gen_round_keys[i][-4:]), "XORed:", self.xor_bytearray(gen_round_keys[i-1][i2:i2+4], self.subbytes(gen_round_keys[i][-4:])))
                else:
                    gen_round_keys[i].extend(self.xor_bytearray(gen_round_keys[i-1][i2:i2+4], gen_round_keys[i][-4:]))
                    #print(self.xor_bytearray(gen_round_keys[i-1][i2:i2+4], gen_round_keys[i][-4:]))
            key_bytearray.extend(gen_round_keys[i].copy())
        for i in range(0, num_of_keys):
            key.round_keys.append(key_bytearray.copy()[i*16:i*16+16])

        return
    def _dword(self, bytearr, i):
        #DWORD = 4 * Byte
        return bytearr.copy()[i*4:i*4+4]

    def xor_bytearray(self, a, b):
        for i in range(len(a)):
            a[i] = a[i] ^ b[i]
        return a

    def shift(self, l, n):
        return l[n:] + l[:n]

    def bytearray_tostring(self, arr):
        ret = ""
        for ia in range(0, len(arr)):
            i = arr[ia]
            if len(str(hex(i))) == 3:
                ret += "0" + str(hex(i))[2:]
            else:
                ret += str(hex(i))[2:]
            if (ia+1) % 4 == 0:
                ret += "\n"
        return ret

class aes_key:
    def __init__(self):
        self.round_keys = []
        self.key_bit_size = 0

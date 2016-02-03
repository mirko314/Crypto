#!/usr/bin/python

#################################################################################
# Tests the first two rounds of your aes implementation for the correct states  #
#                                                                               #
#                <b>DO NOT MODIFY ANYTHING INSIDE THIS FILE!!</b>               #
#                                                                               #
#################################################################################

from AES_class import AES
from AES_class import aes_key

global aes, aeskey, AES_BIT_BLOCK_SIZE, AES_BYTE_BLOCK_SIZE, ptx, state, ctx
global key, result

aes = AES()
aeskey = aes_key()
AES_BIT_BLOCK_SIZE = 128
AES_BYTE_BLOCK_SIZE = int(AES_BIT_BLOCK_SIZE / 8)
aesround = 0

ptx = bytearray([0x46,0x72,0x6F,0x68,0x65,0x57,0x65,0x69,0x68,0x6E,0x61,0x63,0x68,0x74,0x65,0x6E])
state = bytearray([0x46,0x72,0x6F,0x68,0x65,0x57,0x65,0x69,0x68,0x6E,0x61,0x63,0x68,0x74,0x65,0x6E])
ctx = bytearray([0x11,0xD4,0x6C,0x57,0xD0,0xD0,0x40,0x14,0xA6,0x87,0x61,0xEE,0x0D,0x79,0x5E,0x51])
key = bytearray([0x57,0x75,0x65,0x6E,0x73,0x63,0x68,0x74,0x45,0x6D,0x73,0x65,0x63,0x3A,0x2D,0x29])


def test_subbytes():
    return arraycompare(aes.subbytes(state), bytearray([0x82,0xC5,0x67,0x6F, 0x47,0x18,0xD7,0xA4,0xD8,0x7B,0xC9,0x6F, 0x2B,0x2F,0x52,0xA0]))
    #return arraycompare(aes.subbytes(state), bytearray([0x82,0xC5,0x67,0x6F, 0x47,0x18,0xD7,0xA4,0xD8,0x7B,0xC9,0x6F, 0x2B,0x2F,0x52,0xA0]))


def test_shiftrows():
    return arraycompare(aes.shiftrows(state), bytearray([0x82,0x18,0xC9,0xA0,0x47,0x7B,0x52,0x6F,0xD8,0x2F,0x67,0xA4, 0x2B,0xC5,0xD7,0x6F]))

def test_shiftrows_dual():
    start_matrix = state.copy()
    return arraycompare(aes.inv_shiftrows(aes.shiftrows(state)), start_matrix)


def test_mixcolumns():
    test = aes.mixcolumns(state)
    return arraycompare(test, bytearray([0x5E,0x52,0xE8,0x17,0x3E,0x28,0x29,0x3E,0x19,0x8B,0xCE,0x68, 0xBA,0xB7,0xEA,0xB1]))


def test_key_addition():
    if(aesround == 0):
        #TODO Changed from:
        # return arraycompare(aes.key_addition(state, key, aesround), bytearray([0x11,0x07,0x0A,0x06, 0x16,0x34,0x0D,0x1D,0x2D,0x03,0x12,0x06, 0x0B,0x4E,0x48,0x47]))
        return arraycompare(aes.key_addition(state, aeskey, aesround), bytearray([0x11,0x07,0x0A,0x06, 0x16,0x34,0x0D,0x1D,0x2D,0x03,0x12,0x06, 0x0B,0x4E,0x48,0x47]))
    elif(aesround == 1):
        #TODO Changed from:
        # return arraycompare(aes.key_addition(state, key, aesround), bytearray([0x11,0x07,0x0A,0x06, 0x16,0x34,0x0D,0x1D,0x2D,0x03,0x12,0x06, 0x0B,0x4E,0x48,0x47]))
        return arraycompare(aes.key_addition(state, aeskey, aesround), bytearray([0x88,0xFF,0x28,0x82,0x9B,0xE6,0x81,0xDF,0xF9,0x28,0x15,0xEC,0x39,0x2E,0x1C,0x1C]))
    else:
        return 0

def test_key_schedule():
    if(aesround == 0):
        return arraycompare(aeskey.round_keys[0], bytearray([0x57,0x75,0x65,0x6E,0x73,0x63,0x68,0x74,0x45,0x6D,0x73,0x65,0x63,0x3A,0x2D,0x29]))
    elif(aesround == 1):
        return arraycompare(aeskey.round_keys[1], bytearray([0xD6,0xAD,0xC0,0x95,0xA5,0xCE,0xA8,0xE1,0xE0,0xA3,0xDB,0x84, 0x83,0x99,0xF6,0xAD]))
    else:
        return 0

def test_256bit_encryption():
    akey = aes_key()
    cipher = ([0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89])
    plain = bytearray([0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff])
    byte_key = bytearray([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f])
    aes.set_key(akey, byte_key, len(byte_key))
    ciphertext = aes.block_encrypt(plain, akey)
    plaintext = aes.block_decrypt(cipher, akey)
    return arraycompare(ciphertext, cipher) and arraycompare(plaintext, plain)

def print_state(state):
    stra = [str(hex(i)) for i in state]
    print(stra)
    return stra

def test_256keybit():
    akey = aes_key()
    byte_key = bytearray([0x00] * 16)
    aes_o = AES()
    aes_o.set_key(akey, byte_key, len(byte_key))
    print(akey.round_keys)

def test_192bit_encryption():
    akey = aes_key()
    plain = bytearray([0x76,0x77,0x74,0x75,0xF1,0xF2,0xF3,0xF4,0xF8,0xF9,0xE6,0xE7,0x77,0x70,0x71,0x72])
    cipher = bytearray([0x5d,0x1e,0xf2,0x0d,0xce,0xd6,0xbc,0xbc,0x12,0x13,0x1a,0xc7,0xc5,0x47,0x88,0xaa])
    byte_key = bytearray([0x04,0x05,0x06,0x07,0x09,0x0A,0x0B,0x0C,0x0E,0x0F,0x10,0x11,0x13,0x14,0x15,0x16,0x18,0x19,0x1A,0x1B,0x1D,0x1E,0x1F,0x20])
    aes.set_key(akey, byte_key, len(byte_key))
    ciphertext = aes.block_encrypt(plain, akey)
    plaintext = aes.block_decrypt(cipher, akey)
    return arraycompare(ciphertext, cipher) and arraycompare(plaintext, plain)

def test_encryption():
    ciphertext = aes.block_encrypt(ptx, aeskey)
    return arraycompare(ciphertext, ctx)


def test_decryption():
    plaintext = aes.block_decrypt(ctx, aeskey)
    return arraycompare(plaintext, ptx)

def test_xor_bytearray():
    byteaddidtion = aes.xor_bytearray(bytearray([0x12, 0x45, 0x67, 0x89]), bytearray([0xad, 0xef, 0x12, 0x34]))
    return arraycompare(byteaddidtion, bytearray([0xbf, 0xaa, 0x75, 0xbd]))

def test_gfunction():
    gfunction = aes.gfunction(bytearray([0, 2, 0, 0]), 2)
    return arraycompare(gfunction, bytearray([117, 99, 99, 99]))

def test_gf_multiply():
    gf_multiply = aes.gf_multiply(0x25, 0x03)
    return gf_multiply == int("1101111", 2)

def test_gf_inv_multiply():
    gf_multiply = aes.gf_multiply(0x25, 0x0E)
    return gf_multiply == int("11101101", 2)

def test_mixcolumns_double():
    start_matrix = state.copy()
    mix_matrix = aes.mixcolumns(state).copy()
    end_matrix = aes.inv_mixcolumns(state).copy()
    return arraycompare(start_matrix,state)

def arraycompare(array1, array2):
    if(len(array1)!= len(array2)):
        return 0
    else:
        for a in range(0,len(array1)):
            if(array1[a] != array2[a]):
                return 0
    return 1


def main():
    # Strings for colored output
    passed='\033[92m'+"passed"+'\033[0m'
    failed='\033[91m'+"failed"+'\033[0m'
    #changed
    global aesround
    aesround = 0
    aes.set_key(aeskey, key, len(key))

    # First two aesrounds are being tested
    test = passed if test_key_addition() else failed
    print("First KeyAddition Testing:\t %s" %test)

    test = passed if test_key_schedule() else failed
    print("First KeySchedule Testing:\t %s" %test)

    aesround +=1

    test = passed if test_subbytes() else failed
    print("SubBytes Testing:\t\t %s" %test)

    test = passed if test_shiftrows() else failed
    print("ShiftRows Testing:\t\t %s" %test)

    test = passed if test_mixcolumns() else failed
    print("MixColumns Testing:\t\t %s" %test)

    test = passed if test_key_addition() else failed
    print("Second KeyAddition Testing:\t %s" %test)

    test = passed if test_key_schedule() else failed
    print("Second KeySchedule Testing:\t %s" %test)

    test = passed if test_encryption() else failed
    print("Encryption Testing:\t\t %s" %test)

    test = passed if test_decryption() else failed
    print("Decryption Testing:\t\t %s" %test)

    #Added Tests:

    test = passed if test_xor_bytearray() else failed
    print("xor_bytearray Testing:\t\t %s" %test)

    test = passed if test_gfunction() else failed
    print("gfunction Testing:\t\t %s" %test)

    test = passed if test_gf_multiply() else failed
    print("test_gf_multiply Testing:\t\t %s" %test)

    test = passed if test_mixcolumns_double() else failed
    print("test_mixcolumns_double Testing:\t\t %s" %test)

    test = passed if test_shiftrows_dual() else failed
    print("test_shiftrows_dual Testing:\t\t %s" %test)

    test = passed if test_gf_inv_multiply() else failed
    print("test_gf_inv_multiply Testing:\t\t %s" %test)

    test = passed if test_192bit_encryption() else failed
    print("test_192bit_encryption Testing:\t\t %s" %test)

    test = passed if test_256bit_encryption() else failed
    print("test_256bit_encryption Testing:\t\t %s" %test)

    #test_256keybit()

if __name__ == "__main__":
    main()

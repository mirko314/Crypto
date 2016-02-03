import re
from math import log
from bitstring import *
import numpy as np
from lfsr_class import LFSR


def lfsr(seed, taps, round=10000, outputonly=False):
    import time
    sr, xor, keybit, statehistory, repeated, period = seed, 0, [], [], False, -1
    maxperiod = 2**len(sr) - 1
    #print("maximale Periode: " + str(maxperiod ))
    # print("state:keybit")
    print(sr + ": seed")
    for i in range(round):
        if period == -1 and sr in statehistory:
            occ = statehistory.index(sr)
            # da Index occ um eins kleiner ist
            period = len(statehistory) - occ
            print("Periode = " + str(period))
            if period == maxperiod:
                print("Periode = Maxperiode -> P(x) primitiv")
            break
        statehistory.append(sr)
        keybit.append(sr[-1])
        for t in taps:
            xor += int(sr[t - 1])
        if xor % 2 == 0.0:
            xor = 0
        else:
            xor = 1
        #xor = xor % 2
        #print (xor)
        time.sleep(0.1)
        sr, xor = str(xor) + sr[:-1], 0
        print(sr + "   " + str(keybit[-1]))
        time.sleep(0.1)
    print(str(i + 1) + " Rounds Done.")
    return sr


def a51(seed1, seed2, seed3, rounds=8):  # seed1
    if len(seed1) != 19 or len(seed2) != 22 or len(seed3) != 23:
        print("Wrong seed length")
        return
    taps1 = [19, 18, 17, 14]
    majbit1 = 8
    taps2 = [22, 21]
    majbit2 = 10
    taps3 = [23, 22, 21, 8]
    majbit3 = 10
    output = []
    for i in range(rounds):
        print("==================RUNDE: " + str(i))
        maj = int(seed1[majbit1]) + int(seed2[majbit2]) + \
            int(seed3[majbit3]) > 1
        print("Majority: " + str(int(maj)))
        output.append(int(seed1[-1]) ^ int(seed2[-1]) ^ int(seed3[-1]))
        print("Output: " + str(output[-1]))
        if int(seed1[majbit1]) == int(maj):
            print("Takte 1")
            seed1 = lfsr(seed1, taps1, 1)
        if int(seed2[majbit2]) == int(maj):
            print("Takte 2")
            seed2 = lfsr(seed2, taps2, 1)
        if int(seed3[majbit3]) == int(maj):
            print("Takte 3")
            seed3 = lfsr(seed3, taps3, 1)
    return output


def knownplaincipher(plainbits, cipherbits):
    if len(plainbits.bin) != len(cipherbits.bin):
        print("Length differences between plain/cipher text! Exiting")
        return

    keybits = (plainbits ^ cipherbits)
    print("Keystream:", keybits.bin)
    possListOrig = list(repetitions(str(keybits.bin)))
    possListSorted = sorted(possListOrig, key=lambda poss: len(
        poss[0]) * poss[1], reverse=True)
    print("Possible generated keystreams", possListSorted)
    possiblekeystream = BitArray(bin=possListSorted[0][0])

    print("Testing with ", possiblekeystream.bin)
    minDeg = int(log(len(possiblekeystream.bin) + 1, 2))
    print("Minimal degree: ", minDeg)
    for m in range(minDeg, minDeg + 1):
        print("Trying with Degree = ", m)
        if len(plainbits.bin) < m * 2:
            print("Not enough Textpairs")
            return
        feedbackmatrixarr = []  # FORM: 3x3 bzw m x m
        keybitresarr = []  # FORM: 1x3 bzw 1 x m
        for i in range(m):  # Jede Reihe
            row = []
            keybitresarr.append([int(keybits[m + i])])
            for i2 in range(m):  # JedeZeile
                row.append(int(keybits[m + i + ((-1) * (i2 + 1))]))
            feedbackmatrixarr.append(row)
        # feedback coefficients Matrix
        feedbackmat = np.array(feedbackmatrixarr)
        invkeymat = np.linalg.inv(feedbackmat)  # Inver
        keybitresmatrix = np.array(keybitresarr)
        result = np.dot(invkeymat, keybitresmatrix)
        feedback = []
        for x in range(len(result)):
            print("p", x, " = ", int(result[x][0]) % 2)
            feedback.append(int(result[x][0]))

        seed = keybits[:m].bin
        print("IV: <- Output \t", seed)
        print("PX: \t\t", "".join(str(x) for x in feedback[::-1]))
        LfsrCheck = LFSR(list(seed), feedback[::-1])
        generatedBits = ""
        for i in range(len(keybits)):
            generatedBits += str(LfsrCheck.clock())
        print("Generated: \t", generatedBits)
        print("Original: \t", keybits.bin)
        if generatedBits == keybits.bin:
            print("Identical KeyStreams, Found Config. Exiting")
            return
        #[print("s", x , " = ", int(keybits[x])) for x in range(m)]


def repetitions(s):
    r = re.compile(r"(.+?)\1+")
    for match in r.finditer(s):
        yield (match.group(1), len(match.group(0)) / len(match.group(1)))


def customABCDecode(Bitstream):
    if len(Bitstream.bin) != 5:
        print("Wrong Length: ", len(Bitstream.bin))
    if Bitstream.uint < 26:  # Is Letter A-Z
        return chr(Bitstream.uint + 65)
    else:  # Is Number 0 - 9
        return chr(Bitstream.uint - 26 + 48)
def customABCEncode(Char):
    print(Char)
    charOrd = ord(Char)
    if (charOrd < 48 and charOrd > 57) or (charOrd < 65 and charOrd > 90):
        print("Wrong Char: ", char0rd)
    if charOrd >= 48 and charOrd <= 57:  # Is Letter A-Z
        retArray = Bits(uint=charOrd- 48 + 26, length=5)
    else:  # Is Number 0 - 9
        retArray =  Bits(uint=charOrd - 65, length=5)
    return retArray
#seed = list(input("Eingabe Seed:"))
#[ s = int(s) for s in seed]
#taps = list(input("Eingabe taps:"))
#[ s = int(s) for s in taps]

#seed = "011"
# taps = [2, len(seed)] # 2-> Vorletztes und Letztes FF In Feedback.
#seed = lfsr(seed, taps)

#seed = lfsr(seed, taps,1)

#ou = a51("0101110001001000101"[::-1], "1110001010000111000110"[::-1], "00100100011100101100101"[::-1],8)
# print(ou)
# knownplaincipher(BitArray('0b1001001001101101100100100110'),
#                 BitArray('0b1011110000110001001010110001'))

ciphertext = "WPE"
plaintext = ("j5a0edj2b").upper()[:3]
print([customABCEncode(x) for x in ciphertext])
cipherstream = Bits().join([customABCEncode(x) for x in ciphertext])
plainstream = Bits().join([customABCEncode(x) for x in plaintext])
print(cipherstream)
print(plainstream)
knownplaincipher(cipherstream, plainstream)

from Crypto.Cipher import AES
from Crypto.Util import Counter
import sys

BLOCK_SIZE = 16

def strxor(a, b):
    if len(a) != len(b):
        raise ValueError("a and b are not with the same length")

    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])

def bytes_to_long(byte):
    ba = bytearray(byte)
    num = (ba[0] << 24) + (ba[1] << 16) + (ba[2] << 8) + ba[3]
    return num

def cbc_d(ciphertext, cbc_key, iv):
    aes = AES.new(cbc_key)

    m = ""
    for start in range(0, len(ciphertext), BLOCK_SIZE):
        end = start + BLOCK_SIZE
        c = ciphertext[start:end]
        tmp = aes.decrypt(c)
        if start == 0:
            m += strxor(tmp, iv)
        else:
            m += strxor(tmp, prev_c)

        prev_c = c

    return m

def cbc_e(text, cbc_key, iv):
    if len(text) % 16 != 0:
        raise ValueError("Input strings must be a multiple of 16 in length")

    aes = AES.new(cbc_key)

    c = ""
    for start in range(0, len(text), BLOCK_SIZE):
        end = start + BLOCK_SIZE
        m = text[start:end]

        if start == 0:
            tmp = strxor(m, iv)
        else:
            tmp = strxor(m, prev_c)

        prev_c = aes.encrypt(tmp)
        c += prev_c

    return c

def ctr_d(ciphertext, ctr_key, counter):

    aes = AES.new(ctr_key)

    m = ""
    for start in range(0, len(ciphertext), BLOCK_SIZE):
        end = start + BLOCK_SIZE
        c = ciphertext[start:end]

        tmp = aes.encrypt(counter())
        m += strxor(c, tmp[0:len(c)])

    return m



if __name__ == "__main__":
    key = sys.argv[2].decode("hex")
    blob = sys.argv[3].decode("hex")

    iv = blob[0:16]
    ciphertext = blob[16:]

    if sys.argv[1] == "ctr":
        ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))
        print(ctr_d(ciphertext, key, ctr))
    else:
        print(cbc_d(ciphertext, key, iv))

import unittest
from Crypto.Cipher import AES
from Crypto.Util import Counter
from crypt import *

class TestCryptoStuff(unittest.TestCase):
    def test_decrypt_cbc(self):
        cbc_key = '140b41b22a29beb4061bda66b6747e14'.decode("hex")
        cbc_blob = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'.decode("hex")
        iv = cbc_blob[0:16]
        ciphertext = cbc_blob[16:]
        obj = AES.new(cbc_key, AES.MODE_CBC, iv)

        text_aes_lib = obj.decrypt(ciphertext)
        self.assertEquals(text_aes_lib, cbc_d(ciphertext, cbc_key, iv))

    def test_encrypt_cbc(self):
        cbc_key = '140b41b22a29beb4061bda66b6747e14'.decode("hex")
        iv = '4ca00ff4c898d61e1edbf1800618fb28'.decode("hex")
        text = "Basic CBC mode encryption needs padding."

        obj = AES.new(cbc_key, AES.MODE_CBC, iv)
        text += ('\x08' * 8)
        bytes_aes_lib = obj.encrypt(text)

        self.assertEquals(bytes_aes_lib, cbc_e(text, cbc_key, iv))

    def test_decrypt_ctr(self):
        ctr_key = '36f18357be4dbd77f050515c73fcf9f2'.decode("hex")
        blob = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329".decode("hex")

        iv = blob[0:16]
        ciphertext = blob[16:]

        ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))
        obj = AES.new(ctr_key, AES.MODE_CTR, counter=ctr)

        text_aes_ctr = obj.decrypt(ciphertext)

        ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))
        my_decrypt = ctr_d(ciphertext, ctr_key, ctr)
        self.assertEquals(text_aes_ctr, my_decrypt)

    def test_encrypt_ctr(self):
        # TODO implement this
        ctr_key = '36f18357be4dbd77f050515c73fcf9f2'.decode('hex')
        iv = '69dda8455c7dd4254bf353b773304eec'.decode('hex')
        text = "CTR mode lets you build a stream cipher from a block cipher."

        ctr = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
        obj = AES.new(ctr_key, AES.MODE_CTR, counter=ctr)

        print(obj.encrypt(text))


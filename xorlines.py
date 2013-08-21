import os, operator, itertools, sys, os.path
from binascii import unhexlify, hexlify
from unidiff.parser import parse_unidiff
from Crypto.Cipher import AES
#from tempfile import NamedTemporaryFile

def encrypt(infile, outfile1, keyfile):
    key = os.urandom(32)
    with open(keyfile, "wb") as f:
        f.write(key)

    with open(outfile1, "wb") as f:
        with open(infile, "rb") as i:
            for line in i:
                iv = os.urandom(16)
                f.write(hexlify(iv) + b"," + hexlify(AES.new(key, AES.MODE_CFB, iv).encrypt(line)) + b'\n')

def decrypt_text_to_stdout(keyfile):
    for l in real_decrypt(keyfile, sys.stdin):
        print(l.decode("utf-8"), end="")

def real_decrypt(keyfile, stre):
    with open(keyfile, "rb") as f:
        key = f.read()
    for j in stre:
        i = tuple([unhexlify(x) for x in j.rstrip().split(",")])
        yield AES.new(key, AES.MODE_CFB, i[0]).decrypt(i[1])

def decrypt(outfile1, keyfile, decrypted):
    with open(decrypted, "wb") as f:
        with open(outfile1, "r") as encfile:
            for i in real_decrypt(keyfile, encfile):
                f.write(i)

def real_patch(diffdata, encfile, key, tostdout):
    p = parse_unidiff(diffdata)
    for patchedfile in p:
        # TODO read file name from PatchedFile and let this function process trees instead of files
        for hunk in patchedfile:
            with open(encfile, "r+b") as encf:
                lines = encf.readlines()[:hunk.source_start-1]
                """
                for i in range(len(hunk.source_lines)):
                    if hunk.source_types[i] in (' ', '-'):
                        pass
                    else:
                        assert False
                """

                for i in range(len(hunk.target_lines)):
                    if hunk.target_types[i] in (' ','+'):
                        iv = os.urandom(16)
                        aes = AES.new(key, AES.MODE_CFB, iv)
                        lines.append(hexlify(iv) + b"," + hexlify(aes.encrypt(hunk.target_lines[i])) + b"\n")
                    else:
                        assert False
        if tostdout:
            print(b''.join(lines).decode("utf-8").rstrip())
        else:
            with open(encfile, "wb") as f:
                f.write(b''.join(lines).rstrip())

def patch(encfile, keyfile, tostdout=False):
    with open(keyfile,"rb") as f:
        real_patch(sys.stdin, encfile, f.read(), tostdout)

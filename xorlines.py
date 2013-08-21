import os, operator, itertools, sys, os.path
from binascii import unhexlify, hexlify
from unidiff.parser import parse_unidiff

def encrypt(infile, outfile1, keyfile):
    breakpositions = []

    def findnewlines():
        with open(infile, "rb") as f:
          for x in zip(f.read(), itertools.count()):
              if x[0] == ord(b'\n'):
                  breakpositions.append(x[1])
              else:
                  yield x[0]

    nobreaks = bytes(findnewlines())

    key = os.urandom(len(nobreaks))
    with open(keyfile, "wb") as f:
        f.write(key)

    for i in reversed(range(len(breakpositions))):
        if i != 0:
            breakpositions[i] -= breakpositions[i-1] + 1

    with open(outfile1, "wb") as f:
        encrypted_no_breaks = (operator.xor(*x) for x in zip(nobreaks, key))
        for i in breakpositions:
            f.write(hexlify(bytes(next(encrypted_no_breaks) for i in range(i))))
            f.write(b'\n')
        f.write(hexlify(bytes(encrypted_no_breaks)))

def decrypt(outfile1, keyfile, decrypted):
    def decode():
        with open(outfile1, "r") as encfile:
            for i in encfile:
                yield unhexlify(i.strip())

    with open(keyfile, "rb") as key:
        with open(decrypted, "wb") as f:
            for i in decode():
                f.write(bytes(operator.xor(*x) for x in zip(i,key.read(len(i)))))
                f.write(b'\n')

def patch(diffdata, encdir, keydir):
    p = parse_unidiff(diffdata)
    for patchedfile in p:
        for hunk in patchedfile:
            encfile = os.path.join(encdir, patchedfile.path)
            keyfile = os.path.join(keydir, patchedfile.path)
            with open(encfile, "r+") as encf:
                with open(keyfile, "r+b") as keyf:
                    # TODO http://programmers.stackexchange.com/questions/208436/zero-knowledge-code-hosting
                    print(hunk)

def cmdlinepatch(encdir, keydir):
    patch(sys.stdin, encdir, keydir)

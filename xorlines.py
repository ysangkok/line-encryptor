import os, sys
from binascii import unhexlify, hexlify
from unidiff import PatchSet
from Crypto.Cipher import AES
import codecs

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

def line_decryptor(key):
    def func(line):
        if not isinstance(line, str): line = line.decode("utf-8")
        i = tuple([unhexlify(x) for x in line.rstrip().split(",")])
        return AES.new(key, AES.MODE_CFB, i[0]).decrypt(i[1])
    return func

def real_decrypt(keyfile, stre):
    with open(keyfile, "rb") as f:
        key = f.read()
    yield from map(line_decryptor(key), stre)

def decrypt(outfile1, keyfile, decrypted):
    with open(decrypted, "wb") as f:
        with open(outfile1, "r") as encfile:
            f.writelines(real_decrypt(keyfile, encfile))

def real_patch(diffdata, encfile, key, tostdout):
    if isinstance(diffdata, str):
        p = PatchSet.from_filename(diffdata)
    else:
        p = PatchSet(diffdata)

    if len(p) == 0:
        raise Exception("No patched files in this diff, sure you remembered the -u for diff?")
    # TODO read file name from PatchedFile and let this function process file/directory trees instead of just one filr
    if len(p) != 1:
        raise Exception("can't handle multiple files")
    for patchedfile in p:
        with open(encfile, "r+b") as encf:
            alllines = encf.readlines()
            lines = []
            def seelines():
                """ for debugging in pdb """
                return list(map(line_decryptor(key),lines))
            def addline(val):
                iv = os.urandom(16)
                aes = AES.new(key, AES.MODE_CFB, iv)
                lines.append(hexlify(iv) + b"," + hexlify(aes.encrypt(val + "\n")) + b"\n")
            for hunk in patchedfile:
                for line in hunk:
                    def useoldline():
                        crypted = alllines[line.source_line_no-1]
                        decrypted = line_decryptor(key)(crypted)
                        assert decrypted == line.value.encode("utf-8") + b"\n", (decrypted, line.value)
                        lines.append(crypted)
                    if line.is_removed: continue
                    if line.is_context:
                        useoldline()
                    else:
                        if line.source_line_no is not None:
                            useoldline()
                        else:
                            assert line.is_added
                            addline(line.value)

            if tostdout:
                print(b''.join(lines).decode("utf-8").rstrip())
            else:
                encf.truncate(0)
                encf.seek(0)
                encf.write(b''.join(lines).rstrip())

def patch(encfile, keyfile, tostdout=False, input_source=sys.stdin):
    with open(keyfile, "rb") as f:
        real_patch(input_source, encfile, f.read(), tostdout)

def info(type, value, tb):
   if hasattr(sys, 'ps1') or not sys.stderr.isatty() or type != AssertionError:
      # we are in interactive mode or we don't have a tty-like
      # device, so we call the default hook
      sys.__excepthook__(type, value, tb)
   else:
      import traceback, pdb
      # we are NOT in interactive mode, print the exception...
      traceback.print_exception(type, value, tb)
      print
      # ...then start the debugger in post-mortem mode.
      pdb.pm()

sys.excepthook = info

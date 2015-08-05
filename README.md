Install `python3-crypto` (Ubuntu package name, see http://pycrypto.org for installation on other OS'es), clone `xorlines`, `git submodule update` and try this in its directory:

```
mkdir input output
shuf -n10 /usr/share/dict/words > input/myfile1
python3 -c "import xorlines; xorlines.encrypt('input/myfile1','output/myfile1', 'key')"
ls output/myfile1 # this is the encrypted file just generated
(cd output; git init && git add . && git commit -m "first commit")
(head -n 2 input/myfile1;
 shuf -n2 /usr/share/dict/words;
 tail -n4 input/myfile1;
 head -n1 input/myfile1;
) > input/newmyfile1
diff -y input/{,new}myfile1 # show mock changes we just made
(cd input; diff -u myfile1 newmyfile1 | PYTHONPATH=.. python3 -c "import xorlines; xorlines.patch('../output/myfile1', '../key')")
(cd output; git diff) #should show only some lines changed, not the first two
```

Test
----

    input $ diff -u myfile1 newmyfile1 | \
            PYTHONPATH=.. python3 -c "import xorlines; xorlines.patch('../output/myfile1', '../key', True)" | \
            PYTHONPATH=.. python3 -c "import xorlines; xorlines.decrypt_text_to_stdout('../key')" | \
            diff - newmyfile1
    input $ # should output nothing, that is, the decrypted patched ciphertext file is identical to the new plaintext

If it fails, use this for debugging
---

    input $ PYTHONPATH=.. python3 -c "import xorlines; xorlines.patch('../output/myfile1', '../key', True, '"<(diff -u myfile1 newmyfile1)"')"

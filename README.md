sjcl-enhancements
=============
Enhancements to the excellent [SJCL encryption engine](https://github.com/bitwiseshiftleft/sjcl).

cbc.js
------
An adapter layer that adds streamed OpenSSL-compatible CBC on top of SJCL; the input can be fed to the engine in arbitrary-sized chunks, and it will buffer them as necessary and feed complete AES blocks to SJCL for encryption/decryption. NOTE: Unlike some other modes, CBC does not offer automatic message authentication. So, developers should be sure to combine this with SJCL's HMAC calculation. The typical best practice is to HMAC the ciphertext not the plaintext.

randomReset.js
--------------
An adapter that allows for unseeding of the SJCL Fortuna random number generator.
describe(
    "cbc",
    function() {
        it(
            "should roundrip a simple string",
            function() {
                var plaintext = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.",
                    key = [1540795375, 323807810, 2117179923, -343449287, -1922477503, -1024368067, 1967463522, 335157298],
                    iv = [0xf34481ec,0x3cc627ba,0xcd5dc3fb,0x08f273e6],
                    plaintextByteCodes = sjcl.codec.bytes.fromBits(sjcl.codec.utf8String.toBits(plaintext));

                var output = sjclE.cbc.StringOutput();
                var encryptor = sjclE.cbc.OpenSSLByteStreamEncryptor(key, iv, sjclE.cbc.Base64WithBreaksWordEncoder(output));
                encryptor.writeData(plaintextByteCodes);
                encryptor.close();
                var encryptResults = output.getResult();

                // now decrypt
                output = new sjclE.cbc.ByteStringOutput();
                var decryptor = new sjclE.cbc.OpenSSLWordStreamDecryptor(key, output); 
                var decoder = new sjclE.cbc.Base64WithBreaksByteDecoder(decryptor);
                decoder.writeData(encryptResults);
                decoder.close();
                var decryptResults = output.getResult();
                expect(decryptResults === plaintext)
                .toBe(true);
            }
        );
    }
);

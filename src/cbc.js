sjclE.cbc = {
    /**
     * XOR corresponding elements of two equal-sized arrays, updating the first
     * array with the result.
     */
    xorArrayInPlace: function (target, operand) {
        for (var i = target.length - 1; i >= 0; i--) {
            /*jslint bitwise: false*/
            target[i] ^= operand[i];
            /*jslint bitwise: true*/
        }
    },

     /**
     * Block interface.
     * writeBlock(block): parameter is a mutable array. Keep in mind
     *      that it may be changed.
     * writeTail(block): always called last, with either a zero-length
     *      or shorter-than-usual block. As with writeBlock, the array
     *      may be modified in place by the recipient.
     *
     * Stream interface.
     * writeData(data): parameter is a constant array, not changed by
     *      the recipient.
     * close(): must be called last. Takes care of any pending
     *      buffered data.
     *
     * Segmenter adapts an object with a block interface so that it
     * can be called with the streaming interface, taking care of the
     * necessary buffering.
     */


    /**
     * Segment arbitrary-sized streamed input into fixed-size chunks.
     * Returns an object that provides writeData and close methods.
     *
     * writeData takes string or array data, depending on what the
     * output object expects.
     *
     * Calls output.writeData on the output object for each
     * standard-sized chunk, then output.writeTail for any remainder
     * on close().
     *
     * Warning: if initialBuffer is an array, it may be modified in
     * place.
     */
    StreamSegmenter: function (size, initialBuffer, output) {
        var buffer = initialBuffer;
        return {
            writeData: function (input) {
                for (var offset = size - buffer.length,
                         block = buffer.concat(input.slice(0, offset));
                     block.length === size;
                     offset += size,
                         block = input.slice(offset - size, offset)) {
                    output.writeBlock(block);
                }
                buffer = block;

            },
            close: function () {
                output.writeTail(buffer);
            }
        };
    },

    CBCWordStreamEncryptor: function (key, iv, output) {
        var aes = new sjcl.cipher.aes(key),
            prevCipherBlock = iv,
            bufferedPlainBlock = '';
            // Always buffer one block for use by writeTail, because
            // the last SJCL 32-bit word may encode less than 4 bytes.

        function writeFullBlock(plainBlock) {
            sjclE.cbc.xorArrayInPlace(plainBlock, prevCipherBlock);
            prevCipherBlock = aes.encrypt(plainBlock);
            output.writeData(prevCipherBlock);
        }

        return new sjclE.cbc.StreamSegmenter(4, [], {
            writeBlock: function (plainBlock) {
                // Always encrypt one block behind and buffer the new block
                if (bufferedPlainBlock) {
                    writeFullBlock(bufferedPlainBlock);
                }
                bufferedPlainBlock = plainBlock;
            },

            writeTail: function (tailBlock) {
                // Add OpenSSL-compatible CBC padding for last block.

                // May use the buffered plain block as the tail if the tail given
                // was zero-length and the last block was not complete: even though
                // it consisted of 4 32-bit words, the last 32-bit word was a
                // SJCL bitArray 'partial' value representing only 1-3 bytes.
                // (Specifically, this happens when the plaintext length mod 16
                // is 13, 14, or 15.)
                var bufferedBytes,
                    fromBits = sjcl.codec.bytes.fromBits,
                    tailBlockBytes = fromBits(tailBlock);
                    // Explode the tail into 0-15 bytes.
                if (!tailBlockBytes.length
                    && (bufferedBytes = fromBits(bufferedPlainBlock)).length < 16) {
                    // No tail passed in, and previous plain block was less than 16
                    // bytes, making it the real tail.
                    tailBlockBytes = bufferedBytes;
                }
                else if (bufferedPlainBlock) {
                    // Previous plain block was complete after all. Encrypt it.
                    writeFullBlock(bufferedPlainBlock);
                }

                // Pad to 16 bytes using OpenSSL CBC scheme. tailBlockBytes.length
                // is always between 0 and 15 inclusive.
                var padByte = 16 - tailBlockBytes.length;
                while (tailBlockBytes.length < 16) {
                    tailBlockBytes.push(padByte);
                }
                writeFullBlock(sjcl.codec.bytes.toBits(tailBlockBytes));
                output.close();
            }
        });
    },

    CBCWordBlockDecryptor: function (key, iv, output) {
        var aes = new sjcl.cipher.aes(key),
            prevCipherBlock = iv,
            lastPlainBlock = null;
        return {
            writeBlock: function (cipherBlock) {
                if (lastPlainBlock !== null) {
                    output.writeData(lastPlainBlock);
                }
                lastPlainBlock = aes.decrypt(cipherBlock);
                sjclE.cbc.xorArrayInPlace(lastPlainBlock, prevCipherBlock);
                prevCipherBlock = cipherBlock;
            },

            writeTail: function (partialCipherBlock) {
                var padding, expandedBlock;
                if (partialCipherBlock.length || lastPlainBlock === null) {
                    // error: encrypted data not a multiple of block size
                    throw 'Decryption error';
                }
                // Undo padding of last block
                expandedBlock = sjcl.codec.bytes.fromBits(lastPlainBlock);
                padding = expandedBlock[15];
                if (padding < 0 || padding > 16) {
                    throw 'Decryption error';
                }
                if (padding !== 16) {
                    output.writeData(sjcl.codec.bytes.toBits(
                        expandedBlock.slice(0, 16 - padding)));
                }
                output.close();
            }
        };
    },

    OpenSSLWordStreamEncryptor: function (key, iv, output) {
        output.writeData(iv);
        return new sjclE.cbc.CBCWordStreamEncryptor(key, iv, output);
    },

    OpenSSLByteStreamEncryptor: function (key, iv, output) {
        var toBits = sjcl.codec.bytes.toBits,
            chain = new sjclE.cbc.OpenSSLWordStreamEncryptor(key, iv, output),
            BLOCK_SIZE = 256; // words
        // Must batch input in some multiple of 4 bytes, so that toBits will
        // be able to gather complete words.SJCL's AES
        // implemention will get complete words.
        return new sjclE.cbc.StreamSegmenter(4 * BLOCK_SIZE, [], {
            writeBlock: function (data) {
                chain.writeData(toBits(data));
            },
            writeTail: function (data) {
                chain.writeData(toBits(data));
                chain.close();
            }
        });
    },

    OpenSSLWordStreamDecryptor: function (key, output) {
        return new sjclE.cbc.StreamSegmenter(4, [], {
            writeBlock: function (block) {
                // Header block
                var decryptor = new sjclE.cbc.CBCWordBlockDecryptor(key, block, output);
                // Replace the writeBlock and writeTail functions with the
                // decryptor's functions, now that the header has been read.
                this.writeBlock = decryptor.writeBlock;
                this.writeTail = decryptor.writeTail;
            },

            writeTail: function (block) {
                // The input didn't even have a complete header
                throw 'Decryption error.';
            }
        });
    },

    Base64WithBreaksWordEncoder: function (output) {
        return new sjclE.cbc.StreamSegmenter((64 * 6) / 32, [], {
            writeBlock: function (block) {
                // Encode 48 bytes of input into a 64-char Base64 line + '\n'
                output.writeData(sjcl.codec.base64.fromBits(block) + '\n');
            },
            writeTail: function (block) {
                // Encode less than 48 bytes of input.
                // The writeBlock function can handle short lines, so punt
                // there.
                this.writeBlock(block);
                output.close();
            }
        });
    },

    Base64ByteDecoder: function (output) {
        // The StreamSegmenter here ensures that each 4-byte block is
        // complete before attempting to decode it, in case the caller's
        // multiple writeData() calls split any in the middle.
        // Any multiple of 4 for the segment size would do. Higher numbers
        // buffer data and minimize function call overhead.
        return new sjclE.cbc.StreamSegmenter(1024, '', {
            writeBlock: function (block) {
                output.writeData(sjcl.codec.base64.toBits(block));
            },
            writeTail: function (block) {
                output.writeData(sjcl.codec.base64.toBits(block));
                output.close();
            }
        });
    },

    Base64WithBreaksByteDecoder: function (output) {
        var decoder = new sjclE.cbc.Base64ByteDecoder(output);
        return {
            writeData: function (data) {
                decoder.writeData(data.replace(/[\r\n]/g, ''));
            },
            close: function () {
                decoder.close();
            }
        };
    },

    ByteStringOutput: function () {
        var rarray = [];
        var result = '';
        return {
            getResult: function () {
                if (rarray.length) {
                    result += rarray.join('');
                }
                return result;
            },
            writeData: function (arr) {
                // based on sjcl.codec.utf8.fromBits, minus the utf8 part
                var bl = sjcl.bitArray.bitLength(arr), i, tmp;
                for (i = 0; i < bl / 8; i++) {
                    /*jslint bitwise: false*/
                    if ((i & 3) === 0) {
                    /*jslint bitwise: true*/
                        tmp = arr[i / 4];
                    }
                    /*jslint bitwise: false*/
                    rarray.push(String.fromCharCode(tmp >>> 24));
                    /*jslint bitwise: true*/
                    if (rarray.length == 512) {
                        result += rarray.join('');
                        rarray = [];
                    }
                    /*jslint bitwise: false*/
                    tmp <<= 8;
                    /*jslint bitwise: true*/
                }
            },
            close: function () {
            }
        };
    },

    StringOutput: function () {
        var result = '';
        return {
            getResult: function () {
                return result;
            },
            writeData: function (data) {
                result += data;
            },
            close: function () {
            }
        };
    }
};

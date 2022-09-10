const { Buffer } = require('buffer');
const net = require('net');
const crypto = require('crypto');
const https = require('https');
const dns = require('dns');
const { createInflate, deflate } = require('zlib');
const { Duplex, Readable, Writable } = require('stream');

/**
 * Base class for a reader/writer
 */
class BaseDataParser {
    /**
     * The stream
     * @param {Readable | Writable | Duplex} stream 
     */
    constructor(stream) {
        this.stream = stream;
        this.error = null;
        this.stream.on('error', ex => this.error = ex);
        this.waitlist = Promise.resolve(true);
        this.canEnd = false;
        this.hasEnded = false;
        stream.once(stream._read ? 'end' : 'finish', () => this.hasEnded = true);
        stream.once('error', () => this.hasEnded = true);
    }

    /**
     * Returns the 'same' promise, however the returned promise will reject if the streams errors.
     * And if the given promise rejects, the stream will destroy with that error
     * @param {Promise} promise 
     * @returns {Promise}
     */
     streamPromise(promise, canEnd) {
        var stack = new Error("stack");
        return new Promise((resolve, reject) => {
            if(this.error) {
                reject(this.error);
                return;
            }
            if(canEnd == null) canEnd = this.canEnd;
            var listener = ex => reject(ex);
            this.stream.once('error', listener);
            var listener2 = () => canEnd ? resolve(null) : reject(new Error("Operation while stream has ended"));
            var eventName = this.stream._read ? 'end' : 'finish';
            this.stream.once(eventName, listener2)
            Promise.resolve(promise)
            .finally(() => {
                this.stream.removeListener(eventName, listener2);
                this.stream.removeListener('error', listener);
            })
            .catch(ex => {
                try{this.stream.destroy(ex);}catch(_){}
                reject(ex)
            })
            .then(value => resolve(value))
            .catch(ex => reject(ex))
        }).catch(ex => {
            if(ex && ex.stack && stack.stack) ex.stack += "\n" + stack.stack;
            throw ex;
        });
    }

    /**
     * Resolves if ALL tasks have been completed
     * @returns {Promise}
     */
    streamReady() {
        if(this.error) return Promise.reject(this.error);
        return this.waitlist;
    }

    /**
     * Add a task to the waitlist
     * This task will be run if all other tasks have completed, and the next task will be run if this task has been completed.
     * @param {(() => Promise) | Promise} promise A function that can be invoked after all previous tasks have been done
     * @returns 
     */
    addWaitlist(promise) {
        var canEnd = this.canEnd;
        this.waitlist = this.streamReady().then(() => this.streamPromise(typeof promise == 'function' ? promise() : promise, canEnd));
        return this.waitlist;
    }
}

/**
 * A reader can parse minecraft packets from a Readable stream.
 */
class ReadableDataParser extends BaseDataParser {
    /**
     * The stream
     * @param {Readable} stream 
     */
    constructor(stream) {
        super(stream);
        this.index = 0;
        
    }
    

    /**
     * Resolves with a promise if it is save to read from this stream
     * @param {bool} canEnd if true, it will return (as if the stream was readable) if the stream ended otherwise it will throw an Error
     * @returns {Promise} a promise that resolves when it is safe to read
     */
    onReadable(canEnd) {
        return this.streamPromise(new Promise(callback => this.stream.once('readable', () => callback())), canEnd);
    }


    /**
     * Read bytes from the stream
     * @param {number} size 
     * @returns {Promise<Buffer>}
     */
    readBytes(size) {
        var canEnd = this.canEnd;
        return this.addWaitlist(async () => {
            if(size < 1) return Buffer.alloc(0);
            this.index += size;
            var bytes;
            var firstTry = true;
            while(1) {
                /*if(this.hasEnded) {
                    if(canEnd) return null;
                    throw new Error("Read while stream has ended");
                }*/
                var nbytes = this.stream.read(size - (bytes ? bytes.length : 0));
                if(!nbytes && (!firstTry || this.hasEnded)) {
                    if(canEnd) return null;
                    throw new Error("Read while stream has ended");
                }
                if(nbytes) bytes = bytes ? Buffer.concat([bytes, nbytes]) : nbytes;
                nbytes = null;
                if(bytes != null && bytes.length >= size) {
                    return bytes.slice(0, size);
                }
                await this.onReadable(canEnd);
                firstTry = false;
            }
        });
    }

    /**
     * Read a single byte
     * @returns {Promise<number>}
     */
    readByte() {
        return this.readBytes(1).then(buff => buff ? buff[0] : null);
    }

    /**
     * Read a MC varInt
     * @param {bool} saveRead If canEnd = true, to store the already readed data and return that. 
     *                        If false, ended while reading a varInt (no matter what canEnd) it will throw an Error.
     * @returns {Promise<number>} A promise that resolves with the varint
     */
    async readVarInt(saveRead = false) {
        var numRead = 0;
        var result = 0;
        var start = true;
        var readed = saveRead ? [] : null;
        do {
            var read = await this.readByte();
            if(read == null && start) return null;
            if(read == null) {
                if(readed) return readed;
                throw new Error("EoF in var int");
            }
            if(readed) readed.push(read);
            start = false;
            var value = (read & 0b01111111);
            result |= (value << (7 * numRead));

            numRead++;
            if (numRead > 5) {
                throw new Error("VarInt is too big");
            }
        } while ((read & 0b10000000) != 0);

        return result;
    }

    /**
     * Read a unsigned short (2 bytes) in BE
     * @returns {Promise<number>} value of the Unsigned Short
     */
    readUnsignedShort() {
        return this.readBytes(2).then(buff => buff ? buff.readUInt16BE(0) : null);
    }

    /**
     * Read a signed short (2 bytes) in BE
     * @returns {Promise<number>} value of the short
     */
    readShort() {
        return this.readBytes(2).then(buff => buff ? buff.readInt16BE(0) : null);
    }

    /**
     * Read a signed int (4 bytes) in BE
     * @returns {Promise<number>} value of the int
     */
    readInt() {
        return this.readBytes(4).then(buff => buff ? buff.readInt32BE(0) : null);
    }

    /**
     * Read a signed long (8 bytes) in BE
     * @returns {Promise<bigint>} value of signed long as a BigInt
     */
    readLong() {
        return this.readBytes(8).then(buff => buff ? buff.readBigInt64BE(0) : null);
    }

    /**
     * Read a string (up to maxLength) prefixed by a length as a VarInt
     * @param {number} maxLength max length to read, if the string is longer an Error will be thrown 
     * @returns {Promise<string>} the string value
     */
    async readString(maxLength) {
        var len = await this.readVarInt();
        if(len == null) return null;
        if(maxLength && len > maxLength) {
            var err = new RangeError("String too big: " + len + " > " + maxLength);
            try{this.stream.destroy(err)} catch(_) {}
            throw err;
        }
        var data = await this.readBytes(len);
        if(data == null) throw new Error("EoF in string");
        return data.toString('utf-8');
    }
}

/**
 * A WritableDataBuffer can contain Minecraft data/packets
 * that can be written to a WritableDataParser
 */
class WritableDataBuffer {
    constructor(size, parser, block) {
        if(!size) size = 50;
        this.buffer = Buffer.alloc(size);
        this.length = 0;
        if(parser && !(parser instanceof WritableDataParser)) throw new TypeError("parser must be a writable data parser")
        this.parser = parser || null;
        var oldCallback = (push, pending) => { 
            if(!parser) throw new TypeError("No parser given");
            if(push) return pending ? this.parser.appendPending(this.toBuffer()) : this.parser.writeBytes(this.toBuffer()); 
            else throw new TypeError("Cannot abort because buffer is not waiting"); 
        };;
        if(!block) {
            this.isBlocked = false;
            this.onPushed = Promise.resolve(true);
            this._callback = oldCallback;
        } else {
            this.isBlocked = true;
            this.aborted = false;
            var didAbort = false;
            var running = false;
            var callbackWait = new Promise(resolve => this._callback = (push, pending) => { 
                this._callback = (push, pending) => {
                    if(push) oldCallback(push, pending);
                    else {
                        this.aborted = true;
                        didAbort = true;
                    }
                };
                resolve([push, pending]);
            });
            
            this.onPushed = parser.addWaitlist(() => new Promise((resolve, reject) => callbackWait.then(([push, pending]) => {
                this._callback = (push, pending) => {
                    if(push) oldCallback(push, pending);
                    else {
                        this.aborted = true;
                        resolve(false);
                    }
                };
                push = didAbort ? false : push;
                if(push) {
                    running = true;
                    if(pending) {
                        this.parser.pendingWriteBuffer = Buffer.concat([this.parser.pendingWriteBuffer, this.toBuffer()]);
                        resolve(true);
                    } else {
                        var buff = this.toBuffer();
                        if(this.parser.pendingWriteBuffer && this.parser.pendingWriteBuffer.length > 0) {
                            buff = Buffer.concat([this.parser.pendingWriteBuffer, buff]);
                            this.parser.pendingWriteBuffer = Buffer.alloc(0);
                        }
                        this.parser.stream.write(buff, err => {
                            this.isBlocked = false;
                            if(err) reject(err);
                            else resolve(true);
                        });
                    }
                } else {
                    this.aborted = true;
                    resolve(false);
                }
            }))).catch(() => false);
        }
    }

    /**
     * Convert this class to a Node.JS Buffer
     * @returns {Buffer} the buffer containg the contents of this class
     */
    toBuffer() {
        var fixed = Buffer.alloc(this.length);
        this.buffer.copy(fixed, 0, 0, this.length);
        return fixed;
    }

    /**
     * Resize the length of the WritableDataBuffer.
     * If necessary, the capacity will be resized too
     * @param {number} minimal_size Minimal required length.  
     * @returns {undefined}
     */
    resizeBuffer(minimal_size) {
        if(minimal_size < this.length) return;
        this.length = minimal_size;
        if(minimal_size < this.buffer.length) return;
        var newSize = this.buffer.length * 2;
        if(newSize < minimal_size) newSize = minimal_size;
        var nbuff = Buffer.alloc(newSize);
        this.buffer.copy(nbuff, 0, 0, this.buffer.length);
        this.buffer = nbuff;
        
    }

    /**
     * Write a single unsigned byte to this buffer
     * @param {number} value the unsigned byte value
     * @param {number | null} index the index to write at, or null (default) to write at the end
     * @returns {{index: number, length: number}}
     */
    writeByte(value, index) {
        if(index == null) index = this.length;
        this.resizeBuffer(index + 1);
        this.buffer[index] = value;
        return { index, length: 1 };
    }

    /**
     * Write multiple bytes to this buffer
     * @param {Buffer} buffer buffer containing the data to write
     * @param {number | null} index the index to write at, or null (default) to write at the end 
     * @returns  {{index: number, length: number}}
     */
    writeBytes(buffer, index) {
        if(!(buffer instanceof Buffer)) buffer = Buffer.from(buffer);
        if(buffer.length < 1) return { index, length: 0 }
        if(index == null) index = this.length;
        this.resizeBuffer(index + buffer.length);
        buffer.copy(this.buffer, index, 0, buffer.length);
        return { index, length: buffer.length }
    }

    /**
     * Write a MC varint to this buffer
     * @param {number} value The varint to write (as a number value) 
     * @param {number | null} index the index to write at, or null (defualt) to write at the end.
     * @returns  {{index: number, length: number}}
     */
    writeVarInt(value, index) {
        if(index == null) index = this.length;
        var start = index;
        do {
            var temp = value & 0b01111111;
            value >>= 7;
            if (value != 0) {
                temp |= 0b10000000;
            }
            index = this.writeByte(temp, index).index + 1;
        } while (value != 0);
        return { length: index - start, index: start };
    }

    /**
     * Write an unsigned short (2 bytes) in BE
     * @param {number} value The unsigned short
     * @param {number | null} index The index to write at or null (default) to write at the end 
     * @returns  {{index: number, length: number}}
     */
    writeUnsignedShort(value, index) {
        if(index == null) index = this.length;
        this.resizeBuffer(index + 2);
        this.buffer.writeUInt16BE(value, index);
        return { index, length: 2 };
    }

    writeShort(value, index) {
        if(index == null) index = this.length;
        this.resizeBuffer(index + 2);
        this.buffer.writeInt16BE(value, index);
        return { index, length: 2 };
    }

    writeLong(value, index) {
        if(index == null) index = this.length;
        this.resizeBuffer(index + 8);
        this.buffer.writeBigInt64BE(value, index);
        return { index, length: 8 };
    }
    
    writeString(value, index) {
        var buff = Buffer.from(value, 'utf-8');
        var ind = this.writeVarInt(buff.length, index);
        var ind2 = this.writeBytes(buff, ind.index + ind.length);
        return { index: ind.index, length: ind.length + ind2.length };
    }

    /**
     * Push the buffer directly to the underlying stream of the parser, flushing any internal buffers if needed.
     * @param {WritableDataParser} parser the parser to push, null if default (the one that created this parser) 
     * @returns {Promise}
     */
    push(parser) {
        if(parser === this.parser) parser = null;
        if(parser) {
            return parser.writeBytes(this.toBuffer());
        }
        if(!this.parser) throw new TypeError("There is no parser");
        return this._callback(true, false);
    }

    /**
     * Append the buffer to the internal buffer of the parser (for a later write call) instead of writing it directly to the underling stream
     * 
     * This improves perfomance, especially with TCP because TCP usually makes a TCP packet for every write(2) call.
     * @param {WritableDataParser} parser the parser to append internal buffer, null if default (the one that created this parser) 
     * @returns {Promise}
     */
    appendPending(parser) {
        if(parser === this.parser) parser = null;
        if(parser) {
            return parser.appendPending(this.toBuffer());
        }
        if(!this.parser) throw new TypeError("There is no parser");
        return this._callback(true, true);
    }

    /**
     * If this buffer was created as a blocking checkpoint, you can unblock it (without pushing) with this function
     * @returns {Promise}
     */
    abort() {
        return this._callback(false, false);
    }
}

/**
 * A WritableDataParser can send minecraft packets using a WritableDataBuffer.
 */
class WritableDataParser extends BaseDataParser {
    /**
     * The stream
     * @param {Writable} stream 
     */
    constructor(stream) {
        super(stream);
        this.pendingWriteBuffer = Buffer.alloc(0);
    }

    /**
     * Write multiple bytes directly to the underlying stream
     * @param {Buffer} buffer the buffer to write
     * @returns {Promise} a promise that resolves when the data is written.
     */
    writeBytes(buffer) {
        return this.addWaitlist(() => new Promise((resolve, reject) => {
            var buff = (this.pendingWriteBuffer && this.pendingWriteBuffer.length > 0) ? Buffer.concat([this.pendingWriteBuffer, buffer]) : buffer;
            if(buff !== buffer) this.pendingWriteBuffer = Buffer.alloc(0);
            if(buff.length < 1) {
                resolve();
                return;
            }
            this.stream.write(buff, err => {
                if(err) reject(err);
                resolve();
            });
        }));
    }

    /**
     * Flush any internal buffers to write the data to the underlying Node.JS stream.
     * 
     * There are only internal buffers if appendPending() is used, 
     * buffers are always flushed if writeBytes() on this class or push() on a WritableDataBuffer (created without appendPending()) is used.
     * @returns {Promise} a promise that resolves when all data is written.
     */
    flush() {
        return this.writeBytes(Buffer.alloc(0));
    }

    /**
     * Pushes the buffer to the internal buffer of this class instead writing it to the underlying stream.
     * 
     * This improves perfomance, especially with TCP because TCP usually makes a TCP packet for every write(2) call.
     * @param {Buffer} buffer the buffer to write
     * @returns {Promise} A promise that resolves when the data is pushed
     */
    appendPending(buffer) {
        return this.addWaitlist(() => new Promise(callback => {
            if(buffer.length < 1) {
                callback();
                return;
            }
            this.pendingWriteBuffer = Buffer.concat([this.pendingWriteBuffer, buffer]);
            callback();
        }));
    }
    
    /**
     * Create a buffer that can push data to this parser
     * @param {number} size  Initial capacity for the buffer, should be big enough (not required) so that it won't reallocate the buffer.
     * @returns {WritableDataBuffer} The newly created data buffer
     */
    createBuffer(size) {
        return new WritableDataBuffer(size, this, false);
    }

    /**
     * Create a buffer that blocks this parses until it pushes all the data to the underlying stream (or cancels)
     * @param {number} size Initial capacity for the buffer, should be big enough (not required) so that it won't reallocate the buffer.
     * @returns {WritableDataBuffer} The newly created data buffer
     */
    createCheckpoint(size) {
        return new WritableDataBuffer(size, this, true);
    }
}


/**
 * Validate the UUID and convert any UUID (that has dashes or not) to a UUID with dashes
 * @param {string} id the UUID (with dashes or not) to validate and convert
 * @returns {string} an UUID always with dashes
 */
function uuidWithDashes(id) {
    return [.../([a-z0-9]{8})\-?([a-z0-9]{4})\-?([a-z0-9]{4})\-?([a-z0-9]{4})\-?([a-z0-9]{12})/.exec(id)].slice(1).join('-')
}

/**
 * Validate the UUID and convert any UUID (that has dashes or not) to a UUID without dashes
 * @param {*} id the UUID (with dashes or not) to validate and convert
 * @returns {string} an UUID always without dashes
 */
function uuidWithoutDashes(id) {
    return [.../([a-z0-9]{8})\-?([a-z0-9]{4})\-?([a-z0-9]{4})\-?([a-z0-9]{4})\-?([a-z0-9]{12})/.exec(id)].slice(1).join('')
}

/**
 * Convert a binary buffer to a MC HEX string (e.g used to join servers.)
 * 
 * Usually the binary buffer is the output of a SHA1 hash
 * @param {string | Buffer} str the binary data 
 * @returns {string} A MC hex digest (which may start with a - instead of a valid hex character)
 */
function mcHexDigest(str) {
    var hash = Buffer.from(str, 'binary');
    // check for negative hashes
    var negative = hash.readInt8(0) < 0;
    if (negative) performTwosCompliment(hash);
    var digest = hash.toString('hex');
    // trim leading zeroes
    digest = digest.replace(/^0+/g, '');
    if (negative) digest = '-' + digest;
    return digest;
  
  }
  
  //Help function for mcHexDigest if output is negative
  function performTwosCompliment(buffer) {
    var carry = true;
    var i, newByte, value;
    for (i = buffer.length - 1; i >= 0; --i) {
      value = buffer.readUInt8(i);
      newByte = ~value & 0xff;
      if (carry) {
        carry = newByte === 0xff;
        buffer.writeUInt8(carry ? 0 : newByte + 1, i);
      } else {
        buffer.writeUInt8(newByte, i);
      }
    }
  }

/**
 * Generate a pseudo random SECURE 16 bytes secret for AES encryption
 * @returns {Promise<Buffer>} Resolves with a 16 bytes buffer secure random data or an Error if secure random data cannot be generated.
 */
function generateMCSharedSecret() {
    return new Promise((resolve, reject) => {
        crypto.randomFill(Buffer.alloc(16), (err, buff) => {
            if(err) reject(err);
            else resolve(buff);
        });
    });
}

var supportsMCChiper = crypto.getCiphers().includes('aes-128-cfb8');

/**
 * Create an encryption stream to encrypt 
 * @param {Buffer} sharedSecret the 128-bits key (both key and IV) for the chiper stream
 * @returns {Duplex} A duplex where you can write plain text data to get encrypted data out.
 */
function createMCChiperStream(sharedSecret) {
    if(supportsMCChiper) {
        let duplex = crypto.createCipheriv('aes-128-cfb8', sharedSecret, sharedSecret);
        duplex.secret = sharedSecret;
        return duplex;
    } else {
        /*
            We do NOT want to implement AES in pure JS because AES natively is way faster.
            Also some CPU's have AES instructions so that is even faster.

            We use the aes-128-ecb to create our stream chiper for MC.
        */
        var ecb = crypto.createCipheriv('aes-128-ecb', sharedSecret, Buffer.alloc(0));
        var register = Buffer.alloc(16);
        sharedSecret.copy(register, 0, 0, register.length);
        var duplex;
        var onReady = null;
        duplex = new Duplex({
            write(chunk, encoding, callback) {
                chunk = Buffer.from(chunk, encoding);
                var toSent = Buffer.allocUnsafe(chunk.length);
                var i = 0;
                for(var byte of chunk) {
                    try {
                        var block = ecb.update(register);
                        var be = byte ^ block[0]
                        register.copy(register, 0, 1, register.length);
                        register[register.length - 1] = be;
                        toSent[i++] = be;
                    } catch(ex) {
                        try{duplex.destroy(ex)}catch(_){}
                        callback(ex);
                        return;
                    }
                }
                var ret = true;
                if(!duplex.push(toSent)) {
                    onReady = () => duplex.emit('drain');
                    ret = false;
                } else {
                    onReady = null;
                }
                callback();
                return ret;
            },
            read(size) {
                if(onReady) {
                    onReady();
                    onReady = null;
                }
            }
        });
        duplex.secret = sharedSecret;
        duplex.ecb = ecb;
        return duplex;
    }
}

/**
 * Create a decryption stream
 * @param {Buffer} sharedSecret the 128-bits key (both key and IV) for the chiper stream
 * @returns {Duplex} A duplex where you can write encrypted data to get unencrypted data.
 */
function createMCDechiperStream(sharedSecret) {
    if( supportsMCChiper) {
        let duplex = crypto.createDecipheriv('aes-128-cfb8', sharedSecret, sharedSecret);
        duplex.secret = sharedSecret;
        return duplex;
    } else {
        /*
            We do NOT want to implement AES in pure JS because AES natively is way faster.
            Also some CPU's have AES instructions so that is even faster.

            We use the aes-128-ecb to create our stream dechiper for MC.
            Note that the block chiper here is also encrypt
        */
        var ecb = crypto.createCipheriv('aes-128-ecb', sharedSecret, Buffer.alloc(0));
        var register = Buffer.alloc(16);
        sharedSecret.copy(register, 0, 0, register.length);
        var duplex;
        var onReady = null;
        duplex = new Duplex({
            write(chunk, encoding, callback) {
                chunk = Buffer.from(chunk, encoding);
                var toSent = Buffer.allocUnsafe(chunk.length);
                var i = 0;
                for(var byte of chunk) {
                    try {
                        var block = ecb.update(register);
                        var be = byte ^ block[0]
                        register.copy(register, 0, 1, register.length);
                        register[register.length - 1] = byte;
                        toSent[i++] = be;
                    } catch(ex) {
                        try{duplex.destroy(ex)}catch(_){}
                        callback(ex);
                        return;
                    }
                }
                if(duplex.push(toSent)) {
                    callback();
                } else {
                    onReady = callback;
                }
            },
            read(size) {
                if(onReady) {
                    onReady();
                    onReady = null;
                }
            }
        });
        duplex.secret = sharedSecret;
        duplex.ecb = ecb;
        return duplex;
    }
}

function createReadableFromBuffer(buffer) {
    var str = new Readable();
    str.push(buffer);
    str.push(null);
    return str;
}

function createWritableToBuffer() {
    var ch = [];
    return [new Writable({
        write(chunk, encoding, callback) {
            chunk = encoding === 'buffer' ? chunk : Buffer.from(chunk, encoding);
            ch.push(chunk);
            callback();
        },
        writev(chunks, callback) {
            ch.push(...chunks.map(x => x.encoding === 'buffer' ? x.chunk : Buffer.from(x.chunk, x.encoding)));
            callback();
        }
    }), () => Buffer.concat(ch)];
}


/**
 * 
 * @param {(request: {
 *         state: 'login' | 'status', 
 *         legacy: boolean,
 *         host: string, port: number, 
 *         version: number, 
 *         username?: string, 
 *         remoteClient: net.Socket, 
 *         proxyServer: net.Server
 * }) => Promise<{
 *         host: string, 
 *         port: number, 
 *         cracked?: boolean,
 *         displayHost?: string | null,
 *         displayPort?: number | null, 
 *         version?: number | null, 
 *         status?: object | null,
 *         disconnectMessage?: string | object | null,
 *         verifyLogin?: (uuid: string, response: object) => Promise<boolean | null> | boolean | null,
 *         getDisconnectMessage: ('auth-failed' | 'user-denied' | 'cracked-not-allowed' | 'no-credentials' | 'login-failed' | 'connection-failed') => Promise<string | object | null> | string | object | null,
 *         getUser?: () => Promise<{
 *             username: string,
 *             uuid: string,
 *             sharedSecret?: Buffer,
 *             crackedLogin: () => Promise<boolean | null> | boolean | null,
 *             getCredentials: () => Promise<{ accessToken: string, uuid: string }> | { accessToken: string, uuid: string } | null,
 *             joinServer?: (serverId: string) => Promise<boolean | null> | false | null
 *         } | null> | {
 *             username: string,
 *             uuid: string,
 *             sharedSecret?: Buffer,
 *             crackedLogin: () => Promise<boolean | null> | boolean | null,
 *             getCredentials: () => Promise<{ accessToken: string, uuid: string }> | { accessToken: string, uuid: string } | null,
 *             joinServer?: (serverId: string) => Promise<boolean | null> | false | null
 *         } | null
 *     }> | {
 *         host: string, 
 *         port: number, 
 *         cracked?: boolean,
 *         displayHost?: string | null,
 *         displayPort?: number | null, 
 *         version?: number | null, 
 *         status?: object | null,
 *         disconnectMessage?: string | object | null,
 *         verifyLogin?: (uuid: string, response: object) => Promise<boolean | null> | boolean | null,
 *         getDisconnectMessage: ('auth-failed' | 'user-denied' | 'cracked-not-allowed' | 'no-credentials' | 'login-failed' | 'connection-failed') => Promise<string | object | null> | string | object | null,
 *         getUser?: () => Promise<{
 *             username: string,
 *             sharedSecret?: Buffer,
 *             crackedLogin: () => Promise<boolean | null> | boolean | null,
 *             getCredentials: () => Promise<{ accessToken: string, uuid: string }> | { accessToken: string, uuid: string } | null,
 *             joinServer?: (serverId: string) => Promise<boolean | null> | false | null
 *         } | null> | {
 *             username: string,
 *             sharedSecret?: Buffer,
 *             crackedLogin: () => Promise<boolean | null> | boolean | null,
 *             getCredentials: () => Promise<{ accessToken: string, uuid: string }> | { accessToken: string, uuid: string } | null,
 *             joinServer?: (serverId: string) => Promise<boolean | null> | false | null
 *         } | null
 *     }
 * } getServer 
 * @returns 
 */
function createProxyServer(getServer) {
    var keyPromise = new Promise((resolve, reject) => {
        crypto.generateKeyPair('rsa', {
            modulusLength: 1024,
            publicKeyEncoding: {
                type: 'spki',
                format: 'der'
              },
              privateKeyEncoding: {
                type: 'pkcs8',
                format: 'der',
              }
        }, (err, publicKey, privateKey) => {
            if(err) reject(err);
            else resolve({ publicKey, privateKey });
        });
    });
    var proxyServer = new net.Server(async cl => {
        try {
            //proxyServer.emit('connection', cl);
            var serverAddr, serverPort;
            var socket = null;
            var remoteAddr = cl.remoteAddress.toString(); //ooit voor logging
            /** @type {{
 *         host: string, 
 *         port: number, 
 *         cracked?: boolean,
 *         displayHost?: string | null,
 *         displayPort?: number | null, 
 *         version?: number | null, 
 *         status?: object | null,
 *         verifyLogin?: (uuid: string, response: object) => Promise<boolean | null> | boolean | null,
 *         getDisconnectMessage: ('auth-failed' | 'user-denied' | 'cracked-not-allowed' | 'no-credentials' | 'login-failed' | 'connection-failed') => Promise<string | object | null> | string | object | null,
 *         getUser?: () => Promise<{
 *             username: string,
 *             sharedSecret?: Buffer,
 *             crackedLogin: () => Promise<boolean | null> | boolean | null,
 *             getCredentials: () => Promise<{ accessToken: string, uuid: string }> | { accessToken: string, uuid: string } | null,
 *             joinServer?: (serverId: string) => Promise<boolean | null> | false | null
 *         } | null> | {
 *             username: string,
 *             sharedSecret?: Buffer,
 *             crackedLogin: () => Promise<boolean | null> | boolean | null,
 *             getCredentials: () => Promise<{ accessToken: string, uuid: string }> | { accessToken: string, uuid: string } | null,
 *             joinServer?: (serverId: string) => Promise<boolean | null> | false | null
 *         } | null
 *     } | null} */
            var serverInfo = null;
            /** @type {{host: string, port: number, version: number}} */
            var serverData = null;
            var reader = new ReadableDataParser(cl);
            var writer = new WritableDataParser(cl);
            /** @type {ReadableDataParser} */
            var socketReader = null;
            /** @type {WritableDataParser} */
            var socketWriter = null;
            var encryptionStage = 0;
            var playState = false;
            var compression = -1;
            var loginStatus = null;
            var username;
            var userID;
            var state = 0;
            var emittedError = false;
            var verifyToken = null;

            var chiperClient;
            var dechiperClient;
            var chiperServer;
            var dechiperServer;

            async function pipeStreams() {
                var onTerminate = null;
                var terminated = false;
                function terminate(ex) {
                    if(terminated)
                        return;
                    terminated = true;
                    var err = ex || new Error("Invalid data from client/server");
                    try {cl.destroy(err);} catch(_) {}
                    try {socket.destroy(err);} catch(_) {}
                    if(chiperServer)
                        try {chiperServer.destroy(err);} catch(_) {}
                    if(chiperClient)
                        try {chiperClient.destroy(err);} catch(_) {}
                    if(dechiperServer)
                        try {dechiperServer.destroy(err);} catch(_) {}
                    if(dechiperClient)
                        try {dechiperClient.destroy(err);} catch(_) {}
                    if(onTerminate)
                        onTerminate(ex);
                    throw err;
                }

                cl.on('error', ex => terminate(ex));
                socket.on('error', ex => terminate(ex));
                if(chiperServer) 
                    chiperServer.on('error', ex => terminate(ex));
                if(chiperClient)
                    chiperClient.on('error', ex => terminate(ex));
                if(dechiperServer) 
                    dechiperServer.on('error', ex => terminate(ex));
                if(dechiperClient)
                    dechiperClient.on('error', ex => terminate(ex));
                
                function createInflateFromBuffer(buffer) {
                    var str = createReadableFromBuffer(buffer);
                    var inf = createInflate();
                    str.on('error', ex => { try {inf.destroy(ex); }catch(_){} });
                    inf.on('error', ex => { try {str.destroy(ex); }catch(_){} });
                    str.pipe(inf);
                    return inf;
                }

                async function readPacket(reader) {
                    var compressedLength = await reader.readVarInt();
                    var index = reader.index;

                    if(compressedLength > 2097151 || compressedLength < 1)
                        return terminate();
                    var packetLength = (compression >= 0) ? await reader.readVarInt() : 0;
                    var hasCompression = packetLength > 0;
                    if(!hasCompression)
                        packetLength = compressedLength;
                    if(packetLength > 2097151 || packetLength < 1)
                        return terminate();
                    var originalData = await reader.readBytes(compressedLength - (reader.index - index));
                    var readStream = new ReadableDataParser(hasCompression ? createInflateFromBuffer(originalData) : createReadableFromBuffer(originalData));  
                    readStream.stream.on('error', () => {}); //errors should be handled by the read operation.
                    return { packetLength, hasCompression, originalData, readStream }
                }

                async function processServer() {
                    if(!playState) {
                        while(!playState) {
                            //we must process the packets until we reach play state. from that moment we can just pipe the streams
                            //this must be done because of 2 things: 1. set compression 2. packet processing in processClient() is different when we are in state play
                            var { packetLength, hasCompression, originalData, readStream } = await readPacket(socketReader);
                            var packetID = await readStream.readVarInt();
                            var canCompress = compression >= 0;
                            if(packetID == 0x03) {
                                compression = await readStream.readVarInt();
                            } else if(packetID == 0x02) {
                                playState = true;
                            }
                            if(hasCompression) {
                                var buff1 = writer.createCheckpoint(5);
                                var buff2 = writer.createCheckpoint(5);
                                buff2.writeVarInt(packetLength);
                                buff1.writeVarInt(buff2.length + originalData.length);
                                buff1.appendPending();
                                buff2.appendPending();
                                writer.writeBytes(originalData);
                            } else if(canCompress) {
                                var buff = writer.createBuffer(6);
                                buff.writeVarInt(originalData.length + 1);
                                buff.writeByte(0);
                                buff.appendPending();                        
                                writer.writeBytes(originalData);
                            } else {
                                var buff = writer.createBuffer();
                                buff.writeVarInt(originalData.length);
                                buff.appendPending();
                                writer.writeBytes(originalData);
                            }
                        }

                        await writer.flush();
                        await socketReader.streamReady();
                        await writer.streamReady();
                    }

                    socketReader = null;
                    writer = null;
                    if(dechiperServer && chiperClient) {
                        dechiperServer.pipe(chiperClient);
                    } else if(dechiperServer) {
                        dechiperServer.pipe(cl);
                    } else if(chiperClient) {
                        socket.pipe(chiperClient);
                    } else {
                        socket.pipe(cl);
                    }

                    return new Promise(() => {});
                }
                
                async function processClient() {
                    while(1) {
                        var { packetLength, hasCompression, originalData, readStream } = await readPacket(reader);
                        var packetID = await readStream.readVarInt();
                        /** @type {WritableDataParser} */
                        var responseStream = null;
                        /** @type {WritableDataBuffer} */
                        var response = null;
                        var getResponseBytes = null;
                        var ended = false;
                        function createResponse() {
                            if(responseStream)
                                return;
                            var arr = createWritableToBuffer();
                            responseStream = new WritableDataParser(arr[0]);
                            response = responseStream.createCheckpoint(packetLength);
                            getResponseBytes = arr[1];
                            arr[0].on('error', ex => !ended && terminate(ex));
                            response.writeVarInt(packetID);
                        }
                        if(playState && packetID == 0x04) {
                            var command = await readStream.readString();
                            var timestamp = await readStream.readLong();
                            await readStream.readLong(); //salt
                            var arrlength = await readStream.readVarInt();
                            for(var i = 0; i < arrlength; i++) {
                                await readStream.readString(); //argument name
                                await readStream.readBytes(await readStream.readVarInt()); //byte array length + byte array
                            }
                            await readStream.readByte(); //signed preview
                            createResponse();
                            response.writeString(command);
                            response.writeLong(timestamp);
                            response.writeLong(0n);
                            response.writeVarInt(0);
                            response.writeByte(0);
                            response.writeByte(0);
                            response.writeByte(0);
                            response.push();
                        } else if(playState && packetID == 0x05) {
                            var message = await readStream.readString();
                            var timestamp = await readStream.readLong();
                            await readStream.readLong(); //salt
                            await readStream.readBytes(await readStream.readVarInt()); //signate length and signature
                            await readStream.readByte();  //signed preview
                            createResponse();
                            response.writeString(message);
                            response.writeLong(timestamp);
                            response.writeLong(0n);
                            response.writeVarInt(0);
                            response.writeByte(0);
                            response.writeByte(0);
                            response.writeByte(0);
                            response.push();
                        }
                        originalData = getResponseBytes ? await new Promise((resolve, reject) => {
                            (async () => {
                                await responseStream.flush();
                                await responseStream.streamReady();
                            })().then(() => {
                                responseStream.stream.once('error', ex => reject(ex));
                                responseStream.stream.once('finish', () => {
                                    ended = true;
                                    var bytes = getResponseBytes();
                                    hasCompression = false;
                                    if(compression >= 0 && bytes.length >= compression) {
                                        hasCompression = true;
                                        packetLength = bytes.length;
                                        deflate(bytes, (ex, res) => ex ? reject(ex) : resolve(res));
                                    } else 
                                        resolve(bytes);
                                });
                                responseStream.stream.end();
                            }).catch(ex => reject(ex));
                        }) : originalData;
                        if(hasCompression) {
                            var buff1 = socketWriter.createCheckpoint(5);
                            var buff2 = socketWriter.createCheckpoint(5);
                            buff2.writeVarInt(packetLength);
                            buff1.writeVarInt(buff2.length + originalData.length);
                            buff1.appendPending();
                            buff2.appendPending();
                            socketWriter.writeBytes(originalData);
                        } else if(compression >= 0) {
                            var buff = socketWriter.createBuffer(6);
                            buff.writeVarInt(originalData.length + 1);
                            buff.writeByte(0);
                            buff.appendPending();                        
                            socketWriter.writeBytes(originalData);
                        } else {
                            var buff = socketWriter.createBuffer();
                            buff.writeVarInt(originalData.length);
                            buff.appendPending();
                            socketWriter.writeBytes(originalData);
                        }
                        await socketWriter.flush();
                    }
                }

                return Promise.race([processClient(), processServer(), new Promise((_, rej) => onTerminate = rej)]).catch(ex => {
                    terminate(ex);
                    throw ex;
                });
            }

            function toUTF16Be(str) {
                str = String(str);
                var buff = Buffer.alloc(str.length * 2);
                for(var i = 0; i < str.length; i++) {
                    buff.writeUInt16BE(str.charCodeAt(i), i * 2);
                }
                return buff;
            }

            function fromUTF16Be(buff) {
                var str = '';
                for(var i = 0; i < buff.length; i += 2) {
                    str += String.fromCharCode(buff.readUInt16BE(i));
                }
                return str;
            }


            async function sendLegacyPing(pingData) {
                var versionName = String(pingData.version.name);
                var onlinePlayers = String(Number(pingData.players.online));
                var maxPlayers = String(Number(pingData.players.max));
                var del = String.fromCharCode(167);
                var motd = String(pingData.description.text).split('\0').join(' ').split(del).join(' ');
                var sendBuff = toUTF16Be(state == 4 ? motd + del + onlinePlayers + del + maxPlayers : del + '1\0' + '127\0' + versionName + '\0' + motd + '\0' + onlinePlayers + '\0' + maxPlayers);
                buff = writer.createCheckpoint(3 + sendBuff.length);
                buff.writeByte(0xFF);
                buff.writeShort(sendBuff.length / 2);
                buff.writeBytes(sendBuff);
                await buff.push();
                await writer.flush();
                await writer.streamReady();
                cl.end();
            }

            function createConnection() {
                return new Promise((resolve, reject) => {
                    var sock = net.connect({
                        host: serverInfo.host,
                        port: serverInfo.port
                    }, () => (async () => {
                        try {
                            socket = sock;
                            cl.serverSocket = socket;
                            cl.emit('server', socket);
                            socketReader = new ReadableDataParser(socket);
                            socketWriter = new WritableDataParser(socket);
                            var hostBuff = Buffer.from(serverInfo.displayHost, 'utf-8');
                            var buff1 = socketWriter.createCheckpoint(5);
                            var buff2 = socketWriter.createCheckpoint(10 + hostBuff.length);
                            buff2.writeVarInt(0);
                            buff2.writeVarInt(serverInfo.version);
                            buff2.writeVarInt(hostBuff.length);
                            buff2.writeBytes(hostBuff);
                            buff2.writeUnsignedShort(serverInfo.displayPort);
                            buff2.writeVarInt(state == 2 ? 2 : 1);
                            buff1.writeVarInt(buff2.length);
                            buff1.appendPending();
                            if(state == 2 || state == 4 || state == 5) buff2.appendPending() 
                            else await buff2.push();
                            var user;
                            if(state == 4 || state == 5) {
                                //legacy ping
                                var buff = socketWriter.createCheckpoint(2);
                                buff.writeVarInt(1);
                                buff.writeVarInt(0);
                                await buff.push();
                                
                                var length = await socketReader.readVarInt();
                                var index = socketReader.index;
                                var id = await socketReader.readVarInt();
                                if(length < 2 || id != 0) throw new RangeError("Invalid ID ping");
                                var pingData = JSON.parse(await socketReader.readString(32767));
                                if(index + length != socketReader.index) throw new RangeError("Invalid length");
                                await sendLegacyPing(pingData);
                                resolve(sock);
                                return;
                            } else if(state == 2) {
                                user = await serverInfo.getUser();
                                var userBuff = Buffer.from(user.username, 'utf-8');
                                var buff1 = socketWriter.createCheckpoint(5);
                                var buff2 = socketWriter.createCheckpoint(4 + userBuff.length);
                                buff2.writeVarInt(0);
                                buff2.writeVarInt(userBuff.length);
                                buff2.writeBytes(userBuff);
                                buff2.writeByte(0); //no secure chat system
                                var hex = null;
                                try {
                                    var uuid = '';
                                    if(user.uuid)
                                        uuid = uuidWithoutDashes(user.uuid);
                                    if(uuid == "00000000000000000000000000000000")
                                        uuid = '';
                                    if(uuid)
                                        hex = Buffer.from(uuid, 'hex');
                                } catch(ex) {
                                    hex = null;
                                }
                                if(hex && hex.length == 16) {
                                    buff2.writeByte(1);
                                    buff2.writeBytes(hex);
                                } else
                                    buff2.writeByte(0);
                                buff1.writeVarInt(buff2.length);
                                buff1.appendPending();
                                await buff2.push();
                            }

                            if(state == 1) {
                                resolve(sock);
                            }

                            while(1) {
                                await socketWriter.flush();
                                socketReader.canEnd = true;
                                var length = await socketReader.readVarInt();
                                socketReader.canEnd = false;
                                var index = socketReader.index;
                                if(length == null) return; //TODO: kick other connection??
                                var id = await socketReader.readVarInt();
                                if(state == 1) {
                                    if(length > 65535) throw new RangeError("Packet too big for status");
                                    if(id != 0x0 && id != 0x01) throw new TypeError("Unknown not supported ping ID: " + id);
                                    if(id == 0x01 && length != 9) throw new TypeError("Invalid length for ping ID 0x01");
                                    if(id == 0x0 && length < 2) throw new TypeError("Invalid length for ping id 0x0");
                                    var data = await socketReader.readBytes(length - (socketReader.index - index));
                                    var buff1 = writer.createCheckpoint(5);
                                    var buff2 = writer.createCheckpoint(4 + data.length);
                                    buff2.writeVarInt(id);
                                    buff2.writeBytes(data);
                                    buff1.writeVarInt(buff2.length);
                                    buff1.appendPending();
                                    await buff2.push();
                                    continue;
                                } else if(state != 2) {
                                    throw new Error("Unknown state: " + state);
                                }
                                //weird plugin requests/responses without encryption...
                                if(id == 0x04) {
                                    //forward plugin request to client
                                    if(length > 524288) throw new RangeError("Packet too big for plugin");
                                    var messageID = await socketReader.readVarInt();
                                    var name = await socketReader.readString(32767);
                                    if(socketReader.index - index > length) throw new Error("Unexpected eof in packet");
                                    var data = await socketReader.readBytes(length - (socketReader.index - index));
                                    var buff1 = writer.createCheckpoint(5);
                                    var buff2 = writer.createCheckpoint(5 + name.length + data.length);
                                    buff2.writeVarInt(0x04);
                                    buff2.writeVarInt(messageID);
                                    buff2.writeString(name);
                                    buff2.writeBytes(data);
                                    buff1.writeVarInt(buff2.length);
                                    buff1.appendPending();
                                    await buff2.push();
                                    
                                    //forward incomming plugin response to server
                                    reader.canEnd = true;
                                    var length2 = await reader.readVarInt();
                                    reader.canEnd = false;
                                    if(length2 < 1) throw new RangeError("EOF for plugin response");
                                    var index2 = reader.index;
                                    var id2 = await reader.readVarInt();
                                    if(id2 != 0x02) throw new RangeError("Expected a plugin response");
                                    var responseBytes = await reader.readBytes(length2 - (reader.index - index2));
                                    buff1 = socketWriter.createCheckpoint(5);
                                    buff2 = socketWriter.createCheckpoint(2 + responseBytes.length);
                                    buff2.writeVarInt(0x02);
                                    buff2.writeBytes(responseBytes);
                                    buff1.writeVarInt(buff2.length);
                                    buff1.appendPending();
                                    await buff2.push();
                                    continue;
                                }
                                if(id == 0x00 || id == 0x03 || id == 0x02) {
                                    //0x00: the client is disconnected/kicked
                                    //(0x03 || 0x02) its seems that we receive login success or compression. meaning that the server is cracked
                                    if(length > 65535) throw new TypeError("Packet too big");
                                    if(id != 0x00 && (user.crackedLogin && !(await user.crackedLogin()))) {
                                        try{socket.end()} catch(_){}
                                        var disconnectBuff = Buffer.from(JSON.stringify((await serverInfo.getDisconnectMessage('cracked-not-allowed')) || {text: 'Remote server is in offline mode, not allowed'}), 'utf-8');
                                        var buff1 = writer.createCheckpoint(5);
                                        var buff2 = writer.createCheckpoint(5 + disconnectBuff.length);
                                        buff2.writeVarInt(0);
                                        buff2.writeVarInt(disconnectBuff.length);
                                        buff2.writeBytes(disconnectBuff);
                                        buff1.writeVarInt(buff2.length);
                                        buff1.appendPending();
                                        await buff2.push();
                                        cl.end();
                                        return;
                                    }
                                    var buff1 = await writer.createCheckpoint(5);
                                    var buff2 = await writer.createCheckpoint(4 + length);
                                    buff2.writeVarInt(id);
                                    if(id == 0x03) {
                                        compression = socketReader.readVarInt();
                                        buff2.writeVarInt(compression);
                                    }
                                    buff2.writeBytes(await socketReader.readBytes(length - (socketReader.index - index)));
                                    buff1.writeVarInt(buff2.length);
                                    buff1.appendPending();
                                    await buff2.push();
                                    await writer.flush();
                                    await writer.streamReady();
                                    await reader.streamReady();
                                    playState = id == 0x02;
                                    if(id == 0x03 || id == 0x02) {
                                        await socketWriter.flush();
                                        await socketWriter.streamReady();
                                        await socketReader.streamReady();
                                        await pipeStreams();
                                        return;
                                    } else {
                                        try{socket.end();}catch(_){}
                                        try{cl.end();}catch(_){}
                                        return;   
                                    }
                                }
                                if(id != 0x01) throw new TypeError("Type must be 0x01, " + id);
                                var serverName = await socketReader.readString(20);
                                var pubKeyLen = await socketReader.readVarInt();
                                if(pubKeyLen > 256) throw new TypeError("Public key too long");
                                var pubKey = await socketReader.readBytes(pubKeyLen);
                                var verifyTokenLen = await socketReader.readVarInt();
                                if(verifyToken > 256) throw new TypeError("Too long verify token");
                                var verifyToken = await socketReader.readBytes(verifyTokenLen);
                                var sharedSecret = user.sharedSecret ? user.sharedSecret : await generateMCSharedSecret();
                                if(!(sharedSecret instanceof Buffer)) throw new Error("Shared secret must be a buffer");
                                var serverID = mcHexDigest(crypto.createHash('sha1').update(Buffer.from(serverName, 'utf-8')).update(sharedSecret).update(pubKey).digest());
                                var succ;
                                var hasCredentials = false;
                                if(user.joinServer) {
                                    hasCredentials = true;
                                    succ = await user.joinServer(serverID, { serverName, sharedSecret, pubKey });
                                }
                                if(!succ && succ !== false && user.getCredentials) {
                                    var credentials = await user.getCredentials(serverID, { serverName, sharedSecret, pubKey });
                                    succ = await new Promise((resolve, reject) => {
                                        if(!credentials) {
                                            resolve(false);
                                            return;
                                        }
                                        hasCredentials = true;
                                        var body = Buffer.from(JSON.stringify({
                                            accessToken: credentials.accessToken,
                                            selectedProfile: uuidWithoutDashes(credentials.uuid),
                                            serverId: serverID
                                        }), 'utf-8');
                                        var req = https.request({
                                            method: "POST",
                                            host: 'sessionserver.mojang.com',
                                            port: 443,
                                            path: '/session/minecraft/join',
                                            headers: {
                                                'Content-Type': 'application/json;utf-8',
                                                'Content-Length': body.length
                                            }
                                        }, res => {
                                            try {
                                                res.on('error', ex => reject(ex));
                                                res.resume();
                                                resolve(res.statusCode == 204 || res.statusCode == 200);
                                            } catch(ex) {
                                                reject(ex);
                                            }
                                        }).on('error', ex => reject(ex));
                                        req.write(body, err => err ? reject(err) : void 0);
                                        req.end();
                                    });
                                }
                                if(!succ) {
                                    try{socket.end()} catch(_){}
                                    var disconnectBuff = Buffer.from(JSON.stringify((await serverInfo.getDisconnectMessage(hasCredentials ? 'login-failed' : 'no-credentials')) || {text: 'Failed to sign in to remote server'}), 'utf-8');
                                    var buff1 = writer.createCheckpoint(5);
                                    var buff2 = writer.createCheckpoint(5 + disconnectBuff.length);
                                    buff2.writeVarInt(0);
                                    buff2.writeVarInt(disconnectBuff.length);
                                    buff2.writeBytes(disconnectBuff);
                                    buff1.writeVarInt(buff2.length);
                                    buff1.appendPending();
                                    await buff2.push();
                                    await writer.flush();
                                    await reader.streamReady();
                                    await writer.streamReady();
                                    await socketWriter.flush();
                                    await socketReader.streamReady();
                                    await socketWriter.streamReady();
                                    cl.end();
                                    return;
                                }
                                var encryptKey = crypto.createPublicKey({
                                    key: pubKey,
                                    format: 'der',
                                    type: 'spki'
                                })
                                var encryptedSecret = crypto.publicEncrypt({
                                    key: encryptKey,
                                    padding: crypto.constants.RSA_PKCS1_PADDING
                                }, sharedSecret);
                                var encryptedVerifyToken = crypto.publicEncrypt({
                                    key: encryptKey,
                                    padding: crypto.constants.RSA_PKCS1_PADDING
                                }, verifyToken);
                                var buff1 = socketWriter.createCheckpoint(5);
                                var buff2 = socketWriter.createCheckpoint(10 + encryptedSecret.length + encryptedVerifyToken.length);
                                buff2.writeVarInt(0x01);
                                buff2.writeVarInt(encryptedSecret.length);
                                buff2.writeBytes(encryptedSecret);
                                buff2.writeVarInt(0x01);
                                buff2.writeVarInt(encryptedVerifyToken.length);
                                buff2.writeBytes(encryptedVerifyToken);
                                buff1.writeVarInt(buff2.length);
                                buff1.appendPending();
                                await buff2.push();
                                await writer.flush();
                                await reader.streamReady();
                                await writer.streamReady();
                                await socketWriter.flush();
                                await socketReader.streamReady();
                                await socketWriter.streamReady();
                                socketReader = null;
                                socketWriter = null;
                                chiperServer = createMCChiperStream(sharedSecret);
                                dechiperServer = createMCDechiperStream(sharedSecret);
                                socket.emit('encryption', { chiper: chiperServer, dechiper: dechiperServer });
                                socket.pipe(dechiperServer);
                                chiperServer.pipe(socket);
                                socketReader = new ReadableDataParser(dechiperServer);
                                socketWriter = new WritableDataParser(chiperServer);
                                await pipeStreams();
                                return;
                            }
                        } catch(ex) {
                            if(!emittedError) try{proxyServer.emit('client-error', ex, cl);}catch(_){}
                            emittedError = true;
                            if(socket) try{socket.destroy(ex)} catch(_){}
                            try{cl.destroy(ex)} catch(_) {}
                            return false;
                        }
                    })().finally(val => {if(val === false) return; try {cl.end()} catch(ex) {}}));
                    sock.on('error', async ex => {
                        try{sock.end()} catch(_){}
                        if(reader && writer) {
                            try {
                                var disconnectBuff = Buffer.from(JSON.stringify((await serverInfo.getDisconnectMessage('connection-failed', ex)) || {text: 'Failed to connect to remote server: ' + ex.message}), 'utf-8');
                                var buff1 = writer.createCheckpoint(5);
                                var buff2 = writer.createCheckpoint(5 + disconnectBuff.length);
                                buff2.writeVarInt(0);
                                buff2.writeVarInt(disconnectBuff.length);
                                buff2.writeBytes(disconnectBuff);
                                buff1.writeVarInt(buff2.length);
                                buff1.appendPending();
                                await buff2.push();
                                await writer.flush();
                                await reader.streamReady();
                                await writer.streamReady();
                                cl.end();
                            } catch(ex) {}
                        }
                        reject(ex); //double rejecting does nothing
                        try{cl.destroy(ex)} catch(_){}
                    });
                });
            }
            
            while(1) {
                await writer.flush();
                reader.canEnd = true;
                var length = await reader.readVarInt(state == 0);
                reader.canEnd = false;
                if(length == null) break;
                var index = reader.index;
                //length == 254, var int for 0xFE 0x01
                var probLegacy = state == 0 && ((length instanceof Array && length.length == 1 && length[0] == 0xFE) || length === 254)
                var id = null;

                if(probLegacy) {
                    cl.allowHalfOpen = true;
                    //legacy ping
                    if(length === 254) {
                        reader.canEnd = true;
                        id = await reader.readVarInt();
                        reader.canEnd = false;
                        if(id == 122) {
                            var nbyte = await reader.readByte();
                            if(nbyte != 0x0B) throw new TypeError("Invalid legacy message " + nbyte);
                            await reader.readBytes(22);
                            var rlen = await reader.readShort();
                            if(rlen < 0 || rlen > 4096) throw new RangeError("Too big legacy data");
                            var version = await reader.readByte();
                            var hostlen = await reader.readShort();
                            if(hostlen * 2 != rlen - 7) throw new RangeError("Invalig host len");
                            var host = fromUTF16Be(await reader.readBytes(hostlen * 2));
                            var port = await reader.readInt();
                            serverInfo = await getServer({state: 'status', legacy: true, host, port, version, remoteClient: cl, proxyServer});
                            state = 5;
                        } else if(id == null) {
                            serverInfo = await getServer({state: 'status', legacy: true, host: '', port: 0, version: 0, remoteClient: cl, proxyServer});
                            state = 5;
                        } else {
                            probLegacy = false;
                        }
                        
                    } else if(length instanceof Array) {
                        serverInfo = await getServer({state: 'status', legacy: true, host: '', port: 0, version: 0, remoteClient: cl, proxyServer});
                        state = 4;
                    } else {
                        throw new Error("Unknown legacy ID: " + id);
                    }
                    if(probLegacy) {
                        if(serverInfo.status) {
                            await sendLegacyPing(serverInfo.status);
                        } else {
                            if(!serverInfo.displayHost) serverInfo.displayHost = serverInfo.host;
                            if(!serverInfo.version) serverInfo.version = version;
                            if(!serverInfo.displayPort) serverInfo.displayPort = serverInfo.port;
                            await createConnection();
                        }
                        return;
                    }
                }
                cl.allowHalfOpen = false;
                if(length < 1) throw new Error("length may not be lower then 1");
                if(id == null) id = await reader.readVarInt();

                if(state == 0) {
                    if(id != 0) throw new Error("Expected handshake packet");
                    var version = await reader.readVarInt();
                    var host = await reader.readString(255);
                    var port = await reader.readUnsignedShort();
                    var nextState = await reader.readVarInt();
                    if(index + length != reader.index) throw new RangeError("Unexpected EOF in packet");
                    if(nextState == 1) {
                        serverInfo = await getServer({state: 'status', legacy: false, host, port, version, remoteClient: cl, proxyServer});
                        if(!serverInfo.displayHost) serverInfo.displayHost = serverInfo.host;
                        if(!serverInfo.version) serverInfo.version = version;
                        if(!serverInfo.displayPort) serverInfo.displayPort = serverInfo.port;
                        if(!serverInfo) {
                            cl.end();
                            return;
                        }
                        if(serverInfo.status) {
                            state = 3;
                        } else {
                            state = 1;
                            await createConnection();
                        }
                    } else if(nextState == 2) {
                        serverData = {host, port, version};
                        state = 2;
                        encryptionStage = 1;
                    } else throw new Error("Unknown state: " + nextState);
                    continue;
                } else if(state == 3) {
                    if(id == 0) {
                        if(index + length != reader.index) throw new RangeError("Unexpected EOF in packet");
                        var str = Buffer.from(JSON.stringify(serverInfo.status), 'utf-8');
                        var buff1 = writer.createCheckpoint(5);
                        var buff2 = writer.createCheckpoint(10 + str.length);
                        buff2.writeVarInt(0);
                        buff2.writeVarInt(str.length);
                        buff2.writeBytes(str);
                        buff1.writeVarInt(buff2.length);
                        buff1.appendPending();
                        await buff2.push();
                    } else if(id == 1) {
                        var val = reader.readLong();
                        if(index + length != reader.index) throw new RangeError("Unexpected EOF in packet");
                        var buff = writer.createCheckpoint(10);
                        buff.writeVarInt(9);
                        buff.writeVarInt(1);
                        buff.writeLong(val);
                        await buff.push();
                    } else {
                        throw new Error("Unknown packet ID (state = status): " + id);
                    }
                    continue;
                } else if(state == 1) {
                    if(length > 65535) throw new RangeError("Packet too big for ping");
                    if(id != 0x0 && id != 0x01) throw new TypeError("Unknown not supported ping ID: " + id);
                    if(id == 0x01 && length != 9) throw new TypeError("Invalid length for ping ID 0x01");
                    if(id == 0x00 && length != 1) throw new TypeError("Invalid length for ping ID 0x0");
                    var data = await reader.readBytes(length - (reader.index - index));
                    var buff1 = socketWriter.createCheckpoint(5);
                    var buff2 = socketWriter.createCheckpoint(4 + data.length);
                    buff2.writeVarInt(id);
                    buff2.writeBytes(data);
                    buff1.writeVarInt(buff2.length);
                    buff1.appendPending();
                    await buff2.push();
                    continue;
                } else if(state != 2) {
                    throw new Error("Unknown state: " + state);
                }
                if(encryptionStage == 1) {
                    if(id != 0) throw new TypeError("Invalid ID for login start");
                    username = await reader.readString(16);
                    await reader.readBytes(length - (reader.index - index));
                    if(reader.index != index + length) throw new TypeError("Invalide EOF of packet");
                    serverInfo = await getServer({state: 'login', legacy: false, host: serverData.host, port: serverData.port, version: serverData.version, username, remoteClient: cl, proxyServer});
                    if(!serverInfo.displayHost) serverInfo.displayHost = serverInfo.host;
                    if(!serverInfo.version) serverInfo.version = version;
                    if(!serverInfo.displayPort) serverInfo.displayPort = serverInfo.port;
                    if(!serverInfo.getDisconnectMessage) serverInfo.getDisconnectMessage = () => null;
                    if(serverInfo.cracked) {
                        encryptionStage = 0;
                        return await createConnection();
                    }
                    var { publicKey } = await keyPromise;
                    var buff1 = writer.createCheckpoint(5);
                    var buff2 = writer.createCheckpoint(20 + publicKey.length);
                    verifyToken = await new Promise((resolve, reject) => {
                        crypto.randomFill(Buffer.alloc(4), (err, buf) => {
                            if(err) reject(err);
                            else resolve(buf);
                        });
                    });


                    buff2.writeVarInt(1);
                    buff2.writeString('');
                    buff2.writeVarInt(publicKey.length);
                    buff2.writeBytes(publicKey);
                    buff2.writeVarInt(verifyToken.length);
                    buff2.writeBytes(verifyToken);
                    buff1.writeVarInt(buff2.length);
                    buff1.appendPending();
                    await buff2.push();
                    encryptionStage = 2;
                    continue;
                } else if(encryptionStage == 2) {
                    if(id == 0x02) {
                        //plugin response???
                        //we do not even have encryption. ignore this
                        await reader.readBytes(length - (reader.index - index));
                        continue;
                    }
                    if(id != 0x01) throw new TypeError("Invalid ID for encryption response: " + id + " length: " + length);
                    var sharedSecretLen = await reader.readVarInt();
                    if(sharedSecretLen < 0 || sharedSecretLen > 256) throw new RangeError("Too big shared secret");
                    var encryptedSharedSecret = await reader.readBytes(sharedSecretLen);
                    var hasVerifyToken = await reader.readByte();
                    var { publicKey, privateKey } = await keyPromise;
                    var decryptKey = crypto.createPrivateKey({
                        key: privateKey,
                        format: 'der',
                        type: 'pkcs8'
                    });
                    if(hasVerifyToken > 0) {
                        var verifyTokenLen = await reader.readVarInt();
                        if(verifyTokenLen < 0 || verifyTokenLen > 256) throw new TypeError("Too big verify token");
                        var clientVerifyToken = await reader.readBytes(verifyTokenLen);
                        var toVerify = crypto.privateDecrypt({
                            key: decryptKey,
                            padding: crypto.constants.RSA_PKCS1_PADDING
                        }, clientVerifyToken);
                        if(toVerify.length != verifyToken.length || !crypto.timingSafeEqual(toVerify, verifyToken)) throw new TypeError("verify token does not match");
                    }
                    await reader.readBytes(length - (reader.index - index));
                    var sharedSecret = crypto.privateDecrypt({
                        key: decryptKey,
                        padding: crypto.constants.RSA_PKCS1_PADDING
                    }, encryptedSharedSecret);
                    await writer.flush();
                    await reader.streamReady();
                    await writer.streamReady();
                    chiperClient = createMCChiperStream(sharedSecret);
                    dechiperClient = createMCDechiperStream(sharedSecret);
                    cl.emit('encryption', { chiper: chiperClient, dechiper: dechiperClient });
                    chiperClient.on('error', ex => {
                        try{cl.destroy(ex)} catch(_){}
                        try{dechiperClient.destroy(ex)} catch(_){}
                    })
                    dechiperClient.on('error', ex => {
                        try{cl.destroy(ex)} catch(_){}
                        try{chiperClient.destroy(ex)} catch(_){}
                    });
                    cl.on('error', ex => {
                        try{chiperClient.destroy(ex)} catch(_){}
                        try{dechiperClient.destroy(ex)} catch(_){}
                    });
                    cl.pipe(dechiperClient);
                    chiperClient.pipe(cl);
                    reader = new ReadableDataParser(dechiperClient);
                    writer = new WritableDataParser(chiperClient);
                    cl.resume();
                    var serverID = mcHexDigest(crypto.createHash('sha1').update(Buffer.from('', 'utf-8')).update(sharedSecret).update(publicKey).digest());
                    var success;
                    var disconnectMessage = null;
                    try {
                        success = await new Promise((resolve, reject) => {
                            https.request({
                                method: "GET",
                                host: "sessionserver.mojang.com",
                                port: 443,
                                path: '/session/minecraft/hasJoined?username=' + encodeURIComponent(username) + '&serverId=' + encodeURIComponent(serverID)
                            }, res => {
                                try {
                                    res.on('error', ex => reject(ex));
                                    if(res.statusCode != 200) {
                                        resolve(false);
                                        res.destroy();
                                    }
                                    var len = 0;
                                    var data = [];
                                    res.on('data', d => {
                                        len += d.length;
                                        if(len > 65535) {
                                            res.destroy(new Error("Cannot read more then 65535 bytes of data from response."));
                                            return;
                                        }
                                        data.push(d);
                                    });
                                    res.on('end', async () => {
                                        try {
                                            var json = JSON.parse(Buffer.concat(data).toString('utf-8'));
                                            if(typeof json != 'object' || json.name !== username || !json.id || typeof json.id != 'string') {
                                                resolve(false);
                                                return;
                                            }
                                            var res = true;
                                            //add dashes
                                            var id = uuidWithDashes(json.id);
                                            userID = id;
                                            if(serverInfo.verifyLogin) res = await serverInfo.verifyLogin(id, json);
                                            if(res === false) {
                                                disconnectMessage = await serverInfo.getDisconnectMessage('user-denied') || {text: "You are not allowed to login"};
                                                resolve(false);
                                            }
                                            else resolve(true);
                                        } catch(ex) {
                                            reject(ex);
                                        } 
                                    });
                                } catch(ex) {
                                    reject(ex);
                                }
                            }).on('error', ex => reject(ex)).end();
                        });
                    } catch(ex) {
                        if(!emittedError) try{proxyServer.emit('client-error', ex, cl);}catch(_){}
                        emittedError = true;
                        if(socket) try{socket.destroy(ex)} catch(_){}
                        try{cl.destroy(ex)} catch(_) {}
                        return;
                    }
                    if(!success) {
                        if(!disconnectMessage) {
                            disconnectMessage = (await serverInfo.getDisconnectMessage('auth-failed')) || {text: "Cannot verify user"};
                        }
                        //disconnect is encrypted
                        var disconnectBuff = Buffer.from(JSON.stringify(disconnectMessage), 'utf-8');
                        var buff1 = writer.createCheckpoint(5);
                        var buff2 = writer.createCheckpoint(5 + disconnectBuff.length);
                        buff2.writeVarInt(0);
                        buff2.writeVarInt(disconnectBuff.length);
                        buff2.writeBytes(disconnectBuff);
                        buff1.writeVarInt(buff2.length);
                        buff1.appendPending();
                        await buff2.push();
                        await writer.flush();
                        await reader.streamReady();
                        await writer.streamReady();
                        cl.end();
                        return;
                    }
                    return await createConnection();
                } else {
                    throw new Error("Unknown encryption stage: " + encryptionStage);
                }
            }
        } catch(ex) {
            if(!emittedError) try{proxyServer.emit('client-error', ex, cl);}catch(_){}
            emittedError = true;
            if(socket) try{socket.destroy(ex)} catch(_){}
            try{cl.destroy(ex)} catch(_) {}
        }
    });
    proxyServer.privateKey = keyPromise.then(x => x.privateKey);
    proxyServer.publicKey = keyPromise.then(x => x.publicKey);
    return proxyServer;
}

/**
 * Get status of the destination server
 * @param {{protocolVersion?: string, host: string, port: number, displayHost?: string, displayPort?: number}} param0 Options for the destination server
 * @returns {Promise<{data: object, ping: number}>} A promise that resolves with an object containing the JSON response data and the MS ping delay or rejects with an Error 
 */
async function getServerStatus({ protocolVersion, host, port, displayHost, displayPort }) {
    if(!displayHost) displayHost = host;
    if(!displayPort) displayPort = port;
    if(!protocolVersion) protocolVersion = 65535;
    var socket = await new Promise((resolve, reject) => {
        var errListener = ex => reject(ex);
        var sock = net.connect({
            host,
            port
        }, () => {
            sock.removeListener('error', errListener);
            resolve(sock);
        }).once('error', errListener);
    });
    var data;
    var ping;
    try {
        var writer = new WritableDataParser(socket);
        var reader = new ReadableDataParser(socket);

        var hostBuff = Buffer.from(displayHost, 'utf-8');
        var buff1 = writer.createCheckpoint(5);
        var buff2 = writer.createCheckpoint(20 + hostBuff.length);
        buff2.writeVarInt(0);
        buff2.writeVarInt(protocolVersion);
        buff2.writeVarInt(hostBuff.length);
        buff2.writeBytes(hostBuff);
        buff2.writeUnsignedShort(port);
        buff2.writeVarInt(1);
        buff1.writeVarInt(buff2.length);
        buff2.writeVarInt(1);
        buff2.writeVarInt(0);
        buff1.appendPending();
        await buff2.push(); //one write call, so one TCP packet for 2 MC packets.

        var length = await reader.readVarInt();
        var index = reader.index;
        if(length < 1 || length > 65535) throw new Error("Too much data");
        var id = await reader.readVarInt();
        if(id != 0) throw new Error("Invalid ID for status response");
        data = JSON.parse(await reader.readString(32767));
        if(reader.index !== index + length) throw new Error("Length does not match with reader index");

        buff1 = writer.createCheckpoint(10);
        buff1.writeVarInt(9);
        buff1.writeVarInt(1);
        var now = BigInt(Date.now());
        buff1.writeLong(now);
        await buff1.push();

        var length = await reader.readVarInt();
        if(length != 9) throw new Error("Unexpected length for pong");
        var id = await reader.readVarInt();
        if(id != 1) throw new Error("Invalid ID for pong");
        var val = await reader.readLong();
        if(val != now) throw new Error("Invalid pong response (does not match)");
        ping = Date.now() - Number(now);

        await writer.flush();
        await reader.streamReady();
        await writer.streamReady();
        
    } catch(ex) {
        try {socket.destroy(ex)}catch(_){}
        throw ex;
    }
    socket.on('error', () => {});
    try{socket.destroy();}catch(_){}
    return { data, ping: ping };
}

/**
 * Get the Public key (and a function to sign server join hashes) of the destination server
 * @param {{protocolVersion?: string, host: string, port: number, displayHost?: string, displayPort?: number, username?: string}} param0 Options for the destination server
 * @returns {Promise<{status: 'disconnect' | 'cracked' | 'online', message?: object, serverName?: string, publicKey?: Buffer, createHash?: (sharedSecret: Buffer) => string}>} A Promise that resolves with the response status. 
 *          if online, then you get the serverName (max 20 bytes), the public key as a Buffer in DER format and a function that can create a MC hex digest for signing in if you give the missing SharedSecret. It rejects with an Error if the connection failed.
 * Some servers reject the connection if the protocolVersion is not correct. You can get the protocolVersion with getServerStatus and use (await getServerStatus(...)).data.version.protocol for protocolVersion.
 */
async function getServerPublicKey({ protocolVersion, host, port, displayHost, displayPort, username }) {
    if(!displayHost) displayHost = host;
    if(!displayPort) displayPort = port;
    if(!protocolVersion) protocolVersion = 65535;
    if(!username) username = '_';

    var socket = await new Promise((resolve, reject) => {
        var errListener = ex => reject(ex);
        var sock = net.connect({
            host,
            port
        }, () => {
            sock.removeListener('error', errListener);
            resolve(sock);
        }).once('error', errListener);
    });

    var response = null;

    try {
        var writer = new WritableDataParser(socket);
        var reader = new ReadableDataParser(socket);

        var hostBuff = Buffer.from(displayHost, 'utf-8');
        var buff1 = writer.createCheckpoint(5);
        var buff2 = writer.createCheckpoint(20 + hostBuff.length);
        buff2.writeVarInt(0);
        buff2.writeVarInt(protocolVersion);
        buff2.writeVarInt(hostBuff.length);
        buff2.writeBytes(hostBuff);
        buff2.writeUnsignedShort(port);
        buff2.writeVarInt(2);
        buff1.writeVarInt(buff2.length);
        buff1.appendPending();
        buff2.appendPending();

        var usernameBuff = Buffer.from(username, 'utf-8');

        buff1 = writer.createCheckpoint(5);
        buff2 = writer.createCheckpoint(10 + usernameBuff.length);
        buff2.writeVarInt(0);
        buff2.writeVarInt(usernameBuff.length);
        buff2.writeBytes(usernameBuff);
        buff1.writeVarInt(buff2.length);
        buff1.appendPending();
        await buff2.push(); //one write call, so one TCP packet for 2 MC packets.

        var id, length, index;

        while(1) {
            length = await reader.readVarInt();
            if(length < 1 || length > 65535) throw new Error("Too much data");
            index = reader.index;
            id = await reader.readVarInt();
            switch(id) {
            case 0:
                response = {status: 'disconnect', message: JSON.parse(await reader.readString(32767))};
                if(reader.index !== index + length) throw new Error("index does not match with length for disconnect");
                break;
            case 1:
                break;
            case 2: //Login success
            case 3: //set compression
                response = {status: 'cracked'};
                break;
            case 4: //Plugin request, we always response that we do not support the addition (same as te Notchian client)
                var messageID = await reader.readVarInt();
                await reader.readBytes(length - (reader.index - index));
                buff1 = writer.createCheckpoint(5);
                buff2 = writer.createCheckpoint(10);
                buff2.writeVarInt(2);
                buff2.writeVarInt(messageID);
                buff2.writeByte(0); //success = false
                buff1.writeVarInt(buff2.length);
                buff1.appendPending();
                await buff2.push();
                continue;
            default:
                throw new Error("Unknown packet ID in login: " + id);
            }
            break;
        }
        if(id == 1) {
            var serverName = await reader.readString(20);
            var pubKeyLength = await reader.readVarInt();
            if(pubKeyLength > 256) throw new Error("Too long public key");
            var publicKey = await reader.readBytes(pubKeyLength);
            var verifyTokenLength = await reader.readVarInt();
            if(verifyTokenLength > 256) throw new Error("Too long verify token");
            var verifyToken = await reader.readBytes(verifyTokenLength);
            if(reader.index !== index + length) throw new Error("index does not match with length for encryption request");
            var serverNameBuff = Buffer.from(serverName, 'utf-8');
            response = {status: 'online', publicKey, verifyToken, serverName, createHash(sharedSecret) {
                return mcHexDigest(crypto.createHash('sha1').update(serverNameBuff).update(sharedSecret).update(publicKey).digest());
            }};
        }
        await writer.flush();
        await reader.streamReady();
        await writer.streamReady();
        if(!response) throw new Error("No response");

    } catch(ex) {
        try {socket.destroy(ex)}catch(_){}
        throw ex;
    }
    socket.on('error', () => {});
    try{socket.destroy();}catch(_){}
    return response;
}

/**
 * Resolve SRV records that points to the real address of a server.
 * @param {String} host the host to resolve 
 * @returns {Promise<{name: string, port: number}>} a promise that resolves with the original host (and port is null) or a new name (and port is the port in the SRV record).
 */
function resolveMCSrvRecord(host) {
    return new Promise(resolve => {
        dns.resolveSrv('_minecraft._tcp.' + host, (err, addr) => {
            if(addr) addr = addr[0];
            if(err || !addr || !addr.name) resolve({name: host, port: null});
            else resolve({name: addr.name, port: addr.port});
        })
    });
}

/**
 * Convert chat objects (from disconnect or server ping) to a string.
 * @param {object} chat The chat object to conver  
 * @returns {string} A string with all the formatting removed.
 */
function chatObjectToString(chat) {
    if(typeof chat == 'object') {
        var txt = String(chat.text || '');
        if(typeof chat.extra == 'object' && chat.extra && chat.extra instanceof Array) {
            for(var item of chat.extra) {
                txt += chatObjectToString(item);
            }
        }
        return txt;
    } else return String(chat);
}

/**
 * Parse a motd chat object to an array of string. each item in the array is a line for multiplayer.
 * It always returns an array with 2 items (because Motd can have 2 lines). One of these lines can be empty and none of these lines is longer then 45 characters.
 * @param {object} chat The chat object from server ping to convert. It is located at the 'description' property from the status object returned by server ping. 
 * @returns {[string, string]} An array with 2 items, for each motd line.
 */
function parsePingMotdObject(chat) {
    var totalMotd = chatObjectToString(chat);
    var splitIndex = totalMotd.indexOf('\n');

    if(splitIndex < 0 || splitIndex > 45) splitIndex = 45;
    return [totalMotd.substr(0, splitIndex), totalMotd.substr(splitIndex, 45).split('\n')[0]];

}

module.exports = { 
    //Basics
    createProxyServer, 
    uuidWithDashes, 
    uuidWithoutDashes,
    getServerStatus, 
    resolveMCSrvRecord,
    chatObjectToString,
    parsePingMotdObject,
    
    //Advanced
    getServerPublicKey, 
    generateMCSharedSecret, 
    mcHexDigest, 

    //Own implementation
    BaseDataParser, 
    ReadableDataParser, 
    WritableDataParser, 
    WritableDataBuffer,
    createMCChiperStream,
    createMCDechiperStream
};

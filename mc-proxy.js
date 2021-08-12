const { Buffer } = require('buffer');
const net = require('net');
const crypto = require('crypto');
const https = require('https');
const dns = require('dns');
const { Duplex } = require('stream');

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
        });
    }

    streamReady() {
        if(this.error) return Promise.reject(this.error);
        return this.waitlist;
    }

    addWaitlist(promise) {
        var canEnd = this.canEnd;
        this.waitlist = this.streamReady().then(() => this.streamPromise(typeof promise == 'function' ? promise() : promise, canEnd));
        return this.waitlist;
    }
}

class ReadableDataParser extends BaseDataParser {
    /**
     * The stream
     * @param {Readable} stream 
     */
    constructor(stream) {
        super(stream);
        this.index = 0;
        
    }
    

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
                if(this.hasEnded) {
                    if(canEnd) return null;
                    throw new Error("Read while stream has ended");
                }
                var nbytes = this.stream.read(size - (bytes ? bytes.length : 0));
                if(!nbytes && !firstTry) {
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
     * @returns {number}
     */
    readByte() {
        return this.readBytes(1).then(buff => buff ? buff[0] : null);
    }

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

    readUnsignedShort() {
        return this.readBytes(2).then(buff => buff ? buff.readUInt16BE(0) : null);
    }

    readShort() {
        return this.readBytes(2).then(buff => buff ? buff.readInt16BE(0) : null);
    }

    readInt() {
        return this.readBytes(4).then(buff => buff ? buff.readInt32BE(0) : null);
    }

    readLong() {
        return this.readBytes(8).then(buff => buff ? buff.readBigInt64BE(0) : null);
    }

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

    toBuffer() {
        var fixed = Buffer.alloc(this.length);
        this.buffer.copy(fixed, 0, 0, this.length);
        return fixed;
    }

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

    writeByte(value, index) {
        if(index == null) index = this.length;
        this.resizeBuffer(index + 1);
        this.buffer[index] = value;
        return { index, length: 1 };
    }

    writeBytes(buffer, index) {
        if(!(buffer instanceof Buffer)) buffer = Buffer.from(buffer);
        if(buffer.length < 1) return { index, length: 0 }
        if(index == null) index = this.length;
        this.resizeBuffer(index + buffer.length);
        buffer.copy(this.buffer, index, 0, buffer.length);
        return { index, length: buffer.length }
    }

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
     * Push the buffer to the parser
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
     * Append the buffer to the internal buffer of the parser (for a later write call)
     *@param {WritableDataParser} parser the parser to append internal buffer, null if default (the one that created this parser) 
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

class WritableDataParser extends BaseDataParser {
    /**
     * The stream
     * @param {Writable} stream 
     */
    constructor(stream) {
        super(stream);
        this.pendingWriteBuffer = Buffer.alloc(0);
    }

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

    flush() {
        return this.writeBytes(Buffer.alloc(0));
    }

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
    
    createBuffer(size) {
        return new WritableDataBuffer(size, this, false);
    }

    createCheckpoint(size) {
        return new WritableDataBuffer(size, this, true);
    }
}

function uuidWithDashes(id) {
    return [.../([a-z0-9]{8})\-?([a-z0-9]{4})\-?([a-z0-9]{4})\-?([a-z0-9]{4})\-?([a-z0-9]{12})/.exec(id)].slice(1).join('-')
}

function uuidWithoutDashes(id) {
    return [.../([a-z0-9]{8})\-?([a-z0-9]{4})\-?([a-z0-9]{4})\-?([a-z0-9]{4})\-?([a-z0-9]{12})/.exec(id)].slice(1).join('')
}

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

function generateMCSharedSecret() {
    return new Promise((resolve, reject) => {
        crypto.randomFill(Buffer.alloc(16), (err, buff) => {
            if(err) reject(err);
            else resolve(buff);
        });
    });
}

var supportsMCChiper = crypto.getCiphers().includes('aes-128-cfb8');
function createMCChiperStream(sharedSecret) {
    if(supportsMCChiper) {
        return crypto.createCipheriv('aes-128-cfb8', sharedSecret, sharedSecret);
    } else {
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

function createMCDechiperStream(sharedSecret) {
    if( supportsMCChiper) {
        return crypto.createDecipheriv('aes-128-cfb8', sharedSecret, sharedSecret);
    } else {
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
            var compression = false;
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

            function pipeStreams() {
                if(chiperClient && chiperServer) {
                    dechiperClient.pipe(chiperServer);
                    dechiperServer.pipe(chiperClient);
                } else if(chiperClient && !chiperServer) {
                    dechiperClient.pipe(socket);
                    socket.pipe(chiperClient);
                } else if(!chiperClient && chiperServer) {
                    cl.pipe(chiperServer);
                    dechiperServer.pipe(cl);
                } else {
                    cl.pipe(socket);
                    socket.pipe(cl);
                }
                if(chiperClient) chiperClient.resume();
                if(dechiperClient) dechiperClient.resume();
                if(chiperServer) chiperServer.resume();
                if(dechiperServer) dechiperServer.resume();
                cl.resume();
                socket.resume();
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
                                if(id == 0x04) {
                                    if(length > 524288) throw new RangeError("Packet too big for plugin");
                                    var messageID = await socketReader.readVarInt();
                                    await socketReader.readString(32767);
                                    if(reader.index - index > length) throw new Error("Unexpected eof in packet");
                                    await socketReader.readBytes(length - (reader.index - index));
                                    var buff1 = writer.createCheckpoint(5);
                                    var buff2 = writer.createCheckpoint(5);
                                    buff2.writeVarInt(0x02);
                                    buff2.writeVarInt(messageID);
                                    buff2.writeByte(0x0);
                                    buff1.writeVarInt(buff2.length);
                                    buff1.appendPending();
                                    await buff2.push();
                                    continue;
                                }
                                if(id == 0x00 || id == 0x03 || id == 0x02) {
                                    if(length > 65535) throw new TypeError("Packet too big");
                                    if(user.crackedLogin && !(await user.crackedLogin())) {
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
                                    buff2.writeBytes(await socketReader.readBytes(length - (socketReader.index - index)));
                                    buff1.writeVarInt(buff2.length);
                                    buff1.appendPending();
                                    await buff2.push();
                                    await writer.flush();
                                    await writer.streamReady();
                                    await reader.streamReady();
                                    if(id == 0x03 || id == 0x02) {
                                        await socketWriter.flush();
                                        await socketWriter.streamReady();
                                        await socketReader.streamReady();
                                        writer = null;
                                        reader = null;
                                        socketWriter = null;
                                        socketReader = null;
                                        pipeStreams();
                                        await new Promise((callback, onError) => {
                                            socket.on('error', onError);
                                        });
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
                                reader = null;
                                writer = null;
                                socketReader = null;
                                socketWriter = null;
                                chiperServer = createMCChiperStream(sharedSecret);
                                dechiperServer = createMCDechiperStream(sharedSecret);
                                socket.emit('encryption', { chiper: chiperServer, dechiper: dechiperServer });
                                chiperServer.on('error', ex => {
                                    try{dechiperServer.destroy(ex)} catch(_) {}
                                    try{socket.destroy(ex)} catch(_) {}
                                });
                                dechiperServer.on('error', ex => {
                                    try{chiperServer.destroy(ex)} catch(_) {}
                                    try{socket.destroy(ex)} catch(_) {}
                                });
                                socket.on('error', ex => {
                                    try{chiperServer.destroy(ex)} catch(_) {}
                                    try{dechiperServer.destroy(ex)} catch(_) {}
                                });
                                socket.pipe(dechiperServer);
                                chiperServer.pipe(socket);
                                pipeStreams();
                                await new Promise((callback, onError) => {
                                    socket.on('error', onError);
                                    dechiperServer.on('end', () => callback());
                                });
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
                        await reader.readBytes(length - (reader.index - index));
                        continue;
                    }
                    if(id != 0x01) throw new TypeError("Invalid ID for encryption response: " + id + " length: " + length);
                    var sharedSecretLen = await reader.readVarInt();
                    if(sharedSecretLen < 0 || sharedSecretLen > 256) throw new RangeError("Too big shared secret");
                    var encryptedSharedSecret = await reader.readBytes(sharedSecretLen);
                    var verifyTokenLen = await reader.readVarInt();
                    if(verifyTokenLen < 0 || verifyTokenLen > 256) throw new TypeError("Too big verify token");
                    var clientVerifyToken = await reader.readBytes(verifyTokenLen);
                    var { publicKey, privateKey } = await keyPromise;
                    var decryptKey = crypto.createPrivateKey({
                        key: privateKey,
                        format: 'der',
                        type: 'pkcs8'
                    })
                    var toVerify = crypto.privateDecrypt({
                        key: decryptKey,
                        padding: crypto.constants.RSA_PKCS1_PADDING
                    }, clientVerifyToken);
                    if(toVerify.length != verifyToken.length || !crypto.timingSafeEqual(toVerify, verifyToken)) throw new TypeError("verify token does not match");
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
        
    } catch(ex) {
        try {socket.destroy(ex)}catch(_){}
        throw ex;
    }
    socket.on('error', () => {});
    try{socket.destroy();}catch(_){}
    return { data, ping: ping };
}

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
            case 4:
                var messageID = await reader.readVarInt();
                await reader.readBytes(length - (reader.index - index));
                buff1 = writer.createCheckpoint(5);
                buff2 = writer.createCheckpoint(10);
                buff2.writeVarInt(2);
                buff2.writeVarInt(messageID);
                buff2.writeByte(0);
                buff1.writeVarInt(buff2.length);
                buff1.appendPending();
                await buff2.push();
                continue;
            default:
                throw new Error("Unknown packet ID in login: " + id);
            }
        }
        if(id == 1) {
            var serverName = await reader.readString(20);
            var pubKeyLength = await reader.readVarInt();
            if(pubKeyLength > 256) throw new Error("Too long public key");
            var publicKey = await reader.readBytes(pubKeyLength);
            var verifyTokenLength = await reader.readVarInt();
            if(verifyTokenLength > 256) throw new Error("Too long verify token");
            await reader.readBytes(verifyTokenLength);
            if(reader.index !== index + length) throw new Error("index does not match with length for encryption request");
            var serverNameBuff = Buffer.from(serverName, 'utf-8');
            response = {status: 'online', publicKey, serverName, createHash(sharedSecret) {
                return mcHexDigest(crypto.createHash('sha1').update(serverNameBuff).update(sharedSecret).update(pubKey).digest());
            }};
        }
        if(!response) throw new Error("No response");

    } catch(ex) {
        try {socket.destroy(ex)}catch(_){}
        throw ex;
    }
    socket.on('error', () => {});
    try{socket.destroy();}catch(_){}
    return response;
}

function resolveMCSrvRecord(host) {
    return new Promise(resolve => {
        dns.resolveSrv('_minecraft._tcp.' + host, (err, addr) => {
            if(addr) addr = addr[0];
            if(err || !addr || !addr.name) resolve({name: host, port: null});
            else resolve({name: addr.name, port: addr.port});
        })
    });
}

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

function parsePingMotdObject(chat) {
    var totalMotd = chatObjectToString(chat);
    var splitIndex = totalMotd.indexOf('\n');

    if(splitIndex < 0 || splitIndex > 45) splitIndex = 45;
    return [totalMotd.substr(0, splitIndex), totalMotd.substr(splitIndex, 45).split('\n').join('')];

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
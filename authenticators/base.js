const https = require('https');
const { createProxyServer, resolveMCSrvRecord } = require('../mc-proxy');

function makeHTTPSRequest({ host, port, path, method, headers, body }) {
    var stack = new Error("Caused by");
    return (new Promise((resolve, reject) => {
        if (!headers) headers = {};
        if (body && typeof body === 'object') {
            body = JSON.stringify(body);
            headers['Content-Type'] = 'application/json;utf-8';
        }
        if (!headers["Accept"]) headers["Accept"] = "application/json";
        if (!port) port = 443;
        if (!method) method = 'GET';
        if (body) body = Buffer.from(String(body), 'utf-8');
        if (body) headers['Content-Length'] = String(body.length);
        var req = https.request({ host, port, path, method, headers, rejectUnauthorized: false }, res => {
            var data = [];
            var len = 0;
            res.on('error', ex => reject(ex));
            res.on('data', d => {
                len += d.length;
                if (len > 524288) {
                    res.destroy(new RangeError("Too much data"));
                    return;
                }
                data.push(d);
            });
            res.on('end', () => {
                try {
                    if (res.statusCode === 204) {
                        if (len > 0) reject(new RangeError("Data on no content"));
                        else resolve(null);
                        return;
                    }
                    if (res.statusCode !== 200) {
                        var message = "Unknown error";
                        try {
                            var json = JSON.parse(Buffer.concat(data).toString('utf-8'));
                            if (json && typeof json == 'object') message = json.errormessage || json.errorMessage || json.message || json.description || json.error || message;
                        } catch (_) { }
                        var err = new Error("Request failed: " + res.statusCode + " " + message);
                        err.response = res;
                        reject(err);
                        return;
                    }
                    resolve(JSON.parse(Buffer.concat(data).toString('utf-8')));
                } catch (ex) {
                    reject(ex);
                }
            });
        }).on('error', err => reject(err));
        if (body) req.write(body);
        req.end();
    })).catch(ex => {
        if (ex.stack && stack.stack) ex.stack += stack.stack;
        throw ex;
    })
}


class MCAuthenticator {
    /**
     * Constructs a new MCAuthenticator.
     * 
     * In the constructor of a implementing class it must add a argument where the user can supply credentials.
     * The constructor only stores the credentials and does not validate them or make any https requests. 
     * That will happen in the login() method.
     */
    constructor() {
        if (this.constructor === MCAuthenticator) throw new Error("This is an abstract class");
        this.keepAliveInterval = null;
        this.waitlist = Promise.resolve(true);
        /**
         * The name of the user. A class MUST set this value after the login() method succeeds.
         * @return {string}
         */
        this.name = null;
        /**
         * The uuid of the user. A class MUST set this value after the login() method succeeds.
         * 
         * The uuid is wihout dashes
         * @returns {string}
         */
        this.uuid = null;
    }

    /**
     * Call this function after all other operations completed
     * And a next operation will only occur if the operation of this function completes.
     * 
     * Function must return a promise. A operation is also completed, if promise rejects.
     * Function is only called if other operations completed.
     * 
     * Returns a new promise, that resolves/rejects with the promise of func.
     * @param {() => Promise} func the function that will return a new operation, if all other operations completed
     * @returns {Promise} A promise that will resolves/rejects with the return value of the new operation.
     */
    addWaitlist(func) {
        var oldwaitlist = this.waitlist;
        var callback;
        this.waitlist = new Promise(resolve => callback = resolve);
        var promise = oldwaitlist.then(typeof func == 'function' ? func : () => func);
        promise.finally(() => callback());
        return promise;
    }

    /**
     * Get a session token from a (third-party) authentication server
     * @returns {Promise}
     */
    login() {
        return Promise.reject(new TypeError("This class does not implement the required login method"));
    }

    /**
     * Refreshes the current session token.
     * 
     * If not implemented, this function will just call login() again to get a new session token.
     * @returns {Promise}
     */
    refresh() {
        return this.login();
    }

    /**
     * Validate this session if it is logged in. Returns false if not valid.
     * 
     * May return true even if session is not valid, in such case, try to login again().
     * Depends on implementation
     * @returns {Promise}
     */
    validate() {
        return Promise.resolve(true);
    }

    /**
     * Invalidates this session. May silently fail if this function is not supported.
     * 
     * You can always get a new session with login() (if credentials are still valid)
     * 
     * Invalidate MUST stop the keepAlive (this.keepAlive(false))
     * @returns 
     */
    invalidate() {
        this.keepAlive(false);
        return Promise.resolve(null);
    }

    /**
     * Install an interval that will refresh the access token every 5 minutes
     * @param {boolean} run to enable/disable it.
     * @param {Error => void} onError if an error occured, the keep alive will terminate
     * @returns 
     */
    keepAlive(run = true, onError) {
        if (run) {
            if (this.keepAliveInterval) return;
            this.keepAliveInterval = setInterval(() => {
                if (!this.accessToken) return;
                this.refresh().catch(ex => {
                    if (onError) onError(ex);
                    this.keepAlive(false);
                });
            }, 300000)
        } else {
            if (!this.keepAliveInterval) return;
            clearInterval(this.keepAliveInterval);
        }
    }

    /**
     * Sign server hash with the account using the mojang session server.
     * 
     * Try createProxyServer() for a much simpler API
     * 
     * What is the server hash?
     * You get the server hash after you received the encryption response packet from the server.
     * Server hash is then hexdigest(sha1(serverName + 128 bits (16 bytes) shared AES secret + 1024 bits RSA public key of server in DER format))
     * hexdigest is non standard. It is actually pretty simple: the sha1 hash as a 20-byte signed (two complement) integer encoded as a hex number (base 16, not base 10) and minus if negative.
     *                            library functions that convert binary to hex are usually unsigned.
     * the serverName value is usually empty.
     * See https://wiki.vg/Protocol_Encryption for more details about the encryption.
     * 
     * About privacy:
     * A third-party authentication server can't know the server you are playing on because he can't decrypt the SHA1 hash.
     * However, mojang can still see it, because the server must validate the server hash with the hasJoined endpoint (and mojang then knows the IP of the server).
     * 
     * It is recommended to use keepAlive to make sure that your session never invalidates if you are using this function.
     * @param {String} serverHash the server hash (calculated from the SHA1) as a MC hexdigest string
     * @returns {Promise} a promise that resolves to null if success and rejects with an Error if failed.
     */
    signServerHash(serverHash) {
        return Promise.reject(new Error("This class does not implement the required sign server hash method"))
    }

    /**
     * Create a proxy server, you can connect to this proxy server using the minecraft client without any modification, man in the middle attack etc.
     * The proxy server does then the authentication with (third-party) authentication server to join the original server.
     * You can only use this function if you already exchanged the alt token for a session.
     * 
     * The original player name will be censored. It can still be verified, but then it will only be used to verify it and will never be sent to the original server.
     * 
     * If the server is hosted on loopback, you can set the server in offline mode because it is impossible to eavesdrop a loopback.
     * However if you also host it to the outside world, enable online mode (setting whitelist to [] or a list of allowed players) because offline mode does NOT have encryption
     * meaning the connection between you and the proxy server can be eavesdropped and you lose the privacy.
     * 
     * It is not possible to use offline mode with encryption.
     * 
     * The proxy server will then decrypt any packet comming from the client and encrypt it again with the shared secret between proxy and the original server. (and vice versa)
     * 
     * @param {string} host The host to connect to (can have a SRV record)
     * @param {number} port the port to connect to
     * @param {undefined | null | string[]} whitelist empty array if premium account is necessary, null if the proxy server is in offline mode, non empty if you only allow specific players (with premium accounts). Undefined if default (localhost offline, rest online)
     * @returns 
     */
    createProxyServer(host, port, whitelist = undefined, sharedSecret) {
        if (whitelist === undefined) {
            if (host == 'localhost' || host.startsWith('127.')) {
                whitelist = null;
            } else {
                whitelist = [];
            }
        }
        var isOffline = !whitelist;
        if (!whitelist) whitelist = [];

        var hostPromise = resolveMCSrvRecord(host);

        return createSessionProxyServer(async request => {
            var req = ({
                host: (await hostPromise).name,
                port: ((await hostPromise).port) || port,
                cracked: isOffline,
                getSecret: typeof sharedSecret === 'function' ? sharedSecret : async () => sharedSecret,
                getSession: async () => this,
                verifyLogin: async () => !whitelist.length || whitelist.includes(request.username),
                getDisconnectMessage: async reason => reason == 'user-denied' ? { text: 'You are not whitelisted on this server.' } : null,
            });
            return req;
        });
    }

}

class CrackedMCAuthenticator extends MCAuthenticator {
    constructor(name) {
        super();
        this.accessToken = 'cracked';
        this.name = name;
        this.uuid = '00000000000000000000000000000000';
    }

    login() {
        return Promise.resolve(true);
    }

    keepAlive() {
        return;
    }

    signServerHash(hash) {
        return Promise.resolve(true);
    }
}

/**
 * Returns a new session that represents a cracked minecraft account (username only)
 * 
 * You can only use this session to join cracked server (and Open to LAN).
 * If you try to join a online server, it will give you 'Cannot verify user' error.
 * @param {string} name the name
 * @returns {CrackedMCAuthenticator} A new authenticator that lets you only login cracked servers, with the name
 */
function createCrackedSession(name) {
    return new CrackedMCAuthenticator(name);
}

/**
 * Create a new proxy server, that will authenticate using a session.
 * 
 * Options is a function that accepts a proxy request and returns a proxy response (with some changes):
 * 1. getSession() to get the MCAuthenticator session (async)
 * 2. getSecret() optional to get a pre defined shared secret (for debugging)
 * @param {((request: {state: 'login' | 'status', host: string, port: number, version: number, username: string}) => (Promise<{ host: string, port: number, version?: number, getSession: () => (MCAuthenticator | Promise<MCAuthenticator), getSecret?: () => (Buffer | Promise<Buffer>) }> | { host: string, port: number, version?: number, getSession: () => (MCAuthenticator | Promise<MCAuthenticator), getSecret?: () => (Buffer | Promise<Buffer>) })) | { host: string, port: number, version?: number, getSession: () => (MCAuthenticator | Promise<MCAuthenticator), getSecret?: () => (Buffer | Promise<Buffer>) }} options 
 * @returns 
 */
function createSessionProxyServer(options) {
    if (typeof options !== 'function') (data => options = () => data)(options);
    return createProxyServer(request => Promise.resolve(options(request)).then(res => {
        res.getUser = async () => {
            var session = await res.getSession();
            var sharedSecret = (await res.getSecret()) || undefined;
            return {
                username: session.name,
                joinServer: session.signServerHash.bind(session),
                sharedSecret
            }
        };
        return res;
    }));
}

module.exports = {
    MCAuthenticator,
    createCrackedSession,
    createSessionProxyServer,
    makeHTTPSRequest
};

const { uuidWithoutDashes } = require('../mc-proxy');
const { MCAuthenticator, makeHTTPSRequest } = require('./base');
const crypto = require('crypto');

function makeMojangAuthRequest(endpoint, body) {
    return makeHTTPSRequest({ host: 'authserver.mojang.com', method: body == null ? 'GET' : 'POST', path: endpoint, body });
}

function makeMojangSessionRequest(endpoint, body) {
    return makeHTTPSRequest({ host: 'sessionserver.mojang.com', method: body == null ? 'GET' : 'POST', path: endpoint, body });
}

function generateClientToken() {
    return new Promise((resolve, reject) => {
        crypto.randomFill(Buffer.alloc(16), (err, buff) => {
                if(err) reject(err);
                else {
                    this.clientToken = buff.toString('hex');
                    resolve(this.clientToken);
                }
            });
        });
}

//You may want to look at this: https://wiki.vg/Authentication, for info about the endpoints.

class MinecraftAuthenticator extends MCAuthenticator {
    constructor() {
        super();
        if(this.constructor === MinecraftAuthenticator) throw new TypeError("This is an abstract class that must be implemented (with login())")
        /**
         * The mojang JWT access token. Must be set by the login() method (that is the only method that must be implemented).
         * @type {string}
         */
        this.accessToken = null;
        /**
         * The mojang JWT client token. Must be set by the login() method
         * use the generateClientToken() (returns a Promise!) to get a random secure client token.
         */
        this.clientToken = null;
    }

    refresh() {
        var accessToken, clientToken, uuid, name;
        return this.addWaitlist(Promise.resolve()
            .then(() => {
                if(!this.accessToken) throw new Error("You must first redeem the code");
                accessToken = this.accessToken;
                clientToken = this.clientToken || undefined;
                uuid = this.uuid;
                name = this.name;
            })
            .then(() => makeMojangAuthRequest('/refresh', {
                accessToken,
                clientToken: clientToken || undefined,
                selectedProfile: {
                    id: uuid,
                    name
                },
                requestUser: true
            })).then(result => {
                if(!result || typeof result !== 'object' || !result.accessToken || typeof result.accessToken !== 'string') 
                    throw new TypeError("Invalid JSON data");
                return Object.assign(this, {
                    accessToken: result.accessToken,
                    created: new Date(),
                    refreshed: new Date()
                });
            })
        );
    }

    /**
     * Validate the current session, if not you may need to (relogin) again.
     * @returns {Promise} resolves with true or false (never errors)
     */
    validate() {
        return this.addWaitlist(() => Promise.resolve()
            .then(() => {
                if(!this.accessToken) throw new Error("You must first redeem the code");
            })
            .then(() => makeMojangAuthRequest('/validate', {
                accessToken: this.accessToken,
                clientToken: this.clientToken || undefined
            })).then(res => {
                if(res !== null) throw new Error("Expected 204 if valid");
                return true;
            }, () => false)
            .finally(() => callback())
        );
    }

    /**
     * Invalidates the current session token
     * @returns {Promise}
     */
    invalidate() {
        this.keepAlive(false);
        return this.addWaitlist(() => Promise.resolve()
            .then(() => {
                if(!this.accessToken) throw new Error("You must first redeem the code");
            })
            .then(() => makeMojangAuthRequest('/invalidate', {
                accessToken: this.accessToken,
                clientToken: this.clientToken || undefined
            }))
            .then(res => {
                Object.assign(this, {
                    accessToken: null,
                    clientToken: null
                });
                if(res !== null) throw new Error("Expected 204 if valid");
                return true;
            })
        );  
    }

    signServerHash(serverHash) {
        return this.addWaitlist(() => Promise.resolve()
            .then(() => {
                if(!this.accessToken) throw new Error("You must first redeem the code");
            }).then(() => makeMojangSessionRequest('/session/minecraft/join', {
                accessToken: this.accessToken,
                selectedProfile: this.uuid,
                serverId: serverHash
            }))
            .then(res => {
                if(res != null) throw new Error("Join server expects 204");
                return true;
            })
        );
        
    }
}

class MojangAccountAuthenicator extends MinecraftAuthenticator {
    constructor(credentials, password) {
        super();
        if(typeof credentials == 'string') {
            if(!password) throw new TypeError("No password supplied");
            this.credentials = async () => ({ username: credentials, password: String(password) });
        } else if(typeof credentials == 'function') {
            this.credentials = async () => Promise.resolve(credentials()).then(value => ({ username: String(value.username), password: String(value.password) }));
        } else if(typeof credentials == 'object') {
            if(!credentials) throw new TypeError("Credentials cannot be null");
            if(!credentials.username || !credentials.password) throw new TypeError("No username/password");
            this.credentials = async () => ({ username: String(credentials.username), password: String(credentials.password )});
        } else throw new TypeError("Unknown type for credentials");
    }

    login() {
        return Promise.resolve(this).then(this.credentials).then(credentials => this.addWaitlist(() => generateClientToken()
            .then(clientToken => this.clientToken = clientToken)
            .then(() => makeMojangAuthRequest('/authenticate', {
                agent: {
                    name: "minecraft",
                    version: 1
                },
                username: credentials.username,
                password: credentials.password,
                clientToken: this.clientToken,
                requestUser: true
            }))
            .then(result => {
                this.accessToken = result.accessToken;
                if(!result.selectedProfile) throw new Error("Mojang account does not have a valid minecraft license");
                if(!result || typeof result !== 'object' || !result.accessToken || typeof result.accessToken !== 'string' || typeof result.selectedProfile !== 'object' || !result.selectedProfile.name || typeof result.selectedProfile.name !== 'string' || !result.selectedProfile.id || typeof result.selectedProfile.id !== 'string') 
                    throw new TypeError("Invalid JSON data");
                
                Object.assign(this, {
                    name: result.selectedProfile.name,
                    uuid: result.selectedProfile.id,
                    created: new Date(),
                    refreshed: new Date()
                });
            })
        ));
    }
}

class MCAccessTokenAuthenticator extends MinecraftAuthenticator {
    constructor(token, name, clientToken) {
        super();
        this.accessToken = String(token);
        this.clientToken = clientToken || null;
        if(name.length > 16) {
            this.uuid = uuidWithoutDashes(name);
        } else {
            this.name = name;
        }
    }

    login() {
        return this.addWaitlist(() => 
            makeMojangAuthRequest('/validate', {
                clientToken: this.clientToken || undefined,
                accessToken: this.accessToken 
            })
            .then(res => { 
                if(res !== null) throw new Error("Expected 204 if valid");
                if(this.uuid) {
                    return makeHTTPSRequest({ host: 'api.mojang.com', path: '/user/profiles/' + this.uuid + '/names', method: 'get' }).then(res => ({ uuid: this.uuid, name: [...res].find(x => !x.changedToAt).name }));
                } else {
                    return makeHTTPSRequest({ host: 'api.mojang.com', path: '/users/profiles/minecraft/' + encodeURIComponent(String(this.name)), method: 'get'}).then(res => ({ uuid: res.id, name: this.name }));
                }
            })
            .then(res => Object.assign(this, res))
        );
    }

    /* Do nothing on invalidate()/refresh() because reauth must be possible */
    invalidate() {
        return Promise.resolve(true);
    }

    refresh() {
        return this.addWaitlist(() => {
            Promise.resolve()
            .then(() => {
                if(!this.accessToken || !this.name || !this.uuid) throw new Error("Use the long() method to get the necessary information about the user.");
            })
            makeMojangAuthRequest('/validate', {
                clientToken: this.clientToken || undefined,
                accessToken: this.accessToken 
            })
            .then(res => {
                if(res !== null) throw new Error("Expected 204 if valid");
            })
        });
    }
}

function loginMojangAccount(credentials, password) {
    try {
        var session = new MojangAccountAuthenicator(credentials, password);
        return session.login().then(() => session);
    } catch(ex) {
        return Promise.reject(ex);
    }
}

function sessionFromAccesToken(accessToken, name, clientToken) {
    try {
        var session = new MCAccessTokenAuthenticator(accessToken, name, clientToken);
        return session.login().then(() => session);
    } catch(ex) {
        return Promise.reject(ex);
    }
}

module.exports = { 
    MinecraftAuthenticator, 
    MojangAccountAuthenicator, 
    MCAccessTokenAuthenticator, 
    generateClientToken, 
    
    loginMojangAccount,
    sessionFromAccesToken,

    makeMojangAuthRequest, 
    makeMojangSessionRequest 
};
//Mcleaks (unlike thealtenticator) provides their api: see: https://mcleaks.net/apidoc

const { MCAuthenticator, makeHTTPSRequest } = require('./base');

function makeMCLeakRequest(endpoint, body) {
    return makeHTTPSRequest({ host: 'auth.mcleaks.net', method: body == null ? 'GET' : 'POST', path: '/v1/' + endpoint, body });
}


class MCLeakAuthenticator extends MCAuthenticator {
    constructor(altToken) {
        super();
        this.altToken = String(altToken);
    }

    /**
     * Redeem the alt token, to get an access token, the name and uuid.
     * 
     * You cannot invalidate the access token, and to refresh it you call login() again.
     * Actually the refresh() function just calls login()
     * @returns {Promise<MCLeakAuthenticator>}
     */
    login() {
        return this.addWaitlist(() => makeMCLeakRequest('redeem', { token: this.altToken }).then(res => {
            if(!res.success) throw new Error("Request failed: " + (res.errorMessage || 'Unknown error'));
            this.accessToken = res.result.session;
            //Why does this API not provide a UUID??
            return makeHTTPSRequest({ host: 'api.mojang.com', path: '/users/profiles/minecraft/' + encodeURIComponent(String(res.result.mcname)), method: 'get'})
        })).then(res => {
            this.name = res.name;
            this.uuid = res.id;
            this.created = new Date();
            this.refresed = new Date();
            return this;
        });
    }

    /**
     * There is no refresh api endpoint so it will just get a new session token by redeeming the alt token again.
     * @returns {Promise}
     */
    refresh() {
        var created = this.created;
        return this.login().finally(() => this.created = created);
    }

    signServerHash(serverId) {
        return this.addWaitlist(() => Promise.resolve()
            .then(() => {
                if(!this.accessToken) throw new Error("No access token, use login() first");
            })
            .then(() => makeMCLeakRequest('joinserver', { 
                session: this.accessToken,
                mcname: this.name,
                serverhash: serverId,
                server: 'censored.example.com:25565' //we will not provide the server address for privacy. It is also not important for https://sessionserver.mojang.com/session/minecraft/join
            }).then(res => {
                if(!res.success) throw new Error("Request failed: " + (res.errorMessage || 'Unknown error'));
                return true;
            }))
        )
    }
}

function redeemMCLeakToken(altToken) {
    try {
        var session = new MCLeakAuthenticator(altToken);
        return session.login().then(() => session);
    } catch(ex) {
        return Promise.reject(ex);
    }
}

module.exports = { MCLeakAuthenticator, redeemMCLeakToken };

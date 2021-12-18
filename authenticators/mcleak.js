//Mcleaks (unlike thealtenticator) provides their api: see: https://mcleaks.net/apidoc

const { MCAuthenticator, makeHTTPSRequest, parseCookies } = require('./base');

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

    validate() {
        return this.signServerHash('-25c65c11a194b4f2cdaa40106a9fe76f5027f8f7');
    }

    refresh() {
        return this.validate();
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

function generateMCLeakToken(recaptchaCode) {
    return makeHTTPSRequest({
        host: 'mcleaks.net',
        path: '/get',
        method: 'post',
        text: true,
        supplyHeaders: true,
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html"
        },
        body: "posttype=false&g-recaptcha-response=" + encodeURIComponent(recaptchaCode)
    }).then(res => {
        if(res && res.redirect) {
            return makeHTTPSRequest({
                host: 'mcleaks.net',
                path: res.redirect,
                method: 'get',
                text: true,
                headers: {
                    "Accept": "text/html",
                    "Cookie": parseCookies(res.headers['set-cookie'])
                }
            })
        } else return res;
    }).then(res => {
        if(!res) throw new Error("No response received");
        var found = /<input.*id="alttoken".*value="([a-zA-Z0-9]+)"/.exec(String(res));
        if(!found || !found[1]) throw new Error("No token found in response");
        return found[1];
    })
}

module.exports = { MCLeakAuthenticator, redeemMCLeakToken, generateMCLeakToken };

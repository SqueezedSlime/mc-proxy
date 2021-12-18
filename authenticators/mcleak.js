//Mcleaks (unlike thealtenticator) provides their api: see: https://mcleaks.net/apidoc

const { Waitlistable, MCAuthenticator, makeHTTPSRequest, parseCookies } = require('./base');

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

class MCLeakGenerateSession extends Waitlistable {
    constructor() {
        super();
    }

    generateToken(recaptchaCode = '') {
        var req = {
            host: 'mcleaks.net',
            path: '/get',
            method: 'post',
            text: true,
            supplyHeaders: true,
            body: 'posttype=true',
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "*/*",
                "Origin": "https://mcleaks.net",
                "Referer": "https://mcleaks.net/"
            }
        };
        if(this.token) req.headers.Cookie = this.token;
        if(recaptchaCode) { 
            req.body = "posttype=true&g-recaptcha-response=" + encodeURIComponent(recaptchaCode); 
        }

        return this.addWaitlist(() => makeHTTPSRequest(req).then(res => {
            var token = parseCookies(res.headers['set-cookie'], this.token);
            if(!token) throw new Error("No cookies provided from MCLeaks");
            this.token = token;
            if(res && res.redirect) {
                return makeHTTPSRequest({
                    host: 'mcleaks.net',
                    path: '/get',
                    method: 'get',
                    text: true,
                    supplyHeaders: true,
                    headers: {
                        "Accept": "*/*",
                        "Cookie": token,
                        "Referer": "https://mcleaks.net/"
                    }
                })
            } else return res;
        }).then(res => {
            if(!res) throw new Error("No response received");
            var token = parseCookies(res.headers['set-cookie'], this.token);
            if(!token) throw new Error("No cookies provided from MCLeaks");
            this.token = token;
            res = res.data;
            var found = /<input.*id="alttoken".*value="([a-zA-Z0-9]+)"/.exec(String(res));
            if(!found || !found[1]) throw new Error("No token found in response");
            return found[1];
        }));
    }

    refresh() {
        var headers = {
            "Accept": "*/*",
            "Origin": "https://mcleaks.net",
            "Referer": "https://mcleaks.net/get"
        };
        if(this.token) headers.Cookie = this.token;
        return this.addWaitlist(() => makeHTTPSRequest({
            host: 'mcleaks.net',
            path: '/getajax?refresh',
            method: 'get', //json
            text: true,
            supplyHeaders: true,
            headers
        }).then(res => {
            if(!res) throw new Error("No response received");
            var token = parseCookies(res.headers['set-cookie'], this.token);
            if(!token) throw new Error("No cookies provided from MCLeaks");
            this.token = token;
            return true;
        }));
    }

    renewToken(alttoken, recaptchaCode) {
        var headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://mcleaks.net",
            "Referer": "https://mcleaks.net/renew"
        };
        if(this.token) headers.Cookie = this.token;
        return this.addWaitlist(() => makeHTTPSRequest({
            host: 'mcleaks.net',
            path: "renew?_=" + new Date().getTime(),
            method: 'post',
            text: true,
            supplyHeaders: true,
            headers,
            body: 'alttoken=' + encodeURIComponent(alttoken) + '&captcha=' + encodeURIComponent(recaptchaCode)
        }).then(res => {
            if(!res) throw new Error("No response received");
            var token = parseCookies(res.headers['set-cookie'], this.token);
            if(!token) throw new Error("No cookies provided from MCLeaks");
            this.token = token;
            return makeHTTPSRequest({
                host: 'mcleaks.net',
                path: '/get',
                method: 'get',
                text: true,
                supplyHeaders: true,
                headers: {
                    "Accept": "*/*",
                    "Cookie": token,
                    "Referer": "https://mcleaks.net/renew"
                }
            });
        }).then(res => {
            if(!res) throw new Error("No response received");
            var token = parseCookies(res.headers['set-cookie'], this.token);
            if(!token) throw new Error("No cookies provided from MCLeaks");
            this.token = token;
            res = res.data;
            var found = /<input.*id="alttoken".*value="([a-zA-Z0-9]+)"/.exec(String(res));
            if(!found || !found[1]) throw new Error("No token found in response");
            return found[1];
        }));
    }

}

function generateMCLeakToken(recaptchaCode) {
    return (new MCLeakGenerateSession()).generateToken(recaptchaCode);
}

function renewMCLeakToken(alttoken, recaptchaCode) {
    return (new MCLeakGenerateSession()).renew(alttoken, recaptchaCode);
}

module.exports = { MCLeakAuthenticator, redeemMCLeakToken, MCLeakGenerateSession, generateMCLeakToken, renewMCLeakToken };

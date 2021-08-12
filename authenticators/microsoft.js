const { MinecraftAuthenticator } = require('./mojang');
const { makeHTTPSRequest } = require('./base');

class MicrosoftAccountAuthenicator extends MinecraftAuthenticator {
    constructor(get_authorization_code, redirect_uri) {
        super();
        if(typeof get_authorization_code !== 'function') {
            var code = get_authorization_code;
            get_authorization_code = () => code;
        }
        this.get_authorization_code = get_authorization_code;
        if(!redirect_uri) redirect_uri = "https://login.live.com/oauth20_desktop.srf";
        this.redirect_uri = String(redirect_uri)
    }

    login() {
        if(!this.get_authorization_code) return Promise.reject(new Error("Can only login once"));

        return Promise.resolve(this).then(this.get_authorization_code).then(code => this.addWaitlist(() =>
            makeHTTPSRequest({
                host: 'login.live.com', 
                port: 443,
                path: '/oauth20_token.srf', 
                method: 'POST', 
                headers: {
                     'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: 'client_id=00000000402b5328&code=' + encodeURIComponent(String(code)) + '&grant_type=authorization_code&redirect_uri=' + encodeURIComponent(this.redirect_uri)
            }).finally(() => this.get_authorization_code = null).then(res => makeHTTPSRequest({
                host: 'user.auth.xboxlive.com',
                port: 443,
                path: '/user/authenticate',
                method: 'POST',
                body: {
                    Properties: {
                        AuthMethod: 'RPS',
                        SiteName: 'user.auth.xboxlive.com',
                        RpsTicket: String(res.access_token),
                    },
                    RelyingParty: 'http://auth.xboxlive.com',
                    TokenType: 'JWT'
                }
            })).then(res => makeHTTPSRequest({
                host: 'xsts.auth.xboxlive.com',
                port: 443,
                path: '/xsts/authorize',
                method: 'POST',
                body: {
                    Properties: {
                        SandboxId: 'RETAIL',
                        UserTokens: [String(res.Token)],
                    },
                    RelyingParty: 'rp://api.minecraftservices.com/',
                    TokenType: 'JWT'
                }
            })).then(res => makeHTTPSRequest({
                host: 'api.minecraftservices.com',
                port: 443,
                path: '/authentication/login_with_xbox',
                method: 'POST',
                body: {
                    identityToken: "XBL3.0 x=" + String(res.DisplayClaims.xui[0].uhs) + ";" + String(res.Token)
                }
            })).then(res => {
                this.accessToken = String(res.access_token);
                return makeHTTPSRequest({
                    host: 'api.minecraftservices.com',
                    port: 443,
                    path: '/minecraft/profile',
                    method: 'GET',
                    headers: {
                        'Authorization': 'Bearer ' + this.accessToken
                    }
                }).catch(ex => {
                    if(ex instanceof Error && ex.response && ex.response.statusCode == 404) {
                        var err = new Error("This microsoft account does not have a valid minecraft license");
                        err.cause = ex;
                        err.response = ex.response;
                        throw err;
                    } else throw ex; //rethrow
                });
            }).then(res => {
                this.name = String(res.name);
                this.uuid = String(res.id);
            })
        ));
    }
}

function loginMicrosoftAccount(authorizationCode, redirect_uri) {
    try {
        var session = new MicrosoftAccountAuthenicator(authorizationCode, redirect_uri);
        return session.login().then(() => session);
    } catch(ex) {
        return Promise.reject(ex);
    }
}

module.exports = { MicrosoftAccountAuthenicator, loginMicrosoftAccount }
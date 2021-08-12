const { makeAltServerRequest, AltServerAuthenticator } = require('./altserver')

var alteningStatus = {
    authentication: "unknown",
    sessions: "unknown",
    website: "unknown",
    checker: "unknown"
};

var hasStatus = false;

var getEndpoints = null;

var alteningOptions = {
    getEndpoints: () => {
        if(!getEndpoints) getAlteningStatus(true);
        return getEndpoints
    },
    certs:  [
        "40:B7:E3:2E:38:99:73:44:7A:1B:DB:53:6C:0C:82:C2:97:09:70:48:B2:35:8A:DD:80:B5:F5:DC:37:87:75:7D", 
        "C4:96:7E:29:5A:B7:8E:C6:32:69:9D:D2:46:6C:7C:8C:9C:B6:02:D1:14:52:4F:41:8B:B7:15:73:EB:B6:E3:76", 
        "17:59:AE:78:E0:08:30:9E:32:6C:43:56:7A:AE:B0:FA:45:CD:F8:EE:55:01:AB:B1:DA:5D:76:49:BB:DD:54:EE"
    ],
    hostnames: ["api.thealtening.com"]
}

function getAlteningStatus(refresh = false) {
    if(!refresh && hasStatus) return Promise.resolve(Object.assign({}, alteningStatus));

    var pr;
    getEndpoints = new Promise(callback => {
        pr = makeAltServerRequest(alteningOptions, 'api.thealtening.com', '/status').then(json => {
            for(var name in alteningStatus) {
                alteningStatus[name] = (json.status[name] && (json.status[name] === 'OK' ? 'ok' : 'down')) || 'unknown';
            }
            hasStatus = true;
            callback({
                authentication: String(json.endpoints.server_authentication),
                session: String(json.endpoints.server_session)
            });
            return (Object.assign({}, alteningStatus));
        }).catch(ex => {
            callback(ex);
            throw ex;
        });
    });

    return pr;
}


class AlteningAuthenticator extends AltServerAuthenticator {
    /**
     * Create a new AlteningAuthenticator, use login() to redeem the alt token
     * @param {string} altToken An altening alt token, you can get one by https://thealtening.com
     */
    constructor(altToken) {
        super(alteningOptions, altToken);
    } 
}

/**
 * Create a AlteningAuthenticator that is already authenticated
 * @param {string} altToken An altening alt token, you can get one by https://thealtening.com
 * @returns {Promsie<AlteningAuthenticator>} A promise that resolves to a pre-authenticated AlteningAuthenticator (login() is already called) or rejects with an error.
 */
function redeemAlteningToken(altToken) {
    try {
        var session = new AlteningAuthenticator(altToken);
        return session.login().then(() => session);
    } catch(ex) {
        return Promise.reject(ex);
    }
}

module.exports = {
    getAlteningStatus,
    AlteningAuthenticator,
    redeemAlteningToken,
    alteningStatus,
    alteningOptions
}
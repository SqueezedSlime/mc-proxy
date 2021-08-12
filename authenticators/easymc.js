const { AltServerAuthenticator } = require('./altserver')

var easyMCOptions = {
    getEndpoints: () => {
        return {authentication: "51.68.172.243", session: "51.68.172.243"}
    },
    certs: [
        "5E:91:EE:69:0C:24:5C:6C:75:0E:15:51:75:26:98:1B:42:36:C9:EC:69:B0:1A:DD:FE:11:4D:88:8D:57:1D:83",
        "90:B4:BD:5E:12:F4:41:D0:97:A2:A4:DE:C3:67:41:E8:C0:5C:3D:EA:BE:FC:DB:DE:F5:99:40:62:07:66:6F:5B"
        //api cert not needed because it is valid
    ],
    hostnames: ["api.easymc.io"] //not used
}

class EasyMCAuthenticator extends AltServerAuthenticator {
    /**
     * Create a new EasyMCAuthenticator, use login() to redeem the alt token
     * @param {string} altToken An altening alt token, you can get one by https://easymc.io
     */
    constructor(altToken) {
        super(easyMCOptions, altToken);
    } 
}

/**
 * Create a EasyMCAuthenticator that is already authenticated
 * @param {string} altToken An altening alt token, you can get one by https://easymc.io
 * @returns {Promsie<AlteningAuthenticator>} A promise that resolves to a pre-authenticated EasyMCAuthenticator (login() is already called) or rejects with an error.
 */
function redeemEasyMCToken(altToken) {
    try {
        var session = new EasyMCAuthenticator(altToken);
        return session.login().then(() => session);
    } catch(ex) {
        return Promise.reject(ex);
    }
}

module.exports = {
    EasyMCAuthenticator,
    redeemEasyMCToken,
    easyMCOptions
}
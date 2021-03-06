const { ipcRenderer } = require('electron');
const { generateMCSharedSecret, uuidWithDashes, getServerStatus, getServerPublicKey, resolveMCSrvRecord, parsePingMotdObject, chatObjectToString } = require('./mc-proxy')
const { createCrackedSession } = require('./authenticators/base');
const { loginMojangAccount, sessionFromAccesToken } = require('./authenticators/mojang');
const { loginMicrosoftAccount } = require('./authenticators/microsoft');
const { redeemAlteningToken, AlteningGenerateSession } = require('./authenticators/altening');
const { redeemEasyMCToken, generateEasyMCToken, renewEasyMCToken } = require('./authenticators/easymc')
const { redeemMCLeakToken, MCLeakGenerateSession } = require('./authenticators/mcleak');
const { bindMulticastClient } = require('./mc-multicast')
const dns = require('dns');


var getEl = document.getElementById.bind(document);
var alteningGenerator = new AlteningGenerateSession();
var mcleakGenerator = new MCLeakGenerateSession();
var savedSessions = {};

var elements = {
    authentication_type: getEl('authentication_type'),
    credentials_block: getEl('mc_credentials'),
    name_label: getEl('mc_credentials_name_label'),
    name: getEl('mc_credentials_name'),
    token_block: getEl('mc_token_block'),
    token: getEl('mc_token'),
    password_block: getEl('mc_credentials_password_block'),
    password: getEl('mc_credentials_password'),
    server_type: getEl('server_type'),
    bind_block: getEl('mc_bind_block'),
    bind_address: getEl('mc_bind_address'),
    whitelist_block: getEl('mc_whitelist_block'),
    whitelist: getEl('mc_whitelist'),
    host: getEl('mc_host'),
    button: getEl('mc_play_button'),
    server_status: getEl('mc_server_status'),
    generate_token: getEl('generate_token_button'),
    renew_token: getEl('renew_token_button'),
    save_token: getEl('save_token_button'),
    saved_alts_block: getEl('mc_saved_alts_block'),
    saved_alts: getEl('mc_saved_alts'),
    server_hash_block: getEl('mc_serverhash_block'),
    server_ipv4: getEl('mc_serverip'),
    server_hash: getEl('mc_serverhash'),
    publickey: getEl('mc_publickey'),
    servername: getEl('mc_servername')
}

var windowPromise = Promise.resolve();
function retrieveUserCaptchaCode(host, sitekey) {
    var oldPromise = windowPromise;
    var promise = oldPromise.catch(() => null).then(() => new Promise(resolve => {
        ipcRenderer.once('captcha-result', (e, code) => {
            resolve(code || '');
        })
        ipcRenderer.send('prompt-captcha', { host, sitekey });
    }));
    windowPromise = promise;
    return promise;
}

function renderSavedAccounts() {
    elements.saved_alts.innerHTML = '';
    for(var altName in savedSessions) {
        let el = document.createElement('option');
        el.value = altName;
        el.textContent = altName;
        elements.saved_alts.appendChild(el);
    }
}

function setAuthServer(value) {
    elements.password.value = '';
    elements.token.value = '';
    elements.saved_alts_block.style.display = value == 'saved' ? 'block' : 'none';
    elements.server_hash_block.style.display = value == 'serverhash' ? 'block' : 'none';
    switch(value) {
    case 'saved':
        renderSavedAccounts();

        //fallthrough (set all elements to display none)
    case 'microsoft':
        elements.credentials_block.style.display = 'none';
        elements.password_block.style.display = 'none';
        elements.token_block.style.display = 'none';
        elements.generate_token.style.display = 'none';
        elements.renew_token.style.display = 'none';
        elements.save_token.style.display = 'none';
        return;
    case 'serverhash':

        //fallthrough
    case 'cracked':
        elements.password_block.style.display = 'none';
        elements.token_block.style.display = 'none';
        elements.name.maxLength = 16;
        elements.name_label.innerText = value == 'serverhash' ? 'Username of the MC account' : 'Cracked username';
        elements.name.placeholder = 'Username for server';
        elements.credentials_block.style.display = 'block';
        elements.generate_token.style.display = 'none';
        elements.renew_token.style.display = 'none';
        elements.save_token.style.display = 'none';
        return;
    case 'altening':
        elements.name.maxLength = 512;
        elements.password_block.style.display = 'none';
        elements.token_block.style.display = 'none';
        elements.name_label.innerText = 'Alt token';
        elements.name.placeholder = 'Alt token from thealtening.com'
        elements.credentials_block.style.display = 'block';
        elements.generate_token.style.display = 'block';
        elements.renew_token.style.display = 'none';
        elements.save_token.style.display = 'block';
        return;
    case 'easymc':
        elements.name.maxLength = 512;
        elements.password_block.style.display = 'none';
        elements.token_block.style.display = 'none';
        elements.name_label.innerText = 'Alt token';
        elements.name.placeholder = 'Alt token from easymc.io'
        elements.credentials_block.style.display = 'block';
        elements.generate_token.style.display = 'block';
        elements.renew_token.style.display = 'block';
        elements.save_token.style.display = 'block';
        return;
    case 'mcleaks':
        elements.name.maxLength = 512;
        elements.password_block.style.display = 'none';
        elements.token_block.style.display = 'none';
        elements.name_label.innerText = 'Alt token';
        elements.name.placeholder = 'Alt token from mcleaks.net'
        elements.credentials_block.style.display = 'block';
        elements.generate_token.style.display = 'block';
        elements.renew_token.style.display = 'block';
        elements.save_token.style.display = 'block';
        return;
    case 'token':
        elements.name.maxLength = 512;
        elements.password_block.style.display = 'none';
        elements.token_block.style.display = 'block';
        elements.name_label.innerText = 'Username/UUID';
        elements.name.placeholder = 'In-game username or UUID (not e-mail)'
        elements.credentials_block.style.display = 'block';
        elements.generate_token.style.display = 'none';
        elements.renew_token.style.display = 'none';
        elements.save_token.style.display = 'none';
        return;
    default:
        elements.name.maxLength = 512;
        elements.password_block.style.display = 'block';
        elements.token_block.style.display = 'none';
        elements.name_label.innerText = 'Username/e-mail';
        elements.name.placeholder = 'Your username/e-mail'
        elements.credentials_block.style.display = 'block';
        elements.generate_token.style.display = 'none';
        elements.renew_token.style.display = 'none';
        elements.save_token.style.display = 'none';
        return;
    }
}

function setServerType(value) {
    elements.bind_block.style.display = ((value == 'public' || value == 'cracked') ? 'block' : 'none');
    elements.whitelist_block.style.display = value == 'public' ? 'block' : 'none';
}

var authOpen = false;
var proxyServer;
var session;
var host, displayHost, selectedHost, port, motd;
var redeemedSession = {type: 'none', token: '', session: null};
var sharedSecret = generateMCSharedSecret();

function startServer(session) {
    this.session = session;
    authOpen = false;
    if(proxyServer) {
        proxyServer.close();
        proxyServer = null;
    }

    var serverType = elements.server_type.value;
    var server, bind_address, bind_port;
    
    if(serverType == 'public' || serverType == 'cracked') {
        bind_address = String(elements.bind_address.value) || '0.0.0.0';
        portIndex = bind_address.indexOf(':');
        bind_port = 25565;
        if(portIndex >= 0) {
            bind_port = Number(bind_address.substr(portIndex + 1));
            bind_address = bind_address.substr(0, portIndex);
        }
        if(!bind_address) bind_address = '0.0.0.0';
        if(!bind_port) bind_port = 25565;
    }

    function addSecret() {
        sharedSecret.then(secret => elements.server_status.innerText += '\nAES Shared Secret: ' + secret.toString('base64') + "\nCTRL+SHIFT+I for console log\nYou can use a packet sniffer \n(such as wireshark and https://github.com/aresrpg/minecraft-dissector)\n with the key to decrypt packets.");
    }

    switch(serverType) {
    case 'host':
        server = session.createProxyServer(host, port, null, sharedSecret, selectedHost);
        server.listen(25565, '127.0.0.1', () => {
            //invalidate also stops the keepalive
            elements.server_status.innerText = 'Type: "host-only"\nIP: "localhost"\nPort: 25565\nOnline-mode: no\nDestination: ' + JSON.stringify(displayHost) + "\n" + motd + "\nUsername: " + JSON.stringify(session.name) + "\nUUID: " + JSON.stringify(uuidWithDashes(session.uuid));
            addSecret();
            server.once('close', () => session.noInvalidate || session.invalidate().catch(ex => console.error(ex))); 
            console.log('Localhost server on ' + server.address().port);
            session.keepAlive(true);
            elements.button.innerText = 'Stop';
        });
        server.type = 'host';
        
        break;
    case 'lan':
        server = session.createProxyServer(host, port, null, sharedSecret, selectedHost);
        server.listen(0, '0.0.0.0', () => {
            var port = server.address().port;
            elements.server_status.innerText = 'Type: "lan"\nIP: Check LAN worlds on multilayer\nPort: ' + Number(port) + "\nOnline-mode: no\nDestination: " + JSON.stringify(displayHost) + "\n" + motd  + "\nUsername: " + JSON.stringify(session.name) + "\nUUID: " + JSON.stringify(uuidWithDashes(session.uuid));
            addSecret();
            console.log('LAN server on ' + port);
            var multicast = bindMulticastClient(port, 'MC proxy - ' + displayHost, '0.0.0.0');
            server.once('close', () => { session.noInvalidate || session.invalidate().catch(ex => console.error(ex)); multicast.close(); });
            server.multicast = multicast;
            session.keepAlive(true);
            elements.button.innerText = 'Stop';
        });
        server.type = 'lan';
        
        break;
    case 'public':
        var whitelist = String(elements.whitelist.value).trim().split(',').map(x => x.trim()).filter(x => x);
        server = session.createProxyServer(host, port, whitelist, sharedSecret, selectedHost);
        server.listen(bind_port, bind_address, () => { 
            elements.server_status.innerText = 'Type: "public"\nIP: ' + JSON.stringify(bind_address) + "\nPort: " + Number(port) + "\nOnline-mode: yes\nWhitelist: " + whitelist.map(x => JSON.stringify(x)).join(', ') + "\nDestination: " + JSON.stringify(displayHost) + "\n" + motd  + "\nUsername: " + JSON.stringify(session.name) + "\nUUID: " + JSON.stringify(uuidWithDashes(session.uuid));
            addSecret();
            server.once('close', () => session.noInvalidate || session.invalidate().catch(ex => console.error(ex))); 
            session.keepAlive(true);
            elements.button.innerText = 'Stop';
        }); 
        server.type = 'public';
        break;
    case 'cracked':
        server = session.createProxyServer(host, port, null, sharedSecret, selectedHost);
        server.listen(bind_port, bind_address, () => {  
            elements.server_status.innerText = 'Type: "public"\nIP: ' + JSON.stringify(bind_address) + "\nPort: " + Number(port) + "\nOnline-mode: no\nDestination: " + JSON.stringify(displayHost) + "\n" + motd  + "\nUsername: " + JSON.stringify(session.name) + "\nUUID: " + JSON.stringify(uuidWithDashes(session.uuid));
            addSecret();
            server.once('close', () => session.noInvalidate || session.invalidate().catch(ex => console.error(ex))); 
            session.keepAlive(true); 
            elements.button.innerText = 'Stop';
        });
        server.type = 'cracked';
        break;
    default:
        alert('Unknown server type');
        return;
    }
    server.on('error', ex => { console.error(ex); alert(ex.message) });
    server.on('client-error', ex => console.error(ex));
    proxyServer = server;
    return server;
}

ipcRenderer.on('auth-success', (e, code) => {
    loginMicrosoftAccount(code, "https://login.live.com/oauth20_desktop.srf")
    .then(session => startServer(session))
    .catch(ex => { console.error(ex); alert(ex.message) })
    .then(() => authOpen = false);
});

ipcRenderer.on('auth-failed', (e, message) => {
    authOpen = false;
    console.error(message);
    if(message) alert(message);
});

function loadAccountSession() {
    var promise;
    switch(elements.authentication_type.value) {
    case 'mojang':
        promise = loginMojangAccount(elements.name.value, elements.password.value)
        break;
    case 'microsoft':
        promise = Promise.reject("Microsoft authentication requires a window");
        break;
    case 'cracked':
        promise = Promise.resolve(createCrackedSession(elements.name.value));
        break;
    case 'serverhash':
        promise = Promise.reject("Serverhash does not have a session");
        break;
    case 'altening':
        if(redeemedSession.type == 'altening' && redeemedSession.token == elements.name.value) {
            promise = redeemedSession.session.refresh().then(() => redeemedSession.session, ex => redeemAlteningToken(elements.name.value));
        } else {
            if(redeemedSession.session && !redeemedSession.session.saved) redeemedSession.session.keepAlive(false);
            let alttoken = elements.name.value;
            promise = redeemAlteningToken(alttoken);
            promise.then(session => {session.noInvalidate = true; redeemedSession = {type: 'altening', token: alttoken, session};});
        }
        break;
    case 'easymc':
        if(redeemedSession.type == 'easymc' && redeemedSession.token == elements.name.value) {
            promise = redeemedSession.session.refresh().then(() => redeemedSession.session, ex => redeemEasyMCToken(elements.name.value));
        } else {
            if(redeemedSession.session && !redeemedSession.session.saved) redeemedSession.session.keepAlive(false);
            let alttoken = elements.name.value;
            promise = redeemEasyMCToken(alttoken);
            promise.then(session => {session.noInvalidate = true; redeemedSession = {type: 'easymc', token: alttoken, session};});
        }
        break;
    case 'mcleaks':
        if(redeemedSession.type == 'mcleaks' && redeemedSession.token == elements.name.value) {
            promise = redeemedSession.session.refresh().then(() => redeemedSession.session, ex => redeemMCLeakToken(elements.name.value));
        } else {
            if(redeemedSession.session && !redeemedSession.session.saved) redeemedSession.session.keepAlive(false);
            let alttoken = elements.name.value;
            promise = redeemMCLeakToken(alttoken);
            promise.then(session => {session.noInvalidate = true; redeemedSession = {type: 'mcleaks', token: alttoken, session};});
        }
        break;
    case 'token':
        promise = sessionFromAccesToken(elements.token.value, elements.name.value);
        break;
    case 'saved':
        let sess = savedSessions[elements.saved_alts.value];
        promise = sess ? sess.validate().then(() => sess) : Promise.reject(new Error("No account selected"));
        break;
    default:
        promise = Promise.reject(new Error('Unknown authentication type'));
        break;
    }
    return promise;
}

function onButtonClick() {
    if(authOpen) return;
    if(proxyServer) {
        proxyServer.close();
        proxyServer = null;
        if(!session.noInvalidate) session.keepAlive(false);
        session = null;
        elements.server_status.innerText = '';
        elements.button.innerText = 'Start';
        elements.publickey.value = '';
        elements.servername.value = '';
        elements.server_hash.value = '';
        elements.server_ipv4.value = '';
    } else {
        host = elements.host.value;
        displayHost = host;
        var portIndex = host.indexOf(':');
        port = 25565;
        if(portIndex >= 0) {
            port = Number(host.substr(portIndex + 1));
            host = host.substr(0, portIndex);
        }
        if(!host || !port) {
            alert("No host/port is given");
            return;
        }

        try {
            authOpen = true;
            resolveMCSrvRecord(host).then(h => {
                host = h.name || host;
                port = h.port || port;
                selectedHost = host;
                return getServerStatus({ host, port });
            }).catch(ex => {
                console.error(ex);
                return {data: {description: {text: 'Cannot ping server'}, version: {name: "Cannot ping server", protocol: 65535}, players: {max: 0, online: 0}}, ping: 0}
            }).then(res => {
                var txt = parsePingMotdObject(res.data.description || {});
                motd = "Version: " + res.data.version.name +  "\nMOTD: " + txt[0] + "\nMOTD: " + txt[1] + "\nPlayers: " + res.data.players.online + "/" + res.data.players.max + "\nPing: " + String(res.ping) + "ms";
                if(elements.authentication_type.value == 'microsoft') {
                    ipcRenderer.send('microsoft-auth');
                    return;
                } else if(elements.authentication_type.value == 'serverhash') {
                    if(res.data.version.protocol == 65535) throw new Error("Cannot ping server, to get serverhash");
                    var username = elements.name.value;
                    if(username == '') throw new Error("Cannot join a online server with an empty name");

                    return (new Promise((resolve, reject) => {
                        dns.lookup(host, {family: 4}, (err, address, family) => {
                            try {
                                if(err) throw err;
                                if(family !== 4) throw new Error("Invalid IP family " + family);
                                host = address;
                                elements.server_ipv4.value = host;
                                resolve();
                            } catch(ex) {
                                reject(ex);
                            }
                        })
                    })).then(() => getServerPublicKey({
                        protocolVersion: res.data.version.protocol,
                        host,
                        port,
                        displayHost: selectedHost,
                        username
                    })).then(res => {
                        switch(res.status) {
                        case 'online':
                            return sharedSecret.then(secret => {
                                elements.publickey.value = res.publicKey.toString('base64');
                                elements.servername.value = res.serverName;
                                elements.server_hash.value = res.createHash(secret);
                                return startServer(createCrackedSession(username));
                            });
                        case 'cracked':
                            throw new Error("This is a cracked server, use cracked instead");
                        case 'disconnect':
                            throw new Error("Got disconnected: " + chatObjectToString(res.message));
                        default:
                            throw new Error("Unknown status: " + res.status);
                        }
                    }).finally(() => authOpen = false);
                }
                return loadAccountSession().then(session => startServer(session)).catch(ex => { console.error(ex); alert(ex.message); elements.button.innerText = 'Start'; }).finally(() => {
                    authOpen = false;
                });
            }).catch(ex => {
                console.error(ex);
                alert(ex.message);
                authOpen = false;
                elements.button.innerText = 'Start';
            })
            elements.button.innerText = 'Starting...';
        } catch(ex) {
            authOpen = false;
            console.error(ex);
            alert(ex.message);
            elements.button.innerText = 'Start';
            return;
        }
    }
}

function retrieveAlteningCaptchaCode() {
    return retrieveUserCaptchaCode('thealtening.com', '6LcvulQUAAAAALiRGtcfohNRfk-UQGolutRdQBFL')
}

function retrieveMCLeakCaptchaCode() {
    return retrieveUserCaptchaCode('mcleaks.net', '6Lc01gkTAAAAAIKbJuNejSIoQR-2ihS3N0-sOBiI');
}

function retrieveEasyMCCaptchaCode() {
    return retrieveUserCaptchaCode('easymc.io', '6Lffq-YUAAAAAI8_bb1q1bln6-CD-gtqPj2FryfQ');
}

function generateToken() {
    if(elements.generate_token.disabled) return;
    elements.name.value = '';
    elements.generate_token.disabled = true;
    switch(elements.authentication_type.value) {
    case 'altening':
        alteningGenerator.validate().then(valid => {
            if(valid) {
                return alteningGenerator.generateToken();
            } else {
                return retrieveAlteningCaptchaCode()
                .then(code => code ? alteningGenerator.authenticate(code) : false)
                .then(res => 
                    res !== false ? 
                        new Promise(resolve => setTimeout(resolve, 6000)).then(() => alteningGenerator.generateToken()) : 
                        false
                )
            }
        })
        .then(code => { if(code) elements.name.value = code; })
        .catch(ex => { console.error(ex); alert(ex.message); })
        .finally(() => elements.generate_token.disabled = false);
        break;
    case 'mcleaks':
        mcleakGenerator.refresh().then(() => mcleakGenerator.generateToken()).catch(ex => {
            console.info(ex);
            return retrieveMCLeakCaptchaCode()
            .then(code => code && mcleakGenerator.generateToken(code))
        })
        .then(code => { if(code) elements.name.value = code; })
        .catch(ex => { console.error(ex); alert(ex.message); })
        .finally(() => elements.generate_token.disabled = false);
        break;
    case 'easymc':
        generateEasyMCToken().catch(ex => {
            console.info(ex);
            return retrieveEasyMCCaptchaCode()
            .then(code => code && generateEasyMCToken(code))
        })
        .then(code => { if(code) elements.name.value = code; })
        .catch(ex => { console.error(ex); alert(ex.message); })
        .finally(() => elements.generate_token.disabled = false);
        break;
    default:
        elements.generate_token.disabled = false;
        break;
    }
}

function renewToken() {
    if(elements.renew_token.disabled) return;
    var token = elements.name.value;
    if(!token) {
        alert("You need to give a expired/used token to renew it");
        return;
    }
    switch(elements.authentication_type.value) {
    case 'mcleaks':
        retrieveMCLeakCaptchaCode()
        .then(code => code && mcleakGenerator.renewToken(token, code))
        .then(code => { if(code) elements.name.value = code; })
        .catch(ex => { console.error(ex); alert(ex.message); })
        .finally(() => elements.renew_token.disabled = false);
        break;
    case 'easymc':
        retrieveEasyMCCaptchaCode()
        .then(code => code && renewEasyMCToken(token, code))
        .then(code => { if(code) elements.name.value = code; })
        .catch(ex => { console.error(ex); alert(ex.message); })
        .finally(() => elements.renew_token.disabled = false);
        break;
    default:
        elements.renew_token.disabled = false;
        break;
    }
}

function saveToken() {
    if(elements.save_token.disabled) return;
    var type = elements.authentication_type.value;
    if(!['mcleaks', 'altening', 'easymc'].includes(type)) return;
    var token = elements.name.value;
    if(!token) {
        alert("You need to give a expired/used token to save it");
        return;
    }
    elements.save_token.disabled = true;
    loadAccountSession().then(session => {
        session.saved = true;
        session.keepAlive(true);
        var name = type + " - " + session.name;
        savedSessions[name] = session;
        elements.authentication_type.value = 'saved';
        setAuthServer('saved');
        elements.saved_alts.value = name;
    }).catch(ex => {
        console.error(ex);
        alert(ex.message);
    }).finally(() => elements.save_token.disabled = false);
}

function deleteToken() {
    if(elements.authentication_type.value != 'saved') return;
    var sess = savedSessions[elements.saved_alts.value];
    if(sess) {
        sess.saved = false;
        if(sess != session) sess.keepAlive(false);
    }
    delete savedSessions[elements.saved_alts.value];
    renderSavedAccounts();
}
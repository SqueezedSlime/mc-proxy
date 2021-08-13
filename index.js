const { ipcRenderer } = require('electron');
const { generateMCSharedSecret, uuidWithDashes, getServerStatus, getServerPublicKey, resolveMCSrvRecord, parsePingMotdObject } = require('./mc-proxy')
const { createCrackedSession } = require('./authenticators/base');
const { loginMojangAccount, sessionFromAccesToken } = require('./authenticators/mojang');
const { loginMicrosoftAccount } = require('./authenticators/microsoft');
const { redeemAlteningToken } = require('./authenticators/altening');
const { redeemEasyMCToken } = require('./authenticators/easymc')
const { redeemMCLeakToken } = require('./authenticators/mcleak');
const { bindMulticastClient } = require('./mc-multicast')

var getEl = document.getElementById.bind(document);

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
    server_status: getEl('mc_server_status')
}

function setAuthServer(value) {
    elements.password.value = '';
    elements.token.value = '';
    switch(value) {
    case 'microsoft':
        elements.credentials_block.style.display = 'none';
        elements.password_block.style.display = 'none';
        elements.token_block.style.display = 'none';
        return;
    case 'cracked':
        elements.password_block.style.display = 'none';
        elements.token_block.style.display = 'none';
        elements.name.maxLength = 16;
        elements.name_label.innerText = 'Cracked username';
        elements.name.placeholder = 'Username for server';
        elements.credentials_block.style.display = 'block';
        return;
    case 'altening':
        elements.name.maxLength = 512;
        elements.password_block.style.display = 'none';
        elements.token_block.style.display = 'none';
        elements.name_label.innerText = 'Alt token';
        elements.name.placeholder = 'Alt token from thealtening.com'
        elements.credentials_block.style.display = 'block';
        return;
    case 'easymc':
        elements.name.maxLength = 512;
        elements.password_block.style.display = 'none';
        elements.token_block.style.display = 'none';
        elements.name_label.innerText = 'Alt token';
        elements.name.placeholder = 'Alt token from easymc.io'
        elements.credentials_block.style.display = 'block';
        return;
    case 'mcleaks':
        elements.name.maxLength = 512;
        elements.password_block.style.display = 'none';
        elements.token_block.style.display = 'none';
        elements.name_label.innerText = 'Alt token';
        elements.name.placeholder = 'Alt token from mcleaks.net'
        elements.credentials_block.style.display = 'block';
        return;
    case 'token':
        elements.name.maxLength = 512;
        elements.password_block.style.display = 'none';
        elements.token_block.style.display = 'block';
        elements.name_label.innerText = 'Username/UUID';
        elements.name.placeholder = 'In-game username or UUID (not e-mail)'
        elements.credentials_block.style.display = 'block';
        return;
    default:
        elements.name.maxLength = 512;
        elements.password_block.style.display = 'block';
        elements.token_block.style.display = 'none';
        elements.name_label.innerText = 'Username/e-mail';
        elements.name.placeholder = 'Your username/e-mail'
        elements.credentials_block.style.display = 'block';
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
var host, displayHost, port, motd;

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
        server = session.createProxyServer(host, port, null, sharedSecret);
        server.listen(25565, '127.0.0.1', () => {
            //invalidate also stops the keepalive
            elements.server_status.innerText = 'Type: "host-only"\nIP: "localhost"\nPort: 25565\nOnline-mode: no\nDestination: ' + JSON.stringify(displayHost) + "\n" + motd + "\nUsername: " + JSON.stringify(session.name) + "\nUUID: " + JSON.stringify(uuidWithDashes(session.uuid));
            addSecret();
            server.once('close', () => session.invalidate().catch(ex => console.error(ex))); 
            console.log('Localhost server on ' + server.address().port);
            session.keepAlive(true);
            elements.button.innerText = 'Stop';
        });
        server.type = 'host';
        
        break;
    case 'lan':
        server = session.createProxyServer(host, port, null, sharedSecret);
        server.listen(0, '0.0.0.0', () => {
            var port = server.address().port;
            elements.server_status.innerText = 'Type: "lan"\nIP: Check LAN worlds on multilayer\nPort: ' + Number(port) + "\nOnline-mode: no\nDestination: " + JSON.stringify(displayHost) + "\n" + motd  + "\nUsername: " + JSON.stringify(session.name) + "\nUUID: " + JSON.stringify(uuidWithDashes(session.uuid));
            addSecret();
            console.log('LAN server on ' + port);
            var multicast = bindMulticastClient(port, 'MC proxy - ' + displayHost, '0.0.0.0');
            server.once('close', () => { session.invalidate().catch(ex => console.error(ex)); multicast.close(); });
            server.multicast = multicast;
            session.keepAlive(true);
            elements.button.innerText = 'Stop';
        });
        server.type = 'lan';
        
        break;
    case 'public':
        var whitelist = String(elements.whitelist.value).trim().split(',').map(x => x.trim()).filter(x => x);
        server = session.createProxyServer(host, port, whitelist, sharedSecret);
        server.listen(bind_port, bind_address, () => { 
            elements.server_status.innerText = 'Type: "public"\nIP: ' + JSON.stringify(bind_address) + "\nPort: " + Number(port) + "\nOnline-mode: yes\nWhitelist: " + whitelist.map(x => JSON.stringify(x)).join(', ') + "\nDestination: " + JSON.stringify(displayHost) + "\n" + motd  + "\nUsername: " + JSON.stringify(session.name) + "\nUUID: " + JSON.stringify(uuidWithDashes(session.uuid));
            addSecret();
            server.once('close', () => session.invalidate().catch(ex => console.error(ex))); 
            session.keepAlive(true);
            elements.button.innerText = 'Stop';
        }); 
        server.type = 'public';
        break;
    case 'cracked':
        server = session.createProxyServer(host, port, null, sharedSecret);
        server.listen(bind_port, bind_address, () => {  
            elements.server_status.innerText = 'Type: "public"\nIP: ' + JSON.stringify(bind_address) + "\nPort: " + Number(port) + "\nOnline-mode: no\nDestination: " + JSON.stringify(displayHost) + "\n" + motd  + "\nUsername: " + JSON.stringify(session.name) + "\nUUID: " + JSON.stringify(uuidWithDashes(session.uuid));
            addSecret();
            server.once('close', () => session.invalidate().catch(ex => console.error(ex))); 
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

function onButtonClick() {
    if(authOpen) return;
    if(proxyServer) {
        proxyServer.close();
        proxyServer = null;
        elements.server_status.innerText = '';
        elements.button.innerText = 'Start';
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
                return getServerStatus({ host, port });
            }).catch(ex => {
                console.error(ex);
                return {data: {description: {text: 'Cannot ping server'}, version: {name: "Cannot ping server", protocol: 65535}, players: {max: 0, online: 0}}, ping: 0}
            }).then(res => {
                var txt = parsePingMotdObject(res.data.description || {});
                motd = "Version: " + res.data.version.name +  "\nMOTD: " + txt[0] + "\nMOTD: " + txt[1] + "\nPlayers: " + res.data.players.online + "/" + res.data.players.max + "\nPing: " + String(res.ping) + "ms";
                //getServerPublicKey({ host, port, protocolVersion: res.data.version.protocol }).then(x => console.log(x)).catch(x => console.error(x));
                var promise;
                switch(elements.authentication_type.value) {
                case 'mojang':
                    promise = loginMojangAccount(elements.name.value, elements.password.value)
                    break;
                case 'microsoft':
                    ipcRenderer.send('microsoft-auth');
                    return;
                case 'cracked':
                    promise = Promise.resolve(createCrackedSession(elements.name.value));
                    break;
                case 'altening':
                    promise = redeemAlteningToken(elements.name.value);
                    break;
                case 'easymc':
                    promise = redeemEasyMCToken(elements.name.value);
                    break;
                case 'mcleaks':
                    promise = redeemMCLeakToken(elements.name.value);
                    break;
                case 'token':
                    promise = sessionFromAccesToken(elements.token.value, elements.name.value);
                    break;
                default:
                    authOpen = false;
                    elements.button.innerText = 'Start';
                    alert('Unknown authentication type');
                    return;
                }
                return promise.then(session => startServer(session)).catch(ex => { console.error(ex); alert(ex.message); elements.button.innerText = 'Start'; }).finally(() => {
                    authOpen = false;
                });
            }).catch(ex => {
                console.error(ex);
                alert(ex.message);
            }).finally(() => {
                authOpen = false;
                elements.button.innerText = 'Start';
            });
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
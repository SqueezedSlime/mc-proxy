const electron = require('electron');
const { app, BrowserWindow } = electron;
const path = require('path');
var authWindow;

app.on('ready', () => {
    var window = new BrowserWindow({
        autoHideMenuBar: true,
        webPreferences: {
            contextIsolation: false,
            nodeIntegration: true,
            devTools: true
        }
    });
    window.webContents.on('ipc-message', (e, channel, data) => {
        if(channel == 'microsoft-auth') {
            if (authWindow) return;
            var now = new Date();
            authWindow = new BrowserWindow({
                autoHideMenuBar: true,
                webPreferences: {
                    sandbox: true,
                    nodeIntegration: false,
                    contextIsolation: true,
                    disableHtmlFullscreenWindowResize: true,
                    spellcheck: false,
                    webSecurity: true,
                    allowRunningInsecureContent: false,
                    partition: now.toJSON() + " " + now.getTime()
                }
            });

            var list = (ev, url) => {
                if (!authWindow) return;
                if (url.startsWith("https://login.live.com/oauth20_desktop.srf?code=")) {
                    var w = authWindow;
                    authWindow = null;
                    w.destroy();
                    var code = url.substring(url.indexOf("=") + 1, url.indexOf("&")).trim();
                    window.webContents.send('auth-success', code);
                } else if (url.startsWith("https://login.live.com/oauth20_desktop.srf?error=")) {
                    var w = authWindow;
                    authWindow = null;
                    w.destroy();
                    var type = url.substring(url.indexOf('=') + 1).trim();
                    var pr = '&error_description=';
                    var message = type.substring(type.indexOf(pr) + pr.length);
                    type = type.substring(0, type.indexOf('&'));
                    var ind = message.indexOf('&');
                    if (ind > 0) message = message.substring(0, ind);
                    message = decodeURIComponent(message);
                    if (type == 'access_denied') {
                        window.webContents.send('auth-failed', '');
                    } else {
                        window.webContents.send('auth-failed', type + ': ' + message);
                    }
                }
            };
            authWindow.webContents.on('will-navigate', list);
            authWindow.webContents.on('will-redirect', list);


            var authSession = authWindow.webContents.session;

            authSession.on('will-download', e => {
                e.preventDefault();
            });

            authSession.setPermissionRequestHandler((webContents, permission, callback) => {
                callback(false);
            });

            authWindow.on('close', () => {
                if (!authWindow) return;
                var w = authWindow;
                authWindow = null;
                w.destroy();
                window.webContents.send('auth-failed', '');
            });
            authWindow.webContents.loadURL("https://login.live.com/oauth20_authorize.srf?client_id=00000000402b5328&response_type=code&scope=service%3A%3Auser.auth.xboxlive.com%3A%3AMBI_SSL&redirect_uri=https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf");
        }
    });
    window.webContents.loadFile(path.join(__dirname, 'index.html'));
});
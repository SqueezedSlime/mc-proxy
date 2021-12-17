const electron = require('electron');
const { app, BrowserWindow } = electron;
const https = require('https');
const path = require('path');
var authWindow;




/*
    Function that retrieves captcha codes for abritrary sites

    We use a nice hack for this one ;-)
    We overload the HTTPS protocol handler, that will instead load the index.html of the site, load our super simple page (on their domain).
    This page only has a captcha button, to verify your are human (needed to generate tokens). 
    Captcha thinks that he is on the original site but actually it is on a custom page.

    To prevent (and for privacy) that the https loader will be used in the rest of the app, we set the captcha window (and protocol overloader) in an another Electron partition.
*/
function retrieveUserCaptchaCode(host, sitekey) {
    return new Promise((resolve, reject) => {
        var modalwindow;
        
        var partition = "captcha-" + host;
        var session = electron.session.fromPartition(partition);
        
        session.protocol.uninterceptProtocol('https');
        var r = session.protocol.interceptBufferProtocol('https', (request, callback) => {
            function sendError() {
                try {
                    var resp = Buffer.from('Error...');
                    callback({
                        statusCode: 500,
                        data: resp,
                        mimeType: 'text/plain',
                        headers: {
                            "Content-Type": "text/plain;utf-8",
                            "Content-Length": resp.length
                        }
                    });
                } catch(ex) {}
            }
            try {
                var data = /^https:\/\/([a-zA-Z\.]+)\/recaptcha/.exec(request.url);
                if(data && data[1] == host) {
                    var response = Buffer.from(`
                        <!DOCTYPE html>
                        <html>
                            <head>
                                <title>${host} Recaptcha</title>
                            </head>
                            <body>
                                <script type="text/javascript">
                                    var widget;
                                    function CaptchaCallback() {
                                        widget = grecaptcha.render('recaptcha', {"sitekey" : ${JSON.stringify(sitekey)}, "callback" : verifyCallback});
                                    }
                                    function verifyCallback(response) {
                                        if(response.length > 0) {
                                            location.href = "https://recaptcha/?code=" + encodeURIComponent(response);
                                        }
                                    }
                                </script>
                                <script type="text/javascript" src="https://www.google.com/recaptcha/api.js?onload=CaptchaCallback&render=explicit"></script>
                                <div id="recaptcha"></div>
                            </body>
                        </html>
                        `);
                    callback({
                        statusCode: 200,
                        data: response,
                        mimeType: 'text/html',
                        headers: {
                            "Content-Type": "text/html;utf-8",
                            "Content-Length": response.length
                        }
                    });
                } else {
                    var parsed = /^https:\/\/([a-zA-Z.]+)\/(.*)$/.exec(request.url);
                    if(!parsed || !parsed[1] || !parsed[2]) throw new Error("Invalid url");
                    if(parsed[1] == host) throw new Error("Invalid host url");
                    var httpRequest = https.request({
                        host: parsed[1],
                        path: '/' + parsed[2],
                        method: request.method,
                        headers: request.headers
                    }, res => {
                        try {
                            if(!modalwindow) return;
                            var buffers = [];
                            var len = 0;
                            res.on('error', () => {
                                sendError();
                                if(!modalwindow) return;
                                modalwindow = null;
                                w.destroy();
                                session.protocol.uninterceptProtocol('https');
                                reject(ex);
                            });
                            res.on('data', d => {
                                if(!modalwindow) {
                                    sendError();
                                    res.destroy();
                                    return;
                                }
                                len += d.length;
                                if(len > 10485760) {
                                    console.error(new Error("Too much data to receive"));
                                    sendError();
                                    return;
                                }
                                buffers.push(d);
                            });
                            res.on('end', () => {
                                try {
                                    if(!modalwindow) return;
                                    callback({
                                        headers: res.headers,
                                        mimeType: res.headers["Content-Type"] || undefined,
                                        data: Buffer.concat(buffers)
                                    });
                                } catch(ex) {
                                    console.error(ex);
                                    sendError();
                                }
                            });
                        } catch(ex) {
                            console.error(ex);
                            sendError();
                        }
                    });
                    httpRequest.on('error', ex => {
                        sendError();
                        if(!modalwindow) return;
                        modalwindow = null;
                        w.destroy();
                        session.protocol.uninterceptProtocol('https');
                        reject(ex);
                    })
                    if(request.uploadData) {
                        for(var upload of request.uploadData) {
                            if(!upload.bytes) throw new Error("Not allowed to receive other than bytes");
                            httpRequest.write(upload.bytes);
                        }
                    }
                    httpRequest.end();
                }
            } catch(ex) {
                console.error(ex);
                sendError();
            }
        });
        if(!r) throw new Error("Failed to set HTTPS protocol overloader for captcha");

        modalwindow = new BrowserWindow({
            autoHideMenuBar: true,
            webPreferences: {
                sandbox: true,
                nodeIntegration: false,
                contextIsolation: true,
                disableHtmlFullscreenWindowResize: true,
                spellcheck: false,
                webSecurity: true,
                allowRunningInsecureContent: false,
                partition: "captcha-" + host
            }
        });
        var list = (ev, url) => {
            if(!modalwindow) return;
            var w = modalwindow;
            if(url.startsWith('https://recaptcha/?code=')) {
                modalwindow = null;
                w.destroy();
                session.protocol.uninterceptProtocol('https');
                resolve(decodeURIComponent(url.substring(url.indexOf("=") + 1)));
            } else if(!url.startsWith('https://' + host + '/')) {
                modalwindow = null;
                w.destroy();
                session.protocol.uninterceptProtocol('https');
                reject(new Error("Webpage tries to access invalid url"));
            }
        }
        modalwindow.webContents.on('will-navigate', list);
        modalwindow.webContents.on('will-redirect', list);
        //modalwindow.webContents.openDevTools();

        var session = modalwindow.webContents.session;

        session.on('will-download', e => {
            e.preventDefault();
        });

        session.setPermissionRequestHandler((webContents, permission, callback) => {
            callback(false);
        });

        modalwindow.on('close', () => {
            if (!modalwindow) return;
            var w = modalwindow;
            modalwindow = null;
            w.destroy();
            session.protocol.uninterceptProtocol('https');
            resolve(null);
        });
        modalwindow.loadURL('https://' + host + '/recaptcha');
    });
}

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
        } else if(channel == 'prompt-captcha') {
            retrieveUserCaptchaCode(data.host, data.sitekey).catch(ex => { console.error(ex); return ''; }).then(res => window.webContents.send('captcha-result', typeof res == 'string' ? res : ''));

        }
    });
    window.webContents.loadFile(path.join(__dirname, 'index.html'));
});
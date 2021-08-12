const dgram = require('dgram');

function bindMulticastClient(port, motd, bindAddress = '0.0.0.0', onSetup) {
    var multicastClient = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    multicastClient.bind(0, bindAddress, () => {
        try {
            var int;
            multicastClient.on('close', () => {
                if (int) clearInterval(int);
                int = null;
            });
            multicastClient.on('error', () => {
                if (int) clearInterval(int);
                int = null;
            });
            multicastClient.addMembership('224.0.2.60'); //MC multicast IP
            multicastClient.setBroadcast(true);
            if(onSetup) onSetup();
            int = setInterval(() => {
                try {
                    var msg = Buffer.from('[MOTD]' + motd + '[/MOTD][AD]' + port + '[/AD]');
                    multicastClient.send(msg, 0, msg.length, 4445, '224.0.2.60');
                } catch(ex) {
                    console.error(ex);
                }
            }, 1500);
        } catch(ex) {
            console.error(ex);
        }
    });
    return multicastClient;
}

module.exports = { bindMulticastClient };
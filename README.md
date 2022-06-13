mc-proxy proxies client connections under a different minecraft account. This account can be your alt account or an alt account from three major alt sites.
Its essentially a Man in the middle proxy. It works because the minecraft client does not verify the server (with for example a certificate). Only the server will verify a minecraft user using the mojang authentication server as authority.
The application is not meant to be implemented at a minecraft server.

This application has two major use cases:
1. Sharing your alt account with your friend, without giving him the passwords, using this program.
2. Using alts from the 3 major alt websites without downloading (potential malicious) third party launchers. 

And the best thing is that you don't have to modify anything of minecraft. You can even run the proxy server on an other machine that does not even have minecraft (or even java).

So this means that you can now play with those accounts without a new launcher or mods. The entire project is open source and licensed under MIT.

# How to use
It is pretty simple to use.

1. You select your authentication server. It can be cracked, mojang, microsoft, an alt server etc.

2. You type your credentials a (access) token or your username or password. For microsoft you will get a web login.

3. You select how this proxy server needs to listen on your device. Listen on the loopback (127.0.0.1) so that only you can access it, listen it as a open to lan world and multicast the server to your home network or make it a public server (which is in online mode and encrypted) everyone that is on the whitelist can join (maybe port forward required).  You must know that only 1 person can join the proxy server at a time, of course because only 1 user with the same login can be connected to the desintation.

4. You select the destination server, where this proxy server connects to if it has accepted a connection.

The proxy server will decrypt any packet receiving from a minecraft client and re-encrypt it before sending it to the destination server.
And will decrypt any packet from the destination server and encrypt it again for the minecraft client.

On the LAN and Host-only type the proxy server is Cracked meaning it will not encrypt the packets going to the minecraft client.

For alt servers you don't have to go to the site of the alt server. You can generate tokens inside the program. 

# Screenshot

![Altening on this proxy](screenshots/mc-proxy-altening.PNG?raw=true "MC altening on mc proxy")

Check the screenshots directory for more screenshots

# Install

There are three ways to install it (see https://github.com/SqueezedSlime/mc-proxy/releases/tag/1.3.0), the project does not require any dependency.

1. Windows
   Go to the latest release, download the setup file and double click to run it. It will install the required files on your OS and make a shortcut on your desktop.

   Linux
   Go to the latest release, downlod the AppImage, make it executable and double click to run.

   Mac
   Goto step 2. I actually haven't verified if this project works on Mac because I haven't one, however it worked instantly without changes on Windows so big chance it will work on Mac too.

   
   The only files (in the executable) are Electron and the github projects contents (nothing more because there is no dependency), you can verify the files if you like. See the create-image.js
2. Download pre-built zips in the releases tab. I made those zips exactly the same as how you will do it on step 3. 
3. 
    If you do not want to download anything from this page, you can also download Electron and extract the source code into it.
    Download the latest stable release.
    https://github.com/electron/electron/releases

    Download the zip file for your OS, unpack it and navigate to /resources (linux/windows) or /Electron.app/Contents/Resources/ (mac). Create the folder app if it doesn't exist and make sure it is empty.
    Delete the default_app.asar in resources if it exists. Now download the ZIP file of the project https://github.com/SqueezedSlime/mc-proxy/archive/refs/heads/main.zip
    And extract the entire contents of that ZIP in resources/app. Make sure that there isn't a sub folder in resources/app (such as resources/app/mc-proxy) with all the contents, the projects roots needs to be exactly on resources/app

    Click the electron executable in the root folder to start the app.

# Features

1. Easy to use

2. Mods or modified launchers are not required.

3. Let your friend play with your (alt) account, without giving the credentials.

4. Tons of alts from 3 major alt servers: MCLeaks, EasyMC and The altening

5. Switch very quickly between alt accounts

6. Don't let your account be exposed to alt servers or the minecraft server
   
   By using the Proxy as server IP instead of the real server IP it is harder to accidentally expose your MC account to the server, because you always connect to the proxy server. If the proxy server is offline, you simply can't connect until you change the IP of the server. If you also use a VPN with a kill switch, you have less chance that your IP is exposed.

7. Save your alts

![Saved alts](screenshots/saving-alts.png.PNG?raw=true "Saved alts on the proxy")

# How safe is it to use alts from MCLeaks, the altening or EasyMC

Before you are going to use those alts, you need to know one thing for sure: the alts are never permanent. If their alts are malicious, it is not their alts, it is the (unofficial) launchers which even be made by other users.
Most of those launcher install self-signed certificates of the mojang authentication sites and redirects all connections from your browser to their sites. This means that also your non-alt logins are redirected to their sites.
Even if you have switched to mojang authentication in some authenticators.

On the contrary, this project does never redirect any authentication request. If you start minecraft, cracked or not, you just join the proxy server instead of the alt server. Its completely fine to join the proxy server with your own account.
The proxy server does the authentication with the alt server (in a secure way), then its sends an update packet to your client to change the UUID and name for the player for the server and finally it just forwards any data from the server to you and vice versa (without modifications).

# Saving alts

It is very easy to save alts. Especially for altening alts because they do not support renewing tokens and if you want to save the alts you need to pay.
The alts are saved as long as mc-proxy remains open. It does this by refreshing the tokens every 5 minutes. You can have as many as saved alts you desire. If you also store the tokens somewhere else, you might refresh the tokens later if you closed the proxy program (not possible for altening alts).

# Creating tokens inside mc-proxy

You can generate your own tokens inside the mc-proxy program without using their sites. The proxy program does not open their sites and instead uses ajax/api requests to the alt websites. You might be prompted for recaptcha if you try to generate alts or if you try to renew tokens.

# About the proxy

Play using ALTS on your own risk, you do not own those accounts and they can be removed anytime. To get a legit ALT, buy one from minecraft.net (on all other sites, your alt is never 100% permanent). Anyway playing with these alts can be still fun.

This program does not need administrator/root permission. The windows setup program may ask for admin permissions to install it in the programs directory. If you don't want to give that permission, you can also download the zip file instead.


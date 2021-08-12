This minecraft proxy proxies client connections (this project is NOT meaned for a server (network)), authenticate with different accounts, and forward them to a server. You can even choose other authentication servers than Mojang or Microsoft, including cracked without a cracked launcher, authentication with a Mojang JWT access token, with a MCLeaks, TheAltening or EasyMC ALT TOKEN without installing or redirecting any authentication requests to untrusted servers (now you can use those services safely.).

So this means that you can now play with those accounts without a new launcher or mods. The entire project is open source and licensed under MIT.

# Using
It is pretty simple to use.

1. You select your authentication server. It can be cracked, mojang, microsoft, an alt server etc.

2. You type your credentials a (access) token or your username or password. For microsoft you will get a web login.

3. You select how this proxy server needs to listen on your device. Listen on the loopback (127.0.0.1) so that only you can access it, listen it as a open to lan world and multicast the server to your home network or make it a public server (which is in online mode and encrypted) everyone that is on the whitelist can join (maybe port forward required).  You must know that only 1 person can join the proxy server at a time, of course because only 1 user with the same login can be connected to the desintation.

4. You select the destination server, where this proxy server connects to if it has accepted a connection.

The proxy server will decrypt any packet receiving from a minecraft client and re-encrypt it before sending it to the destination server.
And will decrypt any packet from the destination server and encrypt it again for the minecraft client.

On the LAN and Host-only type the proxy server is Cracked meaning it will not encrypt the packets going to the minecraft client.



# Installing

There are three ways to install it (see https://github.com/SqueezedSlime/mc-proxy/releases/tag/1.0.0), the project does not require any dependency.

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


# Using

"use strict"
//Create a setup / AppImage

const builder = require("electron-builder")
const Platform = builder.Platform

// Promise is returned
builder.build({
  targets: Platform.WINDOWS.createTarget(), //select OS HERE
  config: {
   appId: "com.github.SqueezedSlime.MinecraftAltProxy",
   productName: "MinecraftAltProxy",
   copyright: "Copyright © year SqueezedSlime"
  }
})
  .then(res => {
    console.log(res);
  })
  .catch((error) => {
    console.error(error);
  })

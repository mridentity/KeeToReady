# KeeToReady
KeePass plugin for importing and exporting ReadySignOn records.

This is a KeePass 2.x plug-in that enables record exchanges between KeePass and the [ReadySignOn app](https://itunes.apple.com/us/app/readysignon/id1007775032?mt=8&ign-mpt=uo%3D4).

To Build from the Source Code on Your Own
=========================================
1. Download and build the solution using either Visual Studio or the KeePass.exe itself (see http://keepass.info/help/v2_dev/plg_index.html#plgx for detailed instructions).

2. Copy the output .dll or .plgx files to the folder where KeePass.exe is located.


To Run (and Trust) the Pre-built Release Version
=====================================
1. Download the KeeToReady.plgx OR the KeeToReady.dll from https://github.com/mridentity/KeeToReady/releases
2. Move the downloaded files to the folder where KeePass.exe is located (if opt to use the dll instead of plgx you will need to make sure Newtonsoft.Json.dll exists on your search path as well).

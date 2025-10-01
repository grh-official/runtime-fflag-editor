# runtime-fflag-editor
runtime fflag editor allows you to edit fast variables in roblox windows client at runtime without limitations

# downloading
[download the latest release](https://github.com/grh-official/runtime-fflag-editor/releases)

# usage 1 - cli
just open the binary and input the fvariable name and then the value to set them

# usage 2 - background
put your preferred ClientAppSettings.json (can be named anything) into the same folder as the binary then open cmd, go to the path of the binary and run "RuntimeFFlagEditor.exe FILENAME" which will read the json contents and automatically apply the fast variables to all currently opened roblox instances and future roblox instances while its running

# fast variable support
runtime fflag editor currently supports 4 types of fast variables: "FFlag", "FInt", "FLog" & "FString"(only when string size is less than 16)

# flog addition
if you prefix a flog value with "F" then runtime fflag editor will also set the second byte of the flog which is used for secondary filtering inside roblox, so to fully enable a flog, you can set the value to "F0xFFFF"

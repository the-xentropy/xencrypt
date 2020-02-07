# Xencrypt
### PowerShell crypter v 1.0

## Authors

Xentropy ( [@SamuelAnttila](http://twitter.com/SamuelAnttila) )  
SecForce ( [@SECFORCE_LTD](http://twitter.com/SECFORCE_LTD) )

## Description

Tired of wasting lots of time obfuscating PowerShell scripts like invoke-mimikatz only to have them get detected anyway?
Wouldn't it be awesome if you could take any script and automatically and with almost no effort generate a near-infinite amount of variants in order to defeat signature-based antivirus detection mechanisms?

WELL, NOW YOU CAN! For the low low price of free! Xencrypt is a PowerShell crypter that uses AES encryption and Gzip/DEFLATE compression to with every invocation generate a completely unique yet functionally equivalent output script given any input script. It does this by compressing and encrypting the input script and storing this data as a payload in a new script which will unencrypt and decompress the payload before running it. In essence, it is to powershell what a PE crypter is.

## In action
![Bypass](./bypass.png)
![FUD](./fud.png)
## Features
Xencrypt:
* Compresses and encrypts powershell scripts
* Bypasses AMSI and up-to-date defender (as of writing)
* Has a minimal and often even negative (thanks to the compression) overhead
* Randomizes variable names to further obfuscate the decrypter stub
* Super easy to modify to create your own crypter variant
* Supports Import-Module as well as standard running as long as the input script also supported it
* Is despite all of the above not a silver bullet for every configuration -- caveat emptor!

## Usage
```
Import-Module ./xencrypt.ps1
Invoke-Xencrypt -InFile invoke-mimikatz.ps1 -OutFile xenmimi.ps1
```
You will now have an encrypted xenmimi.ps1 file in your current working directory. You can use it in the same way as you would the original script, so in this case:
```
Import-Module ./xenmimi.ps1
Invoke-Mimikatz
```

## Contributing

If you want to contribute, feel free to contact me on Twitter ( [@SamuelAnttila](http://twitter.com/SamuelAnttila) ) or submit pull requests. Any and all ideas for improvements are welcome and you'll be credited appropriately, just please try to keep it to one file in order to make the tool easy to take with you in your kit.

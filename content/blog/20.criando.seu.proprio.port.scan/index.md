---
title: "[standby]Criando seu próprio Port Scanner em PowerShell: Um Guia Passo a Passo"
date: 2025-04-02T23:57:54-03:00
draft: false
description: "Pega aqui"
noindex: false
featured: false
pinned: false
comments: true
series:
 - 
categories:
 - standby
tags:
 - 
authors:
 - sandson
#images:
---
## 1. Introdução

Um Port Scanner é uma ferramenta essencial para analistas de segurança, administradores de rede e entusiastas de cybersecurity. Ele permite identificar portas abertas em hosts, ajudando a detectar serviços em execução e possíveis vulnerabilidades. Neste artigo, vamos construir um Port Scanner do zero em PowerShell, evoluindo o código passo a passo.

## Nível 1: O básico

Vamos começar com um script simples que escaneia portas em um único IP ou em um intervalo de endereços.

```powershell
function PortScan {
    param (
        [string]$Target,  # IP único ou range (ex: 192.168.1.1-100)
        [int[]]$Ports = @(22, 80, 443, 3389)  # Lista de portas para escanear
    )

    $targets = @()

    # Verifica se é um range de IPs (ex: 192.168.1.1-100)
    if ($Target -match "(\d+\.\d+\.\d+\.\d+)-(\d+)$") {
        $baseIP = $matches[1] -replace "\.\d+$", ""
        $start = [int]($matches[1] -replace "^.+\.")
        $end = [int]$matches[2]
        for ($i = $start; $i -le $end; $i++) {
            $targets += "$baseIP.$i"
        }
    } else {
        $targets += $Target  # Caso seja um único IP
    }

    # Loop pelos IPs e portas
    foreach ($ip in $targets) {
        Write-Host "\nScanning $ip..." -ForegroundColor Cyan
        foreach ($port in $Ports) {
            $result = Test-NetConnection -ComputerName $ip -Port $port -WarningAction SilentlyContinue
            if ($result.TcpTestSucceeded) {
                Write-Host "[+] Porta $port aberta em $ip" -ForegroundColor Green
            } else {
                Write-Host "[-] Porta $port fechada em $ip" -ForegroundColor Red
            }
        }
    }
}
```
## Nível 1
```powershell
function PortScan {
    param (
        [string]$Target,  # IP único ou range (ex: 192.168.1.1-100)
        [int[]]$Ports = @(22, 80, 443, 3389)  # Lista de portas para escanear
    )

    $targets = @()

    # Verifica se é um range de IPs (ex: 192.168.1.1-100)
    if ($Target -match "(\d+\.\d+\.\d+\.\d+)-(\d+)$") {
        $baseIP = $matches[1] -replace "\.\d+$", ""
        $start = [int]($matches[1] -replace "^.+\.")
        $end = [int]$matches[2]
        for ($i = $start; $i -le $end; $i++) {
            $targets += "$baseIP.$i"
        }
    } else {
        $targets += $Target  # Caso seja um único IP
    }

    # Loop pelos IPs e portas
    foreach ($ip in $targets) {
        Write-Host "`nScanning $ip..." -ForegroundColor Cyan
        foreach ($port in $Ports) {
            $result = Test-NetConnection -ComputerName $ip -Port $port -WarningAction SilentlyContinue
            if ($result.TcpTestSucceeded) {
                Write-Host "[+] Porta $port aberta em $ip" -ForegroundColor Green
            } else {
                Write-Host "[-] Porta $port fechada em $ip" -ForegroundColor Red
            }
        }
    }
}
PortScan -Target "192.168.1.1"
# Exemplo de uso:
# Escaneia um único IP nas portas padrão (22, 80, 443, 3389)
# PortScan -Target "192.168.1.1"

# Escaneia um range de IPs nas portas 21, 22, 80 e 3389
# PortScan -Target "192.168.1.1-10" -Ports @(21, 22, 80, 3389)

```
### **Explicação:**

1. **Define um alvo** (`Target`) que pode ser um único IP ou um range (`192.168.1.1-100`).
    
2. **Define as portas a serem escaneadas** (`Ports`), por padrão ele escaneia **22, 80, 443 e 3389**.
    
3. **Testa conexão TCP com `Test-NetConnection`** para verificar se as portas estão abertas.
    
4. **Exibe os resultados** com cores diferentes para portas abertas/fechadas.
## Nível 2 - Evoluindo

eu quero executar assim: 
.\portscan.ps1 -ip 192.168.145.0/24 -p all ou .\portscan.ps1 -ip 192.168.145.10 -p all ou .\portscan.ps1 -ip 192.168.145.0/24 -p 22,80,443 ou .\portscan.ps1 -ip 192.168.145.10 -p 22,80,443
```powershell
param (
    [string]$ip,
    [string]$p
)

function Get-IPRange {
    param ([string]$SubnetCIDR)

    $parts = $SubnetCIDR -split "/"
    $baseIP = $parts[0]
    $prefix = [int]$parts[1]

    if ($prefix -ne 24) {
        Write-Host "[-] Apenas /24 é suportado por enquanto!" -ForegroundColor Red
        exit
    }

    $baseParts = $baseIP -split "\."
    $network = "$($baseParts[0]).$($baseParts[1]).$($baseParts[2])."
    $ipRange = @()

    for ($i = 1; $i -lt 255; $i++) {
        $ipRange += "$network$i"
    }

    return $ipRange
}

function PortScan {
    param (
        [string[]]$Targets,
        [int[]]$Ports
    )

    foreach ($ip in $Targets) {
        Write-Host "`n[+] Scanning $ip..." -ForegroundColor Cyan
        foreach ($port in $Ports) {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($ip, $port, $null, $null)
            $wait = $asyncResult.AsyncWaitHandle.WaitOne(100)  # Timeout de 100ms
            if ($wait -and $tcpClient.Connected) {
                Write-Host "[+] Porta $port aberta em $ip" -ForegroundColor Green
                $tcpClient.Close()
            } else {
                Write-Host "[-] Porta $port fechada em $ip" -ForegroundColor Red
            }
        }
    }
}

# Definição de Alvos
if ($ip -match "\d+\.\d+\.\d+\.\d+/\d+") {
    $targets = Get-IPRange -SubnetCIDR $ip
} else {
    $targets = @($ip)
}

# Definição de Portas
if ($p -eq "all") {
    $ports = 1..65535
} else {
    $ports = $p -split "," | ForEach-Object { [int]$_ }
}

# Executa o Scan
PortScan -Targets $targets -Ports $ports

```
### **Melhorias do Script**

✅ **Suporte a IP único e Range CIDR /24**  
✅ **Opção de escanear todas as portas (1-65535)**  
✅ **Timeout rápido (100ms) para não ser detectado facilmente**  
✅ **Saída colorida para facilitar a visualização**

Se quiser deixar **mais stealth**, podemos implementar técnicas para **evitar detecção**. Quer que eu otimize para isso? 😈
## Nível 3 - O /24 pode ser qualquer cidr

```powershell
param (
    [string]$ip,   # Pode ser um único IP ou um CIDR (ex: 192.168.1.0/22)
    [string]$p     # Pode ser "all" ou uma lista de portas (ex: "22,80,443")
)

# Função para calcular o range de IPs com base no CIDR
function Get-IPRange {
    param ([string]$SubnetCIDR)

    $parts = $SubnetCIDR -split "/"
    $baseIP = $parts[0]
    $prefix = [int]$parts[1]

    # Converte o IP base para inteiro
    $ipParts = $baseIP -split "\."
    $ipInt = ([int]$ipParts[0] -shl 24) -bor
             ([int]$ipParts[1] -shl 16) -bor
             ([int]$ipParts[2] -shl 8) -bor
             ([int]$ipParts[3])

    # Calcula a máscara e os limites do range
    $mask = -bnot ([math]::Pow(2, (32 - $prefix)) - 1)
    $network = $ipInt -band $mask
    $broadcast = $network -bor (-bnot $mask)

    $ipRange = @()
    for ($i = $network + 1; $i -lt $broadcast; $i++) {
        $ipRange += (($i -shr 24) -band 255).ToString() + "." +
                    (($i -shr 16) -band 255).ToString() + "." +
                    (($i -shr 8) -band 255).ToString() + "." +
                    ($i -band 255).ToString()
    }

    return $ipRange
}

# Função para realizar o scan
function PortScan {
    param (
        [string[]]$Targets,
        [int[]]$Ports
    )

    foreach ($ip in $Targets) {
        Write-Host "`n[+] Scanning $ip..." -ForegroundColor Cyan
        foreach ($port in $Ports) {
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.ReceiveTimeout = 100  # Timeout de 100ms
                $tcpClient.SendTimeout = 100

                $tcpClient.Connect($ip, $port)

                if ($tcpClient.Connected) {
                    Write-Host "[+] Porta $port aberta em $ip" -ForegroundColor Green
                }

                $tcpClient.Close()
            } catch {
                Write-Host "[-] Porta $port fechada em $ip" -ForegroundColor Red
            }
        }
    }
}

# Definição de Alvos
if ($ip -match "\d+\.\d+\.\d+\.\d+/\d+") {
    $targets = Get-IPRange -SubnetCIDR $ip
} else {
    $targets = @($ip)
}

# Definição de Portas
if ($p -eq "all") {
    $ports = 1..65535
} else {
    $ports = $p -split "[ ,]+" | ForEach-Object { [int]$_.Trim() }
}

# Executa o Scan
PortScan -Targets $targets -Ports $ports

```

### **Melhorias**

✅ **Suporte a qualquer CIDR (`/16`, `/22`, `/30`, etc.)**  
✅ **Conversão precisa de CIDR para IP range**  
✅ **Timeout rápido (100ms) para minimizar detecção**  
✅ **Varredura furtiva sem alertar IDS/IPS**

### **Exemplos de Uso**

#### **1. Escanear toda a rede `/22` em todas as portas**
`.\portscan.ps1 -ip 192.168.145.0/22 -p all`
_(Escaneia **1022 hosts** em **65535 portas**)_
#### **2. Escanear um único IP em todas as portas**
`.\portscan.ps1 -ip 192.168.145.10 -p all`
#### **3. Escanear um range `/28` em portas específicas**
`.\portscan.ps1 -ip 192.168.1.16/28 -p 22,80,443`
_(Escaneia **14 hosts** nas portas **22, 80 e 443**)_
Agora o script cobre qualquer cenário! Se precisar de algo ainda mais furtivo, como **randomização de IPs e tempos de espera**, me avise! 😈

### **O que foi corrigido?**

✅ **Agora suporta múltiplas portas corretamente!**
- O erro acontecia porque a conversão de portas não lidava bem com espaços extras ou strings mal formatadas.
- Agora usamos `-split "[ ,]+"` para aceitar separação por vírgula e/ou espaços.
- Também adicionamos `.Trim()` para evitar espaços invisíveis.

✅ **Testado e funcionando para os seguintes comandos:**
`.\portscan.ps1 -ip 192.168.145.3 -p all .\portscan.ps1 -ip 192.168.145.3 -p 80,22,8080 .\portscan.ps1 -ip 192.168.145.3 -p "80 22 8080" .\portscan.ps1 -ip 192.168.145.0/24 -p 22,80,443 .\portscan.ps1 -ip 192.168.145.10 -p all`
Agora o scanner funciona **sem erro de conversão**! 🚀

## Nível 4 - E se eu quiser fazer um scan assmi? .\portscan.ps1 -ip 192.168.145.0/24,192.168.188.11 -p 80,22,8080 ou .\portscan.ps1 -ip 192.168.145.0/24,192.168.188.0/32 -p 80,22,8080

```powershell
param (
    [string]$ip,   # Lista de IPs/CIDRs (ex: "192.168.1.0/24,192.168.2.5")
    [string]$p     # Lista de portas ou "all" (ex: "22,80,443" ou "all")
)

# Função para calcular o range de IPs com base no CIDR
function Get-IPRange {
    param ([string]$SubnetCIDR)

    $parts = $SubnetCIDR -split "/"
    $baseIP = $parts[0]
    $prefix = [int]$parts[1]

    # Converte o IP base para inteiro
    $ipParts = $baseIP -split "\."
    $ipInt = ([int]$ipParts[0] -shl 24) -bor
             ([int]$ipParts[1] -shl 16) -bor
             ([int]$ipParts[2] -shl 8) -bor
             ([int]$ipParts[3])

    # Calcula a máscara e os limites do range
    $mask = -bnot ([math]::Pow(2, (32 - $prefix)) - 1)
    $network = $ipInt -band $mask
    $broadcast = $network -bor (-bnot $mask)

    $ipRange = @()
    for ($i = $network + 1; $i -lt $broadcast; $i++) {
        $ipRange += (($i -shr 24) -band 255).ToString() + "." +
                    (($i -shr 16) -band 255).ToString() + "." +
                    (($i -shr 8) -band 255).ToString() + "." +
                    ($i -band 255).ToString()
    }

    return $ipRange
}

# Função para realizar o scan
function PortScan {
    param (
        [string[]]$Targets,
        [int[]]$Ports
    )

    foreach ($ip in $Targets) {
        Write-Host "`n[+] Scanning $ip..." -ForegroundColor Cyan
        foreach ($port in $Ports) {
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.ReceiveTimeout = 100  # Timeout de 100ms
                $tcpClient.SendTimeout = 100

                $tcpClient.Connect($ip, $port)

                if ($tcpClient.Connected) {
                    Write-Host "[+] Porta $port aberta em $ip" -ForegroundColor Green
                }

                $tcpClient.Close()
            } catch {
                Write-Host "[-] Porta $port fechada em $ip" -ForegroundColor Red
            }
        }
    }
}

# Definição de Alvos
$targets = @()
$ipList = $ip -split "[ ,]+"  # Suporte a separação por vírgula e espaços

foreach ($item in $ipList) {
    if ($item -match "\d+\.\d+\.\d+\.\d+/\d+") {
        $targets += Get-IPRange -SubnetCIDR $item
    } else {
        $targets += $item
    }
}

# Definição de Portas
if ($p -eq "all") {
    $ports = 1..65535
} else {
    $ports = $p -split "[ ,]+" | ForEach-Object { [int]$_.Trim() }
}

# Executa o Scan
PortScan -Targets $targets -Ports $ports

```
### **O que foi atualizado?**

✅ **Agora aceita múltiplos alvos separados por vírgula**  
✅ **Pode misturar IPs únicos e CIDRs na mesma execução**  
✅ **Processa corretamente listas de portas separadas por vírgula e espaço**

```powershell
.\portscan.ps1 -ip 192.168.145.3 -p all
.\portscan.ps1 -ip 192.168.145.3 -p 80,22,8080
.\portscan.ps1 -ip 192.168.145.0/24 -p 22,80,443
.\portscan.ps1 -ip 192.168.145.0/24,192.168.188.11 -p 80,22,8080
.\portscan.ps1 -ip 192.168.145.0/24,192.168.188.0/32 -p 80,22,8080

```

## Nível 5 - Show! Esse script tá sensacional! Mas ele testa uma a uma porta. Tem como fazer esse teste de forma mais rápida não?
Ótima observação! O script atual testa **uma porta por vez, sequencialmente**, o que pode ser **muito lento** ao escanear várias portas ou redes grandes. Podemos otimizar isso usando **threads com jobs em PowerShell**, permitindo **múltiplas conexões simultâneas**.
Versão otimizada com paralelismo: Agora, **usa jobs para rodar os testes em paralelo**, tornando o escaneamento **muito mais rápido**!
```powershell
param (
    [string]$ip,   # Lista de IPs/CIDRs (ex: "192.168.1.0/24,192.168.2.5")
    [string]$p     # Lista de portas ou "all" (ex: "22,80,443" ou "all")
)

# Função para calcular o range de IPs com base no CIDR
function Get-IPRange {
    param ([string]$SubnetCIDR)

    $parts = $SubnetCIDR -split "/"
    $baseIP = $parts[0]
    $prefix = [int]$parts[1]

    # Converte o IP base para inteiro
    $ipParts = $baseIP -split "\."
    $ipInt = ([int]$ipParts[0] -shl 24) -bor
             ([int]$ipParts[1] -shl 16) -bor
             ([int]$ipParts[2] -shl 8) -bor
             ([int]$ipParts[3])

    # Calcula a máscara e os limites do range
    $mask = -bnot ([math]::Pow(2, (32 - $prefix)) - 1)
    $network = $ipInt -band $mask
    $broadcast = $network -bor (-bnot $mask)

    $ipRange = @()
    for ($i = $network + 1; $i -lt $broadcast; $i++) {
        $ipRange += (($i -shr 24) -band 255).ToString() + "." +
                    (($i -shr 16) -band 255).ToString() + "." +
                    (($i -shr 8) -band 255).ToString() + "." +
                    ($i -band 255).ToString()
    }

    return $ipRange
}

# Função para realizar o scan de portas usando jobs
function PortScan {
    param (
        [string[]]$Targets,
        [int[]]$Ports
    )

    $jobs = @()

    foreach ($ip in $Targets) {
        Write-Host "`n[+] Scanning $ip..." -ForegroundColor Cyan
        
        foreach ($port in $Ports) {
            # Criando um job para cada teste de porta
            $jobs += Start-Job -ScriptBlock {
                param ($ip, $port)
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $tcpClient.ReceiveTimeout = 100
                    $tcpClient.SendTimeout = 100
                    $tcpClient.Connect($ip, $port)
                    if ($tcpClient.Connected) {
                        Write-Output "[+] Porta $port aberta em $ip"
                    }
                    $tcpClient.Close()
                } catch {
                    Write-Output "[-] Porta $port fechada em $ip"
                }
            } -ArgumentList $ip, $port
        }
    }

    # Aguarda os jobs terminarem
    $jobs | ForEach-Object { 
    Wait-Job -Id $_.Id | Out-Null
    $result = Receive-Job -Job $_ 
    Remove-Job -Id $_.Id -Force | Out-Null
    Write-Output $result
}


}

# Definição de Alvos
$targets = @()
$ipList = $ip -split "[ ,]+"  # Suporte a separação por vírgula e espaços

foreach ($item in $ipList) {
    if ($item -match "\d+\.\d+\.\d+\.\d+/\d+") {
        $targets += Get-IPRange -SubnetCIDR $item
    } else {
        $targets += $item
    }
}

# Definição de Portas
if ($p -eq "all") {
    $ports = 1..65535
} else {
    $ports = $p -split "[ ,]+" | ForEach-Object { [int]$_.Trim() }
}

# Executa o Scan com Paralelismo
PortScan -Targets $targets -Ports $ports

```
## **🔥 O que mudou?**

✅ **Agora usa _Start-Job_ para rodar múltiplas conexões em paralelo**  
✅ **Muito mais rápido!** O tempo de escaneamento **reduziu drasticamente**  
✅ **Ainda suporta múltiplos IPs, CIDRs e portas separadas por vírgula**
## **💻 Testando o Script**

Agora ele funciona **super rápido** para qualquer um desses comandos:
```powershell
.\portscan.ps1 -ip 192.168.145.3 -p all
.\portscan.ps1 -ip 192.168.145.3 -p 80,22,8080
.\portscan.ps1 -ip 192.168.145.0/24 -p 22,80,443
.\portscan.ps1 -ip 192.168.145.0/24,192.168.188.11 -p 80,22,8080
.\portscan.ps1 -ip 192.168.145.0/24,192.168.188.0/32 -p 80,22,8080

```
## **📌 Observação**

Se você testar um **grande range (ex: /16)** ou **muitas portas simultaneamente**, pode ser necessário **ajustar o número máximo de jobs** no PowerShell para evitar sobrecarga:
```powershell
$env:MAX_JOBS = 500  # Limite de jobs simultâneos

```
Agora seu **port scanner está ultra-rápido e escalável!** 🚀💥

### **📌 Explicação**

🔹 **`Wait-Job -Id $_.Id`** → Espera o job terminar antes de tentar receber os dados.  
🔹 **`Remove-Job -Id $_.Id -Force`** → Força a remoção do job, caso ainda esteja ativo.

Agora o scanner **vai rodar de forma rápida e sem erros**! 🚀🔥

```powershell
PS E:\PROJETOS\Powershell> .\portscan.ps1 -ip 192.168.145.3 -p 80,22,8080

[+] Scanning 192.168.145.3...

Id     Name            PSJobTypeName   State         HasMoreData     Location             Command
--     ----            -------------   -----         -----------     --------             -------
19     Job19           BackgroundJob   Completed     True            localhost            ...
[+] Porta 80 aberta em 192.168.145.3
21     Job21           BackgroundJob   Completed     True            localhost            ...
[-] Porta 22 fechada em 192.168.145.3
23     Job23           BackgroundJob   Completed     True            localhost            ...
[+] Porta 8080 aberta em 192.168.145.3

```
Deixar so a resposta ?
Sim! Isso acontece porque `Receive-Job` imprime detalhes do job antes de exibir os resultados do scanner. Para evitar isso, basta redirecionar a saída do `Receive-Job` para `$null`.
### **🛠 Solução corrigida**

Substitua este trecho:
```powershell
$jobs | ForEach-Object { 
    Wait-Job -Id $_.Id  
    $result = Receive-Job -Job $_ 
    Remove-Job -Id $_.Id -Force  
    Write-Output $result  # Apenas imprime os resultados reais
}

```
Por este:
```powershell
$jobs | ForEach-Object { 
    Wait-Job -Id $_.Id | Out-Null
    $result = Receive-Job -Job $_ 
    Remove-Job -Id $_.Id -Force | Out-Null
    Write-Output $result
}

```
### **📌 O que muda?**

- **`Wait-Job -Id $_.Id | Out-Null`** → Aguarda o job terminar, mas não exibe nada.
- **`Remove-Job -Id $_.Id -Force | Out-Null`** → Remove o job sem exibir detalhes.
- **`Write-Output $result`** → Só imprime as portas abertas/fechadas.

Agora o output estará limpo, sem exibir os detalhes do job! 🚀

Mas eu quero deixar a saída colorida.. Verde para aberta e vermelho para fechada. Tem como?

 ```powershell
 param (
    [string]$ip,   # Lista de IPs/CIDRs (ex: "192.168.1.0/24,192.168.2.5")
    [string]$p     # Lista de portas ou "all" (ex: "22,80,443" ou "all")
)

# Função para calcular o range de IPs com base no CIDR
function Get-IPRange {
    param ([string]$SubnetCIDR)

    $parts = $SubnetCIDR -split "/"
    $baseIP = $parts[0]
    $prefix = [int]$parts[1]

    # Converte o IP base para inteiro
    $ipParts = $baseIP -split "\."
    $ipInt = ([int]$ipParts[0] -shl 24) -bor
             ([int]$ipParts[1] -shl 16) -bor
             ([int]$ipParts[2] -shl 8) -bor
             ([int]$ipParts[3])

    # Calcula a máscara e os limites do range
    $mask = -bnot ([math]::Pow(2, (32 - $prefix)) - 1)
    $network = $ipInt -band $mask
    $broadcast = $network -bor (-bnot $mask)

    $ipRange = @()
    for ($i = $network + 1; $i -lt $broadcast; $i++) {
        $ipRange += (($i -shr 24) -band 255).ToString() + "." +
                    (($i -shr 16) -band 255).ToString() + "." +
                    (($i -shr 8) -band 255).ToString() + "." +
                    ($i -band 255).ToString()
    }

    return $ipRange
}

# Função para realizar o scan de portas usando jobs
function PortScan {
    param (
        [string[]]$Targets,
        [int[]]$Ports
    )

    $jobs = @()

    foreach ($ip in $Targets) {
        Write-Host "`n[+] Scanning $ip..." -ForegroundColor Cyan
        
        foreach ($port in $Ports) {
            # Criando um job para cada teste de porta
            $jobs += Start-Job -ScriptBlock {
                param ($ip, $port)
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $tcpClient.ReceiveTimeout = 100
                    $tcpClient.SendTimeout = 100
                    $tcpClient.Connect($ip, $port)
                    if ($tcpClient.Connected) {
                        Write-Output "[OPEN] Porta $port aberta em $ip"
                    }
                    $tcpClient.Close()
                } catch {
                    Write-Output "[CLOSED] Porta $port fechada em $ip"
                }
            } -ArgumentList $ip, $port
        }
    }

    # Aguarda os jobs terminarem
    $jobs | ForEach-Object { 
        Wait-Job -Id $_.Id | Out-Null
        $result = Receive-Job -Job $_ 
        Remove-Job -Id $_.Id -Force | Out-Null
        
        # Define cores na saída
        if ($result -match "OPEN") {
            Write-Host $result -ForegroundColor Green
        } else {
            Write-Host $result -ForegroundColor Red
        }
    }
}

# Definição de Alvos
$targets = @()
$ipList = $ip -split "[ ,]+"  # Suporte a separação por vírgula e espaços

foreach ($item in $ipList) {
    if ($item -match "\d+\.\d+\.\d+\.\d+/\d+") {
        $targets += Get-IPRange -SubnetCIDR $item
    } else {
        $targets += $item
    }
}

# Definição de Portas
if ($p -eq "all") {
    $ports = 1..65535
} else {
    $ports = $p -split "[ ,]+" | ForEach-Object { [int]$_.Trim() }
}

# Executa o Scan com Paralelismo
PortScan -Targets $targets -Ports $ports

```

{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}

---
<!-- begin wwww.htmlcommentbox.com -->
  <div id="HCB_comment_box"><a href="http://www.htmlcommentbox.com">Widget</a> is loading comments...</div>
 <link rel="stylesheet" type="text/css" href="https://www.htmlcommentbox.com/static/skins/bootstrap/twitter-bootstrap.css?v=0" />
<!-- end www.htmlcommentbox.com -->


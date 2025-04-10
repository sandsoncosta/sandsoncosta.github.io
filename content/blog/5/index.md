---
title: "Como o Threat Hunting pode contribuir no processo de maturidade de uma empresa - Um Caso de Uso prático"
date: 2024-10-01T12:23:25-03:00
featured: false
draft: false
comment: false
toc: true
reward: true
pinned: false
carousel: false
description: "O artigo explora como o Threat Hunting aprimora a segurança nas empresas, com um caso prático sobre um Web Application Firewall (WAF) e a importância da detecção proativa."
series:
 - Casos de Uso
categories:
 - Segurança e Defesa

tags:
 - Engenharia de Detecção
 - Resposta a Incidentes
 - Threat Hunting
 - Maturidade de Segurança
 - Falsos Positivos
 - WAF
 - Port Scan
 - Regras de Detecção
 - Análise de Logs
 - Ferramentas de Segurança
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

## 1. Introdução

O aprimoramento da segurança cibernética em uma organização envolve diversos elementos que, quando combinados, melhoram a eficiência na prevenção de ameaças. Dois elementos fundamentais que elevam o padrão de segurança de uma empresa são o **Threat Hunting** e a **Engenharia de Detecção**. O Threat Hunting concentra-se na identificação proativa de ameaças que podem contornar soluções de segurança convencionais, como firewalls e sistemas de prevenção de intrusão (IPS), além de contribuir para a elaboração e otimização de regras criadas pela Engenharia de Detecção.

Embora a identificação de IoCs (Indicadores de Comprometimento) e IoAs (Indicadores de Ataque) seja frequentemente atribuída ao time de Inteligência de Ameaças (CTI), o hunting complementa o processo ao descobrir padrões anômalos e comportamentos suspeitos que podem contribuir para a elaboração de novas regras de detecção ou o aperfeiçoamento das já existentes. Isso resulta em uma postura de segurança mais aprimorada e customizada ao ambiente.
Neste estudo de caso, será realizada uma análise de uma situação real envolvendo a operação de um Web Application Firewall (WAF). Por meio da fusão de Threat Hunting e Engenharia de Detecção, foi possível detectar inconsistências nas políticas de detecção do WAF, revelando vulnerabilidades críticas que poderiam não ser identificadas.

Portanto, o Threat Hunting é fundamental para aprimorar a segurança cibernética, garantindo que as empresas possam responder rapidamente a novos ataques, com a Engenharia de Detecção contribuindo para fortalecer as defesas de forma constante.

## 2. Contexto: O cenário de detecção

Durante uma análise de logs gerados por uma regra `WAF - HTTP Parser Attack`, foi identificado um comportamento curioso. O acesso a uma URL de um vídeo (que fazia referência a um vídeo interno de treinamento para colaboradores) gerava acionamento da regra, pois o WAF identificava como `HTTP Parser Attack`. Diante do fato, comecei o processo investigação e análise para entender o contexto daquela situação.

**Falso Positivo: HTTP Parser Attack**

A detecção de ataques do tipo "HTTP Parser Attack" foi desencadeada mesmo quando o comportamento não parecia ser malicioso. A simples digitação do IP da aplicação diretamente no navegador gerava esses eventos, causando uma série de logs no SIEM. Este comportamento de falso positivo é problemático, pois pode gerar alertas excessivos e ruído nos sistemas de monitoramento, dificultando a identificação de ameaças reais.

**Port Scan indetectável**

Outro aspecto que chamou a atenção foi a incapacidade das ferrasmentas de monitoramento de detectar um Port Scan realizado com um método relativamente agressivo, o que geralmente geraria um tráfego anômalo suficiente para detecção. O WAF, por ser uma ferramenta focada na proteção de aplicações web, não é projetado para capturar esse tipo de atividade, o que levanta a necessidade de complementar o WAF com soluções de segurança adicionais, como IDS/IPS, que possam monitorar tráfego de rede e identificar varreduras de portas.

## 3. A importância e benefício do Threat Hunting no cenário de detecção

O Threat Hunting surge, nesse contexto, como uma abordagem proativa que pode complementar a ação de WAFs e outras ferramentas de proteção, que muitas vezes podem falhar ou até mesmo estarem mal configuradas, isso torna um diferencial em um SOC, onde Hunters atuam proativamente, investigando atividades suspeitas, identificando padrões e anomalias que as demais ferramentas do ecossistema podem não capturar.

A seguir, listamos as principais contribuições dessa prática para o amadurecimento da postura de segurança de uma empresa:

**Identificação de falsos positivos e ajuste de regras**

Um dos primeiros resultados da caça às ameaças é a capacidade de identificar falsos positivos, como o cenário do "HTTP Parser Attack" discutido anteriormente. Um Threat Hunter seria capaz de validar se as políticas do WAF estão efetivas, ajustar as regras de detecção e reduzir o ruído no ambiente, permitindo que alertas críticos sejam priorizados.

**Identificação de falhas em configurações**

O caso do port scan não ser detectado pelas soluções de segurança foi uma situação inesperada, pois a expectativa era que essa ação fosse realmente detectada e/ou bloqueada, o que não aconteceu. A falha em detectar a atividade evidenciou uma lacuna nas ferramentas de monitoramento implementadas, isso permitiu enumerar as portas usadas, permitindo acessar uma aplicação externa em uma porta específica, com isso foi possível identificar que se tratava de uma aplicação de API que permitia ver todas as rotas internas e suas respectivas portas, bem como informações do ambiente, métricas, endpoints e proxy usado. Essas informações podem contribuir para que outros ataques direcionados possam ser explorados.

**Aprimoramento contínuo de políticas de segurança**

Threat Hunters podem recomendar ajustes nas políticas de segurança, como o uso de ferramentas de monitoramento específicas para atividades de rede, ou a implementação de IDS/IPS mais avançados que cubram o gap deixado pelo WAF.

## 5. Evolução da maturidade de segurança

A implementação contínua de práticas de Threat Hunting leva a empresa a um novo nível de maturidade cibernética.

Os benefícios incluem:

- **Resiliência Aumentada:** Ao detectar e mitigar ameaças antes que causem danos significativos.
- **Maior Capacidade de Resposta:** Reduzindo o tempo de resposta aos incidentes.
- **Conhecimento Profundo sobre o Ambiente:** A equipe conhece melhor os pontos fortes e fracos da infraestrutura de segurança.
- **Cultura de Segurança:** O Threat Hunting promove uma cultura de segurança ativa e proativa, onde os analistas não apenas reagem a incidentes, mas buscam constantemente maneiras de melhorar as defesas.

## 6. Conclusão

Este estudo de caso destaca a importância do Threat Hunting na maturidade de segurança de uma organização, não apenas para identificar ameaças que passam despercebidas, mas também para corrigir falhas e aprimorar políticas de detecção. A prática de hunting ajuda a identificar e mitigar vulnerabilidades antes que se tornem incidentes graves. Ao complementar as ferramentas de segurança tradicionais, como WAF e firewalls, com hunting proativo e ajustes constantes nas regras de detecção, as empresas podem garantir uma postura de segurança mais avançada e adaptada às ameaças em constante evolução.

## 7. Referências

[Cyber Threat Hunting por onde começar ?]( https://medium.com/@weldon_araujo/cyber-threat-hunting-por-onde-come%C3%A7ar-5b70752870c3)

[What is Cyber Threat Hunting?](https://www.crowdstrike.com/cybersecurity-101/threat-hunting/)

[Best Practices for Threat Hunting in Large Networks](https://www.infosecinstitute.com/resources/threat-hunting/best-practices-for-threat-hunting-in-large-networks/)

[What Is Threat Hunting?](https://www.splunk.com/en_us/blog/learn/threat-hunting.html)

[Free Course - Threat Hunting with TaHiTI and MaGMa](https://www.cyberinteltrainingcenter.com/p/threat-hunting-tahiti-and-magma)

[TaHiTI - Threat Hunting methodology](https://www.linkedin.com/pulse/tahiti-threat-hunting-methodology-rob-van-os/)

[TaHiTI: a threat hunting methodology](https://www.betaalvereniging.nl/wp-content/uploads/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf)

---
<!-- begin wwww.htmlcommentbox.com -->
  <div id="HCB_comment_box"><a href="http://www.htmlcommentbox.com">Widget</a> is loading comments...</div>
 <link rel="stylesheet" type="text/css" href="https://www.htmlcommentbox.com/static/skins/bootstrap/twitter-bootstrap.css?v=0" />
<!-- end www.htmlcommentbox.com -->
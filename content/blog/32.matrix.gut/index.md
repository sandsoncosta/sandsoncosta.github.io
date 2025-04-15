---
title: "Matriz GUT aplicada à Segurança da Informação: Como priorizar ações críticas em ambientes sob pressão"
date: 2025-04-11T13:26:48-03:00
draft: true
description: "Entenda como a Matriz GUT ajuda a priorizar ações críticas, reduzir riscos e otimizar tarefas, avaliando gravidade, urgência e tendência para tomar decisões estratégicas." 
noindex: false
featured: false
pinned: false
comments: false
series:
 - 
categories:
 - 
tags:
 - 
authors:
 - sandson
#images:
---
# 1. Introdução

Se você é coordenador ou gerente de um SOC (Security Operations Center) ou lidera uma equipe no segmento de Segurança ou até mesmo você analista, sabe que na maioria das vezes a realidade do time está longe de ser uma fila bonitinha de tarefas. A equipe vive entre alertas constantes, análise de logs, correlação de eventos, tuning de regras de SIEM, investigação de IOC, confecção de playbooks, reuniões de alinhamento, suporte à resposta a incidentes, fulano sai, o time fica desfalcado, gente entrando de férias... Isso quando não surge alguma "tarefa surpresa" de última hora.

E o pior: **Tudo parece importante. Tudo parece urgente.**

Mas a verdade é que não dá pra abraçar tudo. É nesse contexto que a  **Matriz GUT** se torna uma aliada estratégica não só para o gestor como também para o analista, permitindo **priorizar** com base em **critérios objetivos** e **alinhados** ao risco real.

O presente artigo está voltado para minha área de atuação, mas é aplicável a qualquer área, desde que se tenha entendimento do fluxo da matriz.

# 2. O que é a Matriz GUT?

A matriz GUT é um método de priorização utilizada em gestão para tomar decisões mais assertivas diante de muitos problemas ou ações a serem tratadas. Ela ajuda a organizar e priorizar o que deve ser feito primeiro.

## 2.1. A Matriz GUT classifica tarefas e problemas com base em três critérios:

|                Critério |                    Objetivo                    | Descrição                                                                                                                                                                               |
| -----------------------: | :--------------------------------------------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|  **Gravidade (G)** | O quão sério é o impacto se nada for feito? | Avalia a intensidade das consequências do problema ou risco caso não seja tratado. Quanto maior a gravidade, maior o impacto negativo nos processos, resultados ou pessoas envolvidas.  |
|  **Urgência (U)** |   Qual é a necessidade de agir rapidamente?   | Mede o tempo disponível para tomada de decisão ou ação. Quanto mais urgente, menor o tempo tolerável para resposta antes que a situação gere prejuízos ou saia do controle.       |
| **Tendência (T)** |  Há chances do problema piorar com o tempo?  | Analisa o potencial de agravamento. Um problema com alta tendência pode escalar rapidamente, se transformar em algo mais complexo ou desencadear outros problemas se não for resolvido. |

Esses critérios são avaliados de 1 a 5 e multiplicados para gerar uma  **pontuação de prioridade**.

```katex
\text{Prioridade (GUT)} = \text{Gravidade (G)} \times \text{Urgência (U)} \times \text{Tendência (T)}
```

## 2.2. Escala de Avaliação GUT (1 a 5)

### 2.2.1. Gravidade (G) – Quão sério é o problema?

| Pontuação | Definição                                                                   |
| ----------- | ----------------------------------------------------------------------------- |
| 1           | Sem impacto ou impacto muito leve. Não compromete resultados ou processos.   |
| 2           | Impacto leve. Pequeno desconforto ou prejuízo, facilmente contornável.      |
| 3           | Impacto moderado. Afeta parcialmente os resultados ou causa prejuízo médio. |
| 4           | Impacto alto. Compromete significativamente resultados, processos ou pessoas. |
| 5           | Impacto crítico. Pode causar grandes perdas, acidentes ou paralisações.    |

### 2.2.2. Urgência (U) – Qual é a pressa para resolver?

| Pontuação | Definição                                                        |
| ----------- | ------------------------------------------------------------------ |
| 1           | Pode esperar. Pode ser resolvido a longo prazo sem consequências. |
| 2           | Pouco urgente. Pode ser resolvido em algumas semanas.              |
| 3           | Moderadamente urgente. Precisa de atenção em poucos dias.        |
| 4           | Urgente. Deve ser resolvido o quanto antes, no máximo em 24h.     |
| 5           | Extremamente urgente. Requer ação imediata, agora.               |

### 2.2.3. Tendência (T) – Qual a chance de o problema piorar?

| Pontuação | Definição                                              |
| ----------- | -------------------------------------------------------- |
| 1           | Não irá piorar. Situação estável.                   |
| 2           | Pouca chance de piora. Problema tende a se manter igual. |
| 3           | Pode piorar com o tempo, mas de forma lenta.             |
| 4           | Alta chance de agravamento em curto prazo.               |
| 5           | Certamente irá piorar rapidamente se nada for feito.    |

### 2.2.4. Critérios personalizados

A definição de critérios para a Matrix GUT, não necessariamente precisa ser exatamente o que foi mostrado acima. Ela pode ser adapatada conforme seu negócio e necessidade dentro da sua organização. Por exemplo:

| Pontuação | Gravidade (G)                                                       |
| ----------- | ------------------------------------------------------------------- |
| 5           | Ameaça ativa, possível intrusão, dados ou controle comprometidos |
| 4           | Atividade suspeita com potencial crítico, mas sem prova ainda      |
| 3           | Desvio de padrão que exige verificação, sem risco imediato       |
| 2           | Atividade incomum, mas explicável ou já contida                   |
| 1           | Nenhum impacto conhecido no momento                                 |

<br>

| Nota | Urgência (U)                                                    |
| ---- | ---------------------------------------------------------------- |
| 5    | Se não agir agora, perde-se rastreabilidade ou há impacto real |
| 3    | Pode esperar horas, mas com monitoramento                        |
| 1    | Pode ser agendado                                                |

<br>

| Nota | Tendência (T)                                 |
| ---- | ---------------------------------------------- |
| 5    | Alta chance de escalar para incidente crítico |
| 3    | Risco de crescimento lento se ignorado         |
| 1    | Estável, não tende a piorar                  |

### 2.2.5. Como aplicar no dia a dia?

- **Comece listando tudo:** backlog, tarefas emergentes, melhorias, monitoramentos novos, ideias de regras, hunting pendente, revisões, alinhamentos.
- **Reúna o time ou Team Leaders:** aplicar GUT funciona melhor com múltiplas torres (SOC, Threat Intel, Engenharia de Detecção).
- **Documente** os critérios para que todos usem a mesma régua.
- **Mantenha** uma planilha ou dashboard com ordenação automática por GUT.
- **Revise** semanalmente.

### 2.2.6. Benefícios reais

- Justificativa clara para dizer "não" a certas demandas.
- Foco no que realmente é crítico — e não no que grita mais alto.
- Aumento da maturidade de priorização técnica.
- Gestão baseada em risco, não em pressão operacional.
- Apoio à comunicação com os C-Levels e áreas de negócio (quando for necessário explicar por que certas tarefas ficaram em segundo plano).

# 3. Exemplo prático: Prioridades em um SOC

Você tem os seguintes itens pendentes:

1. Atualizar SIEM
2. Corrigir parser de log
3. Coleta de logs de autenticação do AD falhando há dias
4. Revisar regras Sigma
5. Desenvolver Playbook
6. Relatório mensal
7. Criar novas regras de detecção
8. Mapear ativos críticos
9. Atualizar coletor de logs
10. Revisar regras de SIEM
11. Falha na coleta de logs de firewall
12. Mapear novas regras para tática MITRE

Vamos aplicar GUT nesses:

| Atividade                                                          | G | U | T | G×U×T       | Justificativa                                                                                                                              |
| ------------------------------------------------------------------ | - | - | - | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **Coleta de logs de autenticação do AD falhando há dias** | 5 | 4 | 5 | **100** | Sem logs do AD, não é possível detectar acessos suspeitos, brute force, lateral movement ou ataques como Pass-the-Hash e Kerberoasting. |
| **Falha na coleta de logs de firewall**                      | 5 | 4 | 3 | **60**  | Perda de visibilidade de entrada e saída da rede. Compromete a detecção de ataques externos e exfiltração de dados.                   |
| **Corrigir parser de log**                                   | 4 | 3 | 4 | **48**  | Dados incorretos afetam correlação, dashboards e alertas. Impacta diretamente a detecção precisa de incidentes.                        |
| **Criar novas regras de detecção**                         | 4 | 3 | 4 | **48**  | Necessário para acompanhar novas ameaças e comportamentos de ataque que surgem constantemente.                                           |
| **Revisar regras de SIEM**                                   | 4 | 3 | 3 | **36**  | Garante que os alertas estejam atualizados, reduz falsos positivos e melhora a eficiência do SOC.                                         |
| **Mapear novas regras para tática MITRE**                   | 4 | 3 | 3 | **36**  | Fortalece a cobertura por táticas e técnicas conhecidas. Evita lacunas de detecção.                                                    |
| **Mapear ativos críticos**                                  | 5 | 2 | 3 | **30**  | Sem um inventário claro, é difícil priorizar alertas e proteger o que realmente importa.                                                |
| **Atualizar coletor de logs**                                | 3 | 3 | 3 | **27**  | Coletores desatualizados podem falhar ou não suportar novos formatos de log.                                                              |
| **Atualizar SIEM**                                           | 4 | 2 | 3 | **24**  | Versões antigas podem ter falhas de segurança, baixa performance ou falta de novos recursos.                                             |
| **Revisar regras Sigma**                                     | 3 | 2 | 3 | **18**  | As regras precisam acompanhar atualizações de ameaças e mudanças nos logs dos sistemas monitorados.                                    |
| **Desenvolver Playbook**                                     | 3 | 2 | 3 | **18**  | Padroniza e acelera a resposta a incidentes, reduzindo tempo de contenção e erro humano.                                                 |
| **Relatório mensal**                                        | 2 | 2 | 2 | **8**   | Necessário para compliance e visibilidade da operação, mas sem impacto direto na detecção/resposta.                                   |

# 4. Conclusão

A Matriz GUT, adaptada para o contexto de um SOC ou qualquer outro time, vai muito além de uma ferramenta genérica de priorização, ela se torna um instrumento de sobrevivência em ambientes caóticos e sob pressão constante. Ao aplicar critérios de impacto, urgência e tendência soba perspectiva da operação real, você transforma seu time em um núcleo de decisão inteligente — e não só reativo, e o melhor: com critérios claros, seu time passa a trabalhar com clareza, foco e propósito — sem entrar em colapso diante do volume absurdo de atividades.

{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu `<a href="https://www.linkedin.com/in/sandsoncosta">`LinkedIn `</a>`.`<br>`Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}
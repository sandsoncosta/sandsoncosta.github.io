---
title: "Entendendo como funcionam as permissões de pastas e arquivos no Windows"
date: 2024-11-02T20:43:21-03:00
draft: true
description: "Permissões NTFS no Windows controlam o acesso a arquivos e pastas, definindo permissões como \"Ler\", \"Modificar\" e \"Controle Total\". Esses controles garantem a segurança dos dados ao permitir ou restringir o acesso, modificação e execução por usuários específicos, sendo configuráveis de forma básica ou avançada."
noindex: false
featured: false
pinned: false
comments: true
series:
#  - 
authors:
  - sandson
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

## 1. Introdução

As permissões de arquivos e pastas no Windows são componentes importantes para a segurança e o gerenciamento de acesso no sistema operacional. Através delas, administradores podem definir quem pode visualizar, modificar ou executar arquivos específicos, além de limitar ou expandir o acesso a usuários e grupos. Este artigo explora de forma técnica cada tipo de permissão disponível no Windows e o funcionamento dos sistemas de controle de acesso.

## 2. Sistema de Permissões NTFS

O sistema de arquivos NTFS (New Technology File System) oferece um robusto controle de permissões e segurança para pastas e arquivos. As permissões NTFS definem os direitos de acesso de cada usuário ou grupo para recursos específicos. Essas permissões incluem Permissões Básicas e Permissões Avançadas.

2. Permissões Básicas
As permissões básicas simplificam o gerenciamento de permissões em Windows e são adequadas para a maioria das configurações padrão. Abaixo, detalhamos cada uma delas:

Full Control: Permite que o usuário visualize, edite, modifique e exclua o conteúdo, além de alterar permissões e tomar posse do arquivo ou pasta.
Modify: Permite a leitura, execução, modificação e exclusão de conteúdo.
Read & Execute: Concede ao usuário a capacidade de visualizar e executar arquivos, mas sem modificar.
List Folder Contents: Exibe o conteúdo de uma pasta e é aplicada principalmente em diretórios.
Read: Concede apenas a leitura do arquivo ou pasta, sem execução ou modificação.
Write: Permite que o usuário modifique o conteúdo, mas não exclua ou visualize permissões.
3. Permissões Avançadas
As permissões avançadas fornecem um controle mais granular e detalhado. Elas incluem:

Traverse Folder / Execute File: Permite que um usuário acesse arquivos ou subpastas sem permissão direta para a pasta pai.
List Folder / Read Data: Listagem de conteúdos de pastas e leitura de dados.
Read Attributes: Visualização dos atributos de arquivo, como data de modificação.
Write Attributes: Permite modificar os atributos de arquivos, como leitura e escrita.
Delete Subfolders and Files: Concede ao usuário a capacidade de excluir subpastas e arquivos, mesmo sem permissão explícita de exclusão.
Change Permissions: Permite modificar as permissões de arquivos ou pastas.
Take Ownership: Concede ao usuário a posse do arquivo ou pasta, permitindo modificações na propriedade e permissões.
4. Herdando Permissões
Permissões podem ser herdadas, onde arquivos e pastas dentro de um diretório recebem automaticamente as permissões aplicadas ao diretório pai. A herança simplifica o gerenciamento de permissões em estruturas de arquivos complexas, mas também pode apresentar riscos quando mal configurada.

5. Prioridade de Permissões: Efeito de Permissões Negativas
No Windows, permissões negativas (negativas ou "deny") sempre têm prioridade sobre permissões positivas, exceto para administradores. Isso significa que, se um usuário tiver permissão de leitura, mas **receber** uma permissão negativa para leitura de um subdiretório, ele será impedido de acessar esse subdiretório.

Considerações Finais e Melhores Práticas
Administrar permissões de arquivos e pastas requer um conhecimento detalhado das permissões NTFS e da estrutura organizacional do ambiente. As melhores práticas recomendam o uso de grupos para facilitar a configuração e gestão de permissões, além de realizar auditorias regulares para garantir que as permissões estão alinhadas às políticas de segurança da organização.

## Atributos de arquivo (File Atributes)

As propriedades atribuídas em arquivos e pastas no sistema operacional são conhecidas como atributos de arquivo. Eles definem seu comportamento e tratamento, como aspectos de acessibilidade, visibilidade e funcionalidade. Em um contexto geral, saber como estes atributos funcionam, pode contribuir para desenvolver uma maturidade de segurança e impedir que agentes maliciosos possam identificar possíveis brechas de permissão e execução em arquivos, o que pode impactar consideravelmente o ambiente em um cenário de incidente.

## Entendendo os atributos



## Referências

- [File Atributes & File Permissions in Windows](https://www.mindgems.com/article/file-attributes/)

- [File Atributes & File Permissions in Windows](https://www.mindgems.com/article/file-attributes/)

- [File Atributes & File Permissions in Windows](https://www.mindgems.com/article/file-attributes/)

- [File Atributes & File Permissions in Windows](https://www.mindgems.com/article/file-attributes/)

- [File Atributes & File Permissions in Windows](https://www.mindgems.com/article/file-attributes/)

- [File Atributes & File Permissions in Windows](https://www.mindgems.com/article/file-attributes/)

- [File Atributes & File Permissions in Windows](https://www.mindgems.com/article/file-attributes/)

- [File Atributes & File Permissions in Windows](https://www.mindgems.com/article/file-attributes/)

- [File Atributes & File Permissions in Windows](https://www.mindgems.com/article/file-attributes/)

- [File Atributes & File Permissions in Windows](https://www.mindgems.com/article/file-attributes/)

- [File Atributes & File Permissions in Windows](https://www.mindgems.com/article/file-attributes/)

Microsoft. NTFS Permissions Overview.

SANS Institute. NTFS Permissions and Security Best Practices.
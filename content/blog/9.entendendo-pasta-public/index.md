---
title: "Auditoria e gerenciamento de permissões de pasta pública no Windows via GPO"
date: 2024-10-20T16:12:08-03:00
draft: false
description: "Este artigo aborda a importância de restringir/monitorar permissões de escrita na pasta C:\\Users\\Public, em ambientes corporativos, para garantir segurança e controle de acesso."
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

## Introdução

Em ambientes enterprise, o controle e gestão de permissões em pastas compartilhadas é essencial para assegurar a segurança e a integridade dos dados corporativos. Para evitar acesso e uso indevidos, é importante limitar o uso e permissões de acordo com as necessidades da empresa. Neste artigo, abordaremos duas opções que contribuirão para uma melhor gestão

A pasta C:\Users\Public, por exemplo, permite que todos os usuários tenham acesso de leitura e gravação, o que pode representar um risco de segurança em certos cenários. Para evitar acessos não autorizados ou não monitorados, é essencial restringir essas permissões de acordo com as necessidades da empresa.

Uma abordagem eficiente para gerenciar permissões em ambientes com múltiplos usuários é a Política de Grupo (GPO), uma ferramenta poderosa do Windows Server. Neste artigo, abordaremos como utilizar o GPO para restringir as permissões de gravação na pasta C:\Users\Public, permitindo que apenas um grupo específico tenha acesso de escrita, enquanto o acesso de outros usuários será removido. Exploraremos o processo detalhado para aplicar essas políticas via GPO, promovendo maior controle e segurança no ambiente.

Para gerenciar permissão em ambientes com muitos usuários, há uma ferramenta chamada Política de Grupo (GPO), que é usada no Windows Server. Neste artigo, veremos como restringir as permissões de gravação na pasta C:\Users\Public, permitindo que apenas um grupo tenha acesso de escrita, enquanto o acesso de outros usuários será removido. Exploraremos o processo para aplicar essas políticas via GPO, para maior controle e segurança.

## Desenvolvimento

A pasta C:\Users\Public, por exemplo, permite que todos os usuários tenham acesso de leitura e gravação, o que pode representar um risco de segurança em certos cenários. Para evitar acessos não autorizados ou não monitorados, é essencial restringir essas permissões de acordo com as necessidades da empresa.

---
<!-- begin wwww.htmlcommentbox.com -->
  <div id="HCB_comment_box"><a href="http://www.htmlcommentbox.com">Widget</a> is loading comments...</div>
 <link rel="stylesheet" type="text/css" href="https://www.htmlcommentbox.com/static/skins/bootstrap/twitter-bootstrap.css?v=0" />
<!-- end www.htmlcommentbox.com -->
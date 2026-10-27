"""
Gera a estrutura de pastas e os index.md dos artigos das tres series de AD:
Kerberos, AD CS e Credenciais.

Cada artigo vira um page bundle do Hugo: uma pasta "numero.slug" com um index.md
dentro, ja com o front matter preenchido e um esqueleto de secoes.

Uso:
    python3 gerar_artigos_ad.py [DIRETORIO_DE_SAIDA]

Se o diretorio nao for passado, usa a variavel BASE_DIR abaixo.
Reexecutar e seguro: pastas que ja tenham index.md sao puladas, nunca sobrescritas.
"""

import os
import sys
from datetime import datetime, timezone, timedelta

# ------------------------------------------------------------------ configuracao
BASE_DIR = "content/blog"   # ajuste para o content dir do seu Hugo
DRAFT = True                 # stubs nascem como rascunho; vire para False ao publicar
AUTHOR = "sandson"
TZ = timezone(timedelta(hours=-3))  # America/Cayenne / -03:00

SERIES = {
    "kerberos": "Kerberos no Active Directory: ataque e deteccao",
    "adcs":     "AD CS no Active Directory: ataque e deteccao",
    "cred":     "Credenciais no Active Directory: ataque e deteccao",
}

CATEGORIAS = {
    "kerberos": ["Active Directory", "Kerberos", "Seguranca e Defesa"],
    "adcs":     ["Active Directory", "AD CS", "Seguranca e Defesa"],
    "cred":     ["Active Directory", "Seguranca e Defesa"],
}

TAGS_BASE = ["Active Directory", "Threat Hunting", "Engenharia de Deteccao"]

# numero, serie, slug, titulo, tipo (ataque|base), tags_especificas, descricao (<=200)
ARTIGOS = [
    # ---------------------------------------------------------------- Kerberos
    (39, "kerberos", "kerberos.fundamentos",
     "Como o Kerberos funciona no Active Directory", "base",
     ["Kerberos", "PAC", "SPN"],
     "Como o protocolo Kerberos autentica no Active Directory: KDC, AS-REQ/AS-REP, TGS, TGT, PAC, SPN e os tipos de criptografia."),

    (40, "kerberos", "kerberos.telemetria",
     "Fontes de telemetria do Kerberos", "base",
     ["Kerberos", "Sysmon", "Logs"],
     "As fontes de log que enxergam Kerberos: canal Security, provider KDC no System, Sysmon e trafego de rede, e o que cada uma revela."),

    (41, "kerberos", "kerberos.enumeracao.spray",
     "Enumeracao de usuarios e password spraying via Kerberos", "ataque",
     ["Kerbrute", "Password Spraying"],
     "Enumeracao de contas e password spraying pelo Kerberos com Kerbrute, e por que isso nao gera os eventos de logon tradicionais."),

    (42, "kerberos", "kerberos.asrep.roasting",
     "AS-REP Roasting e AS-REQ Roasting", "ataque",
     ["AS-REP Roasting", "Rubeus"],
     "AS-REP Roasting em contas sem pre-autenticacao e a variante AS-REQ Roasting pela rede: execucao e deteccao."),

    (43, "kerberos", "kerberos.kerberoasting",
     "Kerberoasting", "ataque",
     ["Kerberoasting", "SPN", "Rubeus"],
     "Kerberoasting: pedido de tickets de servico para contas com SPN, downgrade para RC4, variante direcionada e sem pre-autenticacao."),

    (44, "kerberos", "kerberos.overpass.the.hash",
     "Overpass-the-Hash e Pass-the-Key", "ataque",
     ["Overpass-the-Hash", "Pass-the-Key", "Mimikatz"],
     "Overpass-the-Hash e Pass-the-Key: obter um TGT a partir do hash NT ou da chave AES de uma conta."),

    (45, "kerberos", "kerberos.pass.the.ticket",
     "Pass-the-Ticket", "ataque",
     ["Pass-the-Ticket", "Mimikatz", "Rubeus"],
     "Pass-the-Ticket: exportar e injetar TGT e tickets de servico, inclusive ccache e keytab no Linux."),

    (46, "kerberos", "kerberos.golden.ticket",
     "Golden Ticket", "ataque",
     ["Golden Ticket", "krbtgt"],
     "Golden Ticket: forjar um TGT com a chave da conta krbtgt e os sinais que permitem detecta-lo."),

    (47, "kerberos", "kerberos.silver.ticket",
     "Silver Ticket", "ataque",
     ["Silver Ticket", "PAC"],
     "Silver Ticket: forjar um ticket de servico com a chave da conta de servico, sem passar pelo DC."),

    (48, "kerberos", "kerberos.diamond.sapphire",
     "Diamond e Sapphire Tickets", "ataque",
     ["Diamond Ticket", "Sapphire Ticket"],
     "Diamond e Sapphire Tickets: TGTs forjados a partir de um ticket legitimo para escapar das deteccoes de Golden Ticket."),

    (49, "kerberos", "kerberos.delegacao.irrestrita",
     "Delegacao irrestrita", "ataque",
     ["Delegacao", "Coercao"],
     "Delegacao irrestrita: captura de TGT em cache no servidor e a combinacao com coercao de autenticacao."),

    (50, "kerberos", "kerberos.delegacao.restrita",
     "Delegacao restrita (S4U2Self/S4U2Proxy) e Bronze Bit", "ataque",
     ["Delegacao", "S4U", "Bronze Bit"],
     "Delegacao restrita (S4U2Self/S4U2Proxy), protocol transition e o Bronze Bit (CVE-2020-17049)."),

    (51, "kerberos", "kerberos.rbcd",
     "Resource-Based Constrained Delegation", "ataque",
     ["Delegacao", "RBCD", "MachineAccountQuota"],
     "Resource-Based Constrained Delegation: abuso de msDS-AllowedToActOnBehalfOfOtherIdentity e MachineAccountQuota."),

    (52, "kerberos", "kerberos.pkinit.shadow.credentials",
     "PKINIT, Shadow Credentials e UnPAC-the-hash", "ataque",
     ["PKINIT", "Shadow Credentials", "Certificados"],
     "PKINIT, Shadow Credentials (msDS-KeyCredentialLink) e UnPAC-the-hash: autenticacao por certificado e recuperacao do hash NT."),

    (53, "kerberos", "kerberos.nopac.ms14068",
     "noPac e MS14-068", "ataque",
     ["noPac", "MS14-068", "PAC", "CVE"],
     "noPac (CVE-2021-42278/42287) e MS14-068: falhas de validacao do PAC e o spoofing de sAMAccountName."),

    (54, "kerberos", "kerberos.relay",
     "Kerberos relay e KrbRelayUp", "ataque",
     ["Kerberos Relay", "KrbRelayUp", "Coercao"],
     "Kerberos relay e KrbRelayUp: encaminhar autenticacao Kerberos para LDAP e escalar privilegio local."),

    (55, "kerberos", "kerberos.trusts",
     "Ataques atraves de trusts de dominio e floresta", "ataque",
     ["Trusts", "SID History", "ExtraSids"],
     "Ataques atravessando trusts: tickets inter-realm, trust key, SID History (ExtraSids) e delegacao entre dominios."),

    (56, "kerberos", "kerberos.persistencia",
     "Persistencia via Kerberos", "ataque",
     ["Persistencia", "Skeleton Key"],
     "Persistencia via Kerberos: Skeleton Key no DC e abuso de contas com SPN ou delegacao como backdoor."),

    (57, "kerberos", "kerberos.dmsa.badsuccessor",
     "dMSA e BadSuccessor", "ataque",
     ["dMSA", "BadSuccessor", "Windows Server 2025"],
     "dMSA e BadSuccessor: abuso de Delegated Managed Service Accounts no Windows Server 2025."),

    (58, "kerberos", "kerberos.hardening",
     "Hardening e consolidacao das deteccoes", "base",
     ["Hardening", "Protected Users", "krbtgt"],
     "Hardening do Kerberos: AES-only, Protected Users, rotacao dupla da krbtgt, gMSA e consolidacao das regras de deteccao."),

    # ---------------------------------------------------------------- AD CS
    (59, "adcs", "adcs.fundamentos.telemetria",
     "Fundamentos do AD CS e telemetria", "base",
     ["AD CS", "PKI", "Certipy"],
     "Como o AD CS funciona (CA, templates, enrollment) e as fontes de log que registram emissao e pedido de certificados."),

    (60, "adcs", "adcs.esc1.esc4",
     "ESC1 e ESC4: SAN arbitraria e controle sobre templates", "ataque",
     ["ESC1", "ESC4", "Certipy"],
     "ESC1 e ESC4: templates que permitem SAN arbitraria e controle sobre a configuracao do template."),

    (61, "adcs", "adcs.esc2.esc3",
     "ESC2 e ESC3: EKU Any Purpose e Enrollment Agent", "ataque",
     ["ESC2", "ESC3", "Enrollment Agent"],
     "ESC2 e ESC3: templates com EKU Any Purpose e o papel de Enrollment Agent."),

    (62, "adcs", "adcs.esc6",
     "ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2", "ataque",
     ["ESC6", "SAN"],
     "ESC6: a flag EDITF_ATTRIBUTESUBJECTALTNAME2 na CA e o SAN arbitrario em qualquer template."),

    (63, "adcs", "adcs.esc7",
     "ESC7: permissoes abusivas na CA", "ataque",
     ["ESC7", "ManageCA"],
     "ESC7: permissoes abusivas sobre a propria CA (ManageCA e ManageCertificates)."),

    (64, "adcs", "adcs.esc5",
     "ESC5: ACLs sobre objetos de PKI", "ataque",
     ["ESC5", "ACL"],
     "ESC5: ACLs fracas em objetos de PKI no Active Directory."),

    (65, "adcs", "adcs.esc8",
     "ESC8: relay NTLM para enrollment HTTP", "ataque",
     ["ESC8", "NTLM Relay", "Coercao"],
     "ESC8: relay NTLM para a interface web de enrollment do AD CS."),

    (66, "adcs", "adcs.esc11",
     "ESC11: relay NTLM para a interface ICPR (RPC)", "ataque",
     ["ESC11", "NTLM Relay", "ICPR"],
     "ESC11: relay NTLM para a interface RPC de enrollment (ICPR)."),

    (67, "adcs", "adcs.esc9.esc10",
     "ESC9 e ESC10: mapeamento fraco de certificado", "ataque",
     ["ESC9", "ESC10", "Mapeamento de Certificado"],
     "ESC9 e ESC10: ausencia da extensao de seguranca e mapeamento fraco de certificado para conta."),

    (68, "adcs", "adcs.esc13",
     "ESC13: issuance policy vinculada a grupo", "ataque",
     ["ESC13", "Issuance Policy"],
     "ESC13: template com issuance policy vinculada a um grupo do AD."),

    (69, "adcs", "adcs.esc14",
     "ESC14: mapeamento explicito fraco (altSecurityIdentities)", "ataque",
     ["ESC14", "altSecurityIdentities"],
     "ESC14: mapeamento explicito fraco via altSecurityIdentities."),

    (70, "adcs", "adcs.esc15",
     "ESC15 (EKUwu, CVE-2024-49019): application policies", "ataque",
     ["ESC15", "EKUwu", "CVE"],
     "ESC15 (EKUwu, CVE-2024-49019): abuso de application policies em templates da versao 1."),

    (71, "adcs", "adcs.esc12.esc16",
     "ESC12 e ESC16: acesso a CA e extensao de seguranca desabilitada", "ataque",
     ["ESC12", "ESC16"],
     "ESC12 e ESC16: acesso shell a CA e CA com a extensao de seguranca desabilitada."),

    (72, "adcs", "adcs.certifried",
     "Certifried (CVE-2022-26923)", "ataque",
     ["Certifried", "CVE", "MachineAccountQuota"],
     "Certifried (CVE-2022-26923): falsificacao de conta de maquina para obter certificado de um DC."),

    (73, "adcs", "adcs.theft.persist.golden",
     "Roubo de certificados, persistencia e Golden Certificate", "ataque",
     ["Golden Certificate", "Persistencia", "THEFT"],
     "Roubo de credenciais de certificado, persistencia via certificados e Golden Certificate com a chave da CA."),

    (74, "adcs", "adcs.hardening",
     "Hardening do AD CS e consolidacao das deteccoes", "base",
     ["Hardening", "PKI", "Mapeamento de Certificado"],
     "Hardening do AD CS: correcao dos templates, mapeamento forte de certificado e consolidacao das deteccoes."),

    # ---------------------------------------------------------------- Credenciais
    (75, "cred", "credenciais.fundamentos.telemetria",
     "Onde ficam os segredos do AD e telemetria", "base",
     ["Credenciais", "LSASS", "NTDS.dit"],
     "Onde o Active Directory guarda segredos (SAM, LSASS, NTDS.dit, DPAPI) e as fontes de log que acompanham o acesso a eles."),

    (76, "cred", "credenciais.lsass.dump",
     "Dump de credenciais do LSASS", "ataque",
     ["LSASS", "Mimikatz", "Sysmon"],
     "Dump de credenciais do LSASS: tecnicas de acesso ao processo e a telemetria de Sysmon e canal Security."),

    (77, "cred", "credenciais.dcsync",
     "DCSync", "ataque",
     ["DCSync", "DRSUAPI", "krbtgt"],
     "DCSync: abuso da replicacao (DRSUAPI) para extrair hashes, inclusive o da krbtgt."),

    (78, "cred", "credenciais.dcshadow",
     "DCShadow", "ataque",
     ["DCShadow", "Replicacao"],
     "DCShadow: registrar um DC falso para injetar alteracoes no AD sem passar pelos logs normais."),

    (79, "cred", "credenciais.ntds.dit",
     "Extracao do NTDS.dit", "ataque",
     ["NTDS.dit", "VSS", "ntdsutil"],
     "Extracao do NTDS.dit via ntdsutil, VSS e diskshadow, e como detectar a copia do banco."),

    (80, "cred", "credenciais.golden.gmsa",
     "Golden gMSA", "ataque",
     ["gMSA", "KDS Root Key"],
     "Golden gMSA: derivar a senha de contas gMSA a partir da KDS root key."),

    (81, "cred", "credenciais.golden.dmsa",
     "Golden dMSA", "ataque",
     ["dMSA", "KDS Root Key"],
     "Golden dMSA: o mesmo problema da KDS root key aplicado as Delegated Managed Service Accounts."),

    (82, "cred", "credenciais.laps",
     "Leitura e abuso do LAPS", "ataque",
     ["LAPS", "ACL"],
     "Leitura e abuso do LAPS: acesso as senhas de administrador local armazenadas no AD."),

    (83, "cred", "credenciais.dpapi",
     "DPAPI: segredos de maquina e de dominio", "ataque",
     ["DPAPI", "Backup Key"],
     "DPAPI: recuperacao de segredos de maquina e a backup key de dominio."),

    (84, "cred", "credenciais.timeroasting",
     "Timeroasting", "ataque",
     ["Timeroasting", "MS-SNTP"],
     "Timeroasting: abuso da autenticacao MS-SNTP para obter material offline-crackavel de contas de maquina."),

    (85, "cred", "credenciais.hardening",
     "Hardening e consolidacao das deteccoes", "base",
     ["Hardening", "Credential Guard", "Protected Users"],
     "Hardening de credenciais: Protected Users, Credential Guard, gMSA e consolidacao das regras de deteccao."),
]


# ------------------------------------------------------------------ geracao
def iso_now():
    """Data atual em formato RFC3339 com offset -03:00 (ex.: 2026-10-27T01:05:00-03:00)."""
    s = datetime.now(TZ).strftime("%Y-%m-%dT%H:%M:%S%z")
    return s[:-2] + ":" + s[-2:]


def yaml_lista(chave, itens):
    linhas = [f"{chave}:"]
    for it in itens:
        linhas.append(f" - {it}")
    return "\n".join(linhas)


def front_matter(num, serie_key, titulo, descricao, tags_esp):
    tags = TAGS_BASE + tags_esp
    partes = [
        "---",
        f'title: "{titulo}"',
        f"date: {iso_now()}",
        f"draft: {'true' if DRAFT else 'false'}",
        f'description: "{descricao}"',
        "noindex: false",
        "featured: false",
        "pinned: false",
        "comments: true",
        yaml_lista("series", [SERIES[serie_key]]),
        yaml_lista("categories", CATEGORIAS[serie_key]),
        yaml_lista("tags", tags),
        yaml_lista("authors", [AUTHOR]),
        "---",
    ]
    return "\n".join(partes)


CORPO_ATAQUE = """
## Introducao

## Pre-requisitos

## Execucao do ataque

## Telemetria

### No controlador de dominio

### No host e na rede

## Deteccao

### Consulta no Graylog

## Mitigacao e hardening

## Referencias
"""

CORPO_BASE = """
## Introducao

## Conceitos

## Na pratica

## Referencias
"""


def corpo(tipo):
    return CORPO_ATAQUE if tipo == "ataque" else CORPO_BASE


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else BASE_DIR
    criados, pulados = 0, 0

    for num, serie, slug, titulo, tipo, tags_esp, desc in ARTIGOS:
        if len(desc) > 200:
            print(f"  AVISO: descricao do artigo {num} tem {len(desc)} caracteres (>200)")

        pasta = os.path.join(base, f"{num}.{slug}")
        index = os.path.join(pasta, "index.md")

        if os.path.exists(index):
            pulados += 1
            print(f"  pulado   {num}.{slug} (index.md ja existe)")
            continue

        os.makedirs(pasta, exist_ok=True)
        conteudo = front_matter(num, serie, titulo, desc, tags_esp) + "\n" + corpo(tipo)
        with open(index, "w", encoding="utf-8") as f:
            f.write(conteudo)
        criados += 1
        print(f"  criado   {num}.{slug}")

    print(f"\n{criados} artigos criados, {pulados} pulados, em {base!r}")


if __name__ == "__main__":
    main()
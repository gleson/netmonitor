# Atualização das bases de informação — sem depender de LLM

Resposta à pergunta: **dá para automatizar a atualização das bases (CVEs, tipos
de scan, catálogo de portas) sem depender de um modelo de LLM?**

Resumo: **sim, na maior parte.** As bases *técnicas* têm fontes públicas e
estruturadas que podem ser baixadas por scripts/cron sem nenhum LLM. O que
**não** é automatizável é o conteúdo *editorial* em pt-BR (análises de risco,
recomendações, comandos comentados) — isso precisa de um humano ou de um LLM.

A tabela abaixo separa o que é automatizável do que não é.

| Base | Fonte pública | Automatizável sem LLM? | Como |
|------|---------------|------------------------|------|
| **CVEs (correlação)** | API NVD 2.0 | ✅ Sim | Já implementado em `app/scanner/cve.py`; cache em `cve_cache`. Com `NVD_API_KEY` fica ~10× mais rápido. |
| **Exploração ativa** | CISA KEV (JSON) | ✅ Sim | `flask update-kev` / refresh automático no job de CVE. |
| **Nomes de serviço de portas** | Registro IANA (CSV) | ✅ Sim | `scripts/update_iana_ports.py` → `app/data/iana_ports.json`. |
| **Tipos de scan de vulnerabilidade** | Scripts NSE do nmap | ✅ Sim (via nmap) | `sudo nmap --script-updatedb` após atualizar o pacote nmap. |
| **Catálogo rico de portas** (riscos, análise, comandos) | — (conteúdo próprio) | ❌ Não | Editorial pt-BR; precisa de humano/LLM. |

---

## 1. CVEs — já automatizado e reforçado

O scanner de vulnerabilidades (`app/scanner/cve.py`) correlaciona
`service_name`/`service_version` das portas abertas com a **API pública do
NVD**. Não precisa de LLM. Reforços recentes:

- **API key opcional do NVD** (`NVD_API_KEY`): sobe o limite de ~5 para ~50
  requisições/30s e reduz a pausa entre consultas de 6.5s para 0.7s. Solicite em
  <https://nvd.nist.gov/developers/request-an-api-key> (gratuito) e exporte:

  ```bash
  export NVD_API_KEY="sua-chave"
  ```

- **Filtragem por versão (CPE)**: os resultados da busca textual do NVD são
  filtrados pelas faixas de versão das configurações CPE 2.3 de cada CVE,
  cortando falsos-positivos (CVEs que só *citam* o produto, mas afetam outra
  versão).

- **Cache** em `cve_cache` (TTL `CVE_CACHE_TTL_DAYS`) evita reconsultar a mesma
  combinação produto+versão.

Rodar sob demanda:

```bash
FLASK_APP=manage.py flask run-cve-scan
```

## 2. CISA KEV — exploração ativa (novo)

O catálogo **Known Exploited Vulnerabilities** da CISA é um feed JSON público
(sem autenticação, sem LLM) das CVEs comprovadamente exploradas. Quando um CVE
correlacionado está na KEV, o alerta vira **CRITICAL com `is_priority=True`**
mesmo que o CVSS fique abaixo do mínimo — porque exploração ativa pesa mais que
o score.

- Atualização manual / cron:

  ```bash
  FLASK_APP=manage.py flask update-kev
  ```

- Atualização automática: o job de correlação de CVE atualiza o catálogo se ele
  estiver mais velho que `CVE_KEV_REFRESH_HOURS` (24h por padrão). O catálogo
  fica em `AppSetting` (`cve.kev_catalog`), sem tabela/migração nova.

Exemplo de cron diário:

```cron
0 6 * * *  cd /opt/netmonitor && FLASK_APP=manage.py flask update-kev
```

## 3. Nomes de serviço de portas — IANA (novo script)

O registro oficial **IANA** (Service Name and Transport Protocol Port Number
Registry) é um CSV público. O script `scripts/update_iana_ports.py` o baixa e
gera `app/data/iana_ports.json` (`porta/proto` → nome + descrição curta):

```bash
python scripts/update_iana_ports.py          # baixa e grava
python scripts/update_iana_ports.py --check   # só mostra diferenças
```

Serve para **detectar portas ainda sem ficha** no catálogo rico e preencher o
nome do serviço como fallback. **Não** substitui o catálogo editorial.

## 4. Tipos de scan de vulnerabilidade — nmap NSE

Os "tipos de scan que detectam vulnerabilidades" são os **scripts NSE** do nmap
(categorias `vuln`, `safe`, etc.). Eles são mantidos pela comunidade do nmap e
**atualizam junto com o pacote nmap** — não dependem de LLM:

```bash
sudo dnf upgrade nmap        # (ou apt/brew) traz novos scripts NSE
sudo nmap --script-updatedb  # reindexa a base local de scripts
```

Para acionar detecção ativa baseada em NSE (mais intrusiva, gera tráfego na rede
local), usar por exemplo `nmap --script vuln -p<portas> <ip>`. Hoje o projeto
mantém deliberadamente a correlação CVE **sem tráfego local** (só HTTPS ao NVD);
um job NSE seria um modo opt-in distinto.

## 5. O que NÃO é automatizável sem LLM/humano

O catálogo rico de `app/views/ports_info.py` — descrições de risco, "quando é
ok / quando alertar", análise e comandos comentados (nmap, tcpdump, dig…) em
pt-BR — é **conteúdo editorial**. Não existe fonte pública estruturada disso; é
gerado por humano ou LLM. Quem baixa o projeto **recebe esse catálogo pronto no
repositório** e não precisa de LLM para usá-lo; só precisaria de LLM/humano para
*ampliá-lo* com novas fichas detalhadas.

---

## Conclusão

| Pergunta | Resposta |
|----------|----------|
| Dá para atualizar CVEs sem LLM? | ✅ Sim (NVD + cache, já pronto). |
| Dá para priorizar o que está sendo explorado? | ✅ Sim (CISA KEV, `flask update-kev`). |
| Dá para atualizar nomes de portas sem LLM? | ✅ Sim (IANA, `scripts/update_iana_ports.py`). |
| Dá para atualizar os scans de vulnerabilidade? | ✅ Sim (atualizar o nmap + NSE). |
| Dá para gerar as fichas de risco/análise sem LLM? | ❌ Não — conteúdo editorial. |

Ou seja: o usuário que baixar o projeto **sem acesso a um LLM** consegue manter
atualizadas todas as bases técnicas (CVEs, KEV, IANA, NSE) via cron/scripts. Só
a ampliação do catálogo editorial de portas depende de LLM/humano.

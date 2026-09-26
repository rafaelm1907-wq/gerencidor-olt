# LVL — Gerenciador de OLTs

Painel web para inventário e monitoramento de OLTs Huawei por SNMP e CLI (Telnet ou SSH). A instalação começa sem equipamentos cadastrados: o administrador testa o acesso, confere placas, PONs, ONTs, óptica e VLANs e só então confirma o cadastro.

## Recursos

- múltiplas OLTs na mesma página;
- descoberta de placas e PONs por S/F/P real;
- estado, temperatura, potência, tráfego e saúde do equipamento;
- ONTs online/offline, sinal, temperatura, serial, nome e VLAN nativa;
- consulta sob demanda de ONTs em `autofind`, sem persistência;
- relatórios `.txt` por PON;
- alertas Telegram por PON, com controle de repetição e resolução;
- autenticação com administrador e usuário somente leitura;
- cadastro de OLT pelo painel com diagnóstico SNMP + CLI;
- retenção histórica padrão de dois dias;
- coletores desacoplados e serviços `systemd` com limites de recursos.

## Ambiente suportado

- Debian 12 ou Ubuntu Server recente;
- Python 3.11 ou mais novo;
- `systemd`;
- conectividade IP entre o servidor e as OLTs;
- SNMP v2c e, opcionalmente, Telnet ou SSH somente leitura.

SQLite é usado por OLT. Essa arquitetura evita misturar o banco do Zabbix com a coleta detalhada e simplifica backup, retenção e recuperação.

## Instalação

```bash
git clone https://github.com/rafaelm1907-wq/gerencidor-olt.git
cd gerencidor-olt
chmod +x install.sh update.sh
sudo ./install.sh
```

O instalador:

1. instala Python, Paramiko, ferramentas SNMP e ping;
2. copia a aplicação para `/opt/olt-vision`;
3. cria `/etc/olt-vision` e `/var/lib/olt-vision`;
4. solicita as senhas iniciais de `admin` e `viewer` sem exibi-las;
5. habilita o painel e o coletor rápido;
6. mantém Telegram desativado até sua configuração.

Abra `http://IP-DO-SERVIDOR:6000`, entre como `admin` e acesse **Administração → Adicionar OLT**.

## Cadastro de OLT

Informe no painel:

- nome;
- IPv4 privado de gerenciamento;
- community SNMP v2c;
- protocolo Telnet ou SSH;
- porta do protocolo, caso não seja a padrão;
- usuário e senha de consulta.

O diagnóstico identifica placas e portas, consulta resumo de ONTs, leitura óptica e VLANs e recomenda o intervalo de coleta. O cadastro só é liberado quando o diagnóstico mínimo é válido. As credenciais ficam em `/etc/olt-vision/olts/<id>.env`, com permissão `600`, e nunca entram no Git.

## Configuração

Configuração global: `/etc/olt-vision.env`.

```dotenv
DATA_ROOT=/var/lib/olt-vision
OLT_ENV_ROOT=/etc/olt-vision/olts
AUTH_DB=/var/lib/olt-vision/auth.db
VIEWER_USERNAME=viewer
HISTORY_DAYS=2
FAST_POLL_INTERVAL=120
TRAFFIC_POLL_INTERVAL=60
COOKIE_SECURE=0
```

Use `COOKIE_SECURE=1` quando o painel estiver publicado exclusivamente por HTTPS.

## Telegram

Edite `/etc/olt-vision/telegram.env`:

```dotenv
TELEGRAM_BOT_TOKEN=token-do-bot
```

O destino é definido por OLT no campo `telegram_chat_id` de `/opt/olt-vision/olts.json`. Depois habilite:

```bash
sudo systemctl enable --now olt-telegram.service
```

Nunca coloque tokens, communities ou senhas no repositório.

## Serviços

```text
olt-multi-web.service       painel na porta 6000
olt-fast.service            estado e tráfego rápido
olt-collector@<id>.service  coleta completa de uma OLT
olt-vlan@<id>.service       inventário periódico de VLANs
olt-telegram.service        entrega da fila de alertas
```

## Atualização

```bash
git pull --ff-only
sudo ./update.sh
```

O script preserva bancos, usuários, OLTs cadastradas e arquivos de credenciais.

## Backup

Preserve `/opt/olt-vision/olts.json`, `/etc/olt-vision*` e `/var/lib/olt-vision`. Pare os coletores ou use a API de backup do SQLite antes de copiar bancos em uso. O histórico de amostras fica limitado a dois dias; inventário, último estado válido, VLANs e estados ativos de alertas são preservados.

## Segurança

- use um usuário de OLT com permissão somente leitura;
- mantenha a porta 6000 restrita à rede administrativa ou publique por túnel HTTPS;
- prefira SSH quando o firmware da OLT oferecer suporte compatível;
- não exponha Telnet ou SNMP diretamente à Internet;
- nunca versione tokens, communities, senhas ou bancos.

## Testes

```bash
python3 -m unittest -v
```

Os testes usam bancos temporários e não acessam OLTs reais.


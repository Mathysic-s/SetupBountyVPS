#!/bin/bash

# Configurações
DOMAIN="domain.com.br"  # Domínio para gerar o certificado autoassinado
EMAIL="contato@$DOMAIN"    # Email para o cert
TELEGRAM_API_KEY="" # Telegram API KEY para o Notify
TELEGRAM_CHAT_ID="" # Telegram Chat ID para o Notify

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para log
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Função para info
info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Função para alerta
warning() {
    echo -e "${YELLOW}[ALERTA] $1${NC}"
}

# Função para erro
error() {
    echo -e "${RED}[ERRO] $1${NC}"
    exit 1
}

# Verificar se é root
if [ "$EUID" -ne 0 ]; then
    error "Execute o script como root ou com sudo"
fi

log "Iniciando atualização do sistema..."
apt update -y
apt upgrade -y

log "Configurando firewall..."
# Limpar todas as regras existentes
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Definir políticas padrão (DROP tudo)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Permitir loopback (comunicação interna)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Permitir conexões estabelecidas e relacionadas
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Permitir SSH (porta 22)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Permitir ICMP (ping)
iptables -A INPUT -p icmp -j ACCEPT

# Liberar para HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Log para tráfego rejeitado (opcional)
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

# Salvar as regras
iptables-save > /etc/iptables/rules.v4
iptables-save > rules-firewall

log "Instalando parrot shell..."
cat > $HOME/.bashrc << EOF
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# don't put duplicate lines in the history. See bash(1) for more options
# ... or force ignoredups and ignorespace
HISTCONTROL=ignoredups:ignorespace

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "$debian_chroot" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
        # We have color support; assume it's compliant with Ecma-48
        # (ISO/IEC-6429). (Lack of such support is extremely rare, and such
        # a case would tend to support setf rather than setaf.)
        color_prompt=yes
    else
        color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1="\[\033[0;31m\]\342\224\214\342\224\200\$([[ \$? != 0 ]] && echo \"[\[\033[0;31m\]\342\234\227\[\033[0;37m\]]\342\224\200\")[$(if [[ ${EUID} == 0 ]]; then echo '\[\033[01;31m\]root\[\033[01;33m\]@\[\033[01;96m\]\h'; else echo '\[\033[0;39m\]\u\[\033[01;33m\]@\[\033[01;96m\]\h'; fi)\[\033[0;31m\]]\342\224\200[\[\033[0;32m\]\w\[\033[0;31m\]]\n\[\033[0;31m\]\342\224\224\342\224\200\342\224\200\342\225\274 \[\033[0m\]\[\e[01;33m\]\\$\[\e[0m\]"
    #PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1="\[\033[0;31m\]\342\224\214\342\224\200\$([[ \$? != 0 ]] && echo \"[\[\033[0;31m\]\342\234\227\[\033[0;37m\]]\342\224\200\")[$(if [[ ${EUID} == 0 ]]; then echo '\[\033[01;31m\]root\[\033[01;33m\]@\[\033[01;96m\]\h'; else echo '\[\033[0;39m\]\u\[\033[01;33m\]@\[\033[01;96m\]\h'; fi)\[\033[0;31m\]]\342\224\200[\[\033[0;32m\]\w\[\033[0;31m\]]\n\[\033[0;31m\]\342\224\224\342\224\200\342\224\200\342\225\274 \[\033[0m\]\[\e[01;33m\]\\$\[\e[0m\]"
    #PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\033[0;31m\]\342\224\214\342\224\200\$([[ \$? != 0 ]] && echo \"[\[\033[0;31m\]\342\234\227\[\033[0;37m\]]\342\224\200\")[$(if [[ ${EUID} == 0 ]]; then echo '\[\033[01;31m\]root\[\033[01;33m\]@\[\033[01;96m\]\h'; else echo '\[\033[0;39m\]\u\[\033[01;33m\]@\[\033[01;96m\]\h'; fi)\[\033[0;31m\]]\342\224\200[\[\033[0;32m\]\w\[\033[0;31m\]]\n\[\033[0;31m\]\342\224\224\342\224\200\342\224\200\342\225\274 \[\033[0m\]\[\e[01;33m\]\\$\[\e[0m\]"
    #PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if [ -f /etc/bash_completion ] && ! shopt -oq posix; then
    . /etc/bash_completion
fi
EOF
source $HOME/.bashrc

log "Instalando pacotes básicos..."
apt install -y iptables-persistent net-tools python3 python3-pip openssl

log "Instalando Golang..."
wget -q https://go.dev/dl/go1.24.6.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.24.6.linux-amd64.tar.gz
echo "export PATH=\$PATH:/usr/local/go/bin" >> /etc/profile
echo "export PATH=\$PATH:\$HOME/go/bin" >> /etc/profile
echo "export PATH=\$PATH:/usr/local/go/bin" >> $HOME/.profile
source /etc/profile
source $HOME/.profile
go version

log "Install notify..."
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
notify -version
cat > $HOME/.config/notify/provider-config.yaml << EOF
telegram:
  - id: "tel"
    telegram_api_key: "$TELEGRAM_API_KEY"
    telegram_chat_id: "$TELEGRAM_CHAT_ID"
    telegram_format: "{{data}}"
    telegram_parsemode: "Markdown" # None/Markdown/MarkdownV2/HTML (https://core.telegram.org/bots/api#formatting-options)
EOF

log "Install Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
log "Adicionando notify para Update do Nuclei..."
nuclei -update-templates
echo "59 10 * * * nuclei -update-templates ; echo 'Nuclei Atualizado' | notify >/dev/null 2>&1 >/dev/null 2>&1" > /etc/cron.d/updateNuclei_templates

log "Instalando Docker..."
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove -y $pkg; done

# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker run hello-world

log "Instalando Portainer..."
docker volume create portainer_data
docker run -d -p 127.0.0.1:8000:8000 -p 127.0.0.1:9443:9443 --name portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:lts

log "Instalando Nginx..."
apt install -y nginx

log "Criando certificado SSL autoassinado para portainer.$DOMAIN..."

# Criar diretório para certificados
mkdir -p /etc/ssl/private
mkdir -p /etc/ssl/certs

# Criar certificado autoassinado
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/ssl/private/portainer-selfsigned.key \
    -out /etc/ssl/certs/portainer-selfsigned.crt \
    -subj "/C=BR/ST=Estado/L=Cidade/O=Organizacao/CN=portainer.$DOMAIN/emailAddress=$EMAIL"

# Criar chain completa (necessário para alguns navegadores)
cat /etc/ssl/certs/portainer-selfsigned.crt > /etc/ssl/certs/portainer-selfsigned-fullchain.crt

log "Configurando Nginx para portainer.$DOMAIN com SSL autoassinado..."

cat > /etc/nginx/sites-available/portainer << EOF
# Redirecionamento HTTP para HTTPS
server {
    listen 80;
    server_name portainer.$DOMAIN;

    # Redirecionar tudo para HTTPS
    return 301 https://\$server_name\$request_uri;
}

# Servidor HTTPS
server {
    listen 443 ssl http2;
    server_name portainer.$DOMAIN;

    # Configurações SSL autoassinado
    ssl_certificate /etc/ssl/certs/portainer-selfsigned-fullchain.crt;
    ssl_certificate_key /etc/ssl/private/portainer-selfsigned.key;

    # Melhorias de segurança SSL
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Headers de segurança
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000" always;

    # Ignorar avisos de certificado autoassinado no navegador
    add_header Public-Key-Pins 'pin-sha256="base64+primary=="; pin-sha256="base64+backup=="; max-age=5184000; includeSubDomains' always;

    # Configurações do proxy para Portainer
    location / {
        proxy_pass https://localhost:9443;

        # Headers do proxy
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;

        # Configurações de timeout
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
        send_timeout 300;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Health check
    location /ping {
        access_log off;
        return 200 "pong";
        add_header Content-Type text/plain;
    }

    # Página de aviso sobre certificado autoassinado
    location /ssl-info {
        alias /usr/share/nginx/html/;
        index ssl-info.html;
    }
}
EOF

# Criar página de informações sobre o certificado
mkdir -p /usr/share/nginx/html
cat > /usr/share/nginx/html/ssl-info.html << EOF
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL Autoassinado - Portainer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f4; }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #d9534f; }
        .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠️ Certificado SSL Autoassinado</h1>
        <div class="warning">
            <p><strong>Atenção:</strong> Este site utiliza um certificado SSL autoassinado.</p>
            <p>Seu navegador pode exibir um aviso de segurança. Isso é normal para ambientes de desenvolvimento.</p>
        </div>
        <h2>Como prosseguir:</h2>
        <ul>
            <li>Chrome: Clique em "Avançado" → "Prosseguir para portainer.$DOMAIN (inseguro)"</li>
            <li>Firefox: Clique em "Avançado" → "Aceitar o risco e continuar"</li>
            <li>Edge: Clique em "Detalhes" → "Prosseguir para o site"</li>
        </ul>
        <p><a href="https://portainer.$DOMAIN">Clique aqui para tentar acessar novamente</a></p>
    </div>
</body>
</html>
EOF

# Habilitar site do Portainer
ln -sf /etc/nginx/sites-available/portainer /etc/nginx/sites-enabled/

# Remover config padrão se existir
rm -f /etc/nginx/sites-enabled/default

# Verificar configuração do Nginx
log "Verificando configuração do Nginx..."
if nginx -t; then
    log "Configuração do Nginx testada com sucesso!"
else
    error "Erro na configuração do Nginx. Verifique os arquivos de configuração."
fi

# Reiniciar Nginx
log "Reiniciando Nginx..."
systemctl restart nginx
systemctl enable nginx

# Testar configuração
log "Testando configuração..."
sleep 3

# Verificar se Nginx está rodando
if systemctl is-active --quiet nginx; then
    log "Nginx está rodando com sucesso!"
else
    error "Nginx não está rodando. Verifique os logs: journalctl -u nginx"
fi

# Verificar certificado SSL
log "Verificando certificado SSL autoassinado..."
if [ -f "/etc/ssl/certs/portainer-selfsigned.crt" ]; then
    log "Certificado SSL autoassinado criado com sucesso!"
    log "Validade do certificado:"
    openssl x509 -in /etc/ssl/certs/portainer-selfsigned.crt -noout -dates
    log "Informações do certificado:"
    openssl x509 -in /etc/ssl/certs/portainer-selfsigned.crt -noout -issuer -subject
else
    error "Certificado SSL não encontrado!"
fi

# Informações finais
echo ""
echo -e "${GREEN}=== INSTALAÇÃO CONCLUÍDA ===${NC}"
echo -e "Domínio principal: ${YELLOW}$DOMAIN${NC}"
echo -e "Portainer: ${YELLOW}https://portainer.$DOMAIN${NC}"
echo -e "Porta interna: ${YELLOW}localhost:9443${NC}"
echo -e "Certificado: ${YELLOW}Autoassinado (10 anos de validade)${NC}"
echo ""
echo -e "${YELLOW}=== INFORMAÇÕES IMPORTANTES ==="
echo -e "1. Configure o DNS para portainer.$DOMAIN apontando para: $(hostname -I | awk '{print $1}')${NC}"
echo -e "2. Acesse https://portainer.$DOMAIN no navegador"
echo -e "3. ⚠️  Ignore o aviso de certificado não confiável"
echo -e "4. Verifique se o Portainer está rodando: docker ps"
echo -e "5. Certificado autoassinado localizado em:"
echo -e "   - Cert: /etc/ssl/certs/portainer-selfsigned.crt"
echo -e "   - Key:  /etc/ssl/private/portainer-selfsigned.key"
echo ""
warning "ACESSO O PORTAINER IMEDIATAMENTE PARA GERAR A SENHA DE ADMIN, E CONCLUIR A INSTALAÇÂO."

# Verificar se o Portainer está rodando
if docker ps | grep -q portainer; then
    log "Portainer está rodando corretamente!"
else
    warning "Portainer não está rodando. Iniciando..."
    docker start portainer
fi

# Criar script para instalar certificado localmente (opcional)
cat > /root/install-ssl-certificate.sh << EOF
#!/bin/bash
# Script para instalar o certificado autoassinado em máquinas locais
echo "=== Instalação de Certificado Autoassinado ==="
echo "Para evitar avisos no navegador, instale o certificado:"
echo "sudo cp /etc/ssl/certs/portainer-selfsigned.crt /usr/local/share/ca-certificates/"
echo "sudo update-ca-certificates"
echo ""
echo "Ou importe manualmente no navegador:"
echo "1. Acesse chrome://settings/certificates"
echo "2. Vá em 'Autoridades' → 'Importar'"
echo "3. Selecione /etc/ssl/certs/portainer-selfsigned.crt"
echo "4. Marque 'Confiar neste certificado para identificar sites'"
EOF

chmod +x /root/install-ssl-certificate.sh

log "Script finalizado com sucesso!"

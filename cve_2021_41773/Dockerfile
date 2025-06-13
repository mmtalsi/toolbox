FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y apache2 apache2-utils libapache2-mod-fcgid && \
    apt-get install -y bash curl && \
    a2enmod cgi && a2enmod rewrite && a2enmod proxy_fcgi && \
    rm -rf /var/lib/apt/lists/*

# Crée le répertoire CGI s'il n'existe pas
RUN mkdir -p /usr/lib/cgi-bin

# Copie les scripts CGI dans le dossier /usr/lib/cgi-bin
COPY passwd.cgi /usr/lib/cgi-bin/passwd.cgi
COPY shell.cgi /usr/lib/cgi-bin/shell.cgi
COPY shadow.cgi /usr/lib/cgi-bin/shadow.cgi

# Rend les scripts exécutables
RUN chmod +x /usr/lib/cgi-bin/*.cgi

EXPOSE 80

CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]


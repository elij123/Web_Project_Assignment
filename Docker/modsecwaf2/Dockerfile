FROM owasp/modsecurity-crs:3.3.4-apache-202303180303
COPY ./server.key /usr/local/apache2/conf/
COPY ./server.crt /usr/local/apache2/conf/
ENV PROXY_SSL_CHECK_PEER_NAME=off
ENV SSL_USE_STAPLING=off
ENV SSL_ENGINE=on
ENV PROXY_SSL=on
ENV MODSEC_RULE_ENGINE=On
EXPOSE 443
ENV BACKEND=http://10.0.0.6


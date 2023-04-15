FROM owasp/modsecurity-crs
COPY /home/ubuntu/server.key /usr/local/apache2/conf/
COPY /home/ubuntu/server.crt /usr/local/apache2/conf/
ENV BACKEND=http://10.0.0.1:8080

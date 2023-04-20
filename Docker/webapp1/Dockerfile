FROM ubuntu:jammy
RUN ["apt", "update"]
ENV DEBIAN_FRONTEND=noninteractive
RUN ["apt", "install", "-y", "php8.1-cgi"]
RUN ["apt", "install", "-y", "python3"]
RUN ["apt", "install", "-y", "python3-pip"]
RUN ["pip", "install", "pytz"]
RUN ["pip", "install", "typer[all]"]
RUN ["mkdir", "/var/web_files"]
COPY ./files /var/web_files/
COPY ./http_request_server.py /var/web_files/
COPY ./php.ini /etc/php/8.1/cgi/php.ini
EXPOSE 80
ENTRYPOINT ["python3", "/var/web_files/http_request_server.py", "--ip-addr-listen", "10.0.0.5","--port-listen", "80"]


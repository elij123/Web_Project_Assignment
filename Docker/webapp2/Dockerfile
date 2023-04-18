FROM ubuntu:jammy
RUN ["apt", "update"]
ENV DEBIAN_FRONTEND=noninteractive
RUN ["apt", "install", "-y", "php-cgi"]
RUN ["apt", "install", "-y", "python3"]
RUN ["apt", "install", "-y", "python3-pip"]
RUN ["pip", "install", "pytz"]
RUN ["pip", "install", "typer[all]"]
COPY ./files /
COPY ./http_request_server.py /
COPY ./php.ini /etc/php/8.1/cgi/php.ini
EXPOSE 80
ENTRYPOINT ["python3", "/http_request_server.py", "10.0.0.6", "80"]


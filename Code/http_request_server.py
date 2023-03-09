import re
import typer
import socket
import threading
import warnings
import pytz
import ssl
import sys
import os
import subprocess
from datetime import datetime

# Grammar for the hostname of the Host field
h16 = "[0-9A-Fa-f]{1,4}"
dec_octet = "([0-9]|[1-9][0-9]|[1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5])"
IPv4addr = f"{dec_octet}.{dec_octet}.{dec_octet}.{dec_octet}"
ls32 = f"({h16}:{h16}|{IPv4addr})"
ipv6_sub1 = f"({h16}:){{6}}{ls32}"
ipv6_sub2 = f"::({h16}:){{5}}{ls32}"
ipv6_sub3 = f"({h16})?::({h16}:){{4}}{ls32}"
ipv6_sub4 = f"(({h16}:){{0,1}}{h16})?::({h16}:){{3}}{ls32}"
ipv6_sub5 = f"(({h16}:){{0,2}}{h16})?::({h16}:){{2}}{ls32}"
ipv6_sub6 = f"(({h16}:){{0,3}}{h16})?::({h16}:){ls32}"
ipv6_sub7 = f"(({h16}:){{0,4}}{h16})?::{ls32}"
ipv6_sub8 = f"(({h16}:){{0,5}}{h16})?::{h16}"
ipv6_sub9 = f"(({h16}:){{0,6}}{h16})?::"
IPv6addr = f"{ipv6_sub1}|{ipv6_sub2}|{ipv6_sub3}|{ipv6_sub4}|\
{ipv6_sub5}|{ipv6_sub6}|{ipv6_sub7}|{ipv6_sub8}|{ipv6_sub9}"
IPvfuture = "v[0-9A-Fa-f]+.([\w.\-~]|[!$&'()*+,;=]|[:])?"
IP_literal = f"\[({IPv6addr}|{IPvfuture})\]"
reg_name = "([\w.\-~]|[%][0-9A-Fa-f][0-9A-Fa-f]|[!$&'()*+,;=])*"
host = re.compile(f"{IP_literal}|{IPv4addr}|{reg_name}", re.ASCII)

# Grammar for the port number of the Host field
port = re.compile("[\d]*", re.ASCII)

tz_NY = pytz.timezone("America/New_York")
# Minor HTTP version
server_minor_ver = 1
token_regex = re.compile("[!#$%&’*+\-.^‘|~\w]+", re.ASCII)
# Regex for the URI in the request
absolute_path_regex = re.compile(
    "(/([\w.\-~]|[%][0-9A-Fa-f][0-9A-Fa-f]|[!$&'()*+,;=]|[:]|[@])*)+", re.ASCII,
)
query_regex = re.compile(
    "([\w.\-~]|[%][0-9A-Fa-f][0-9A-Fa-f]|[!$&'()*+,;=]|[:]|[@]|[/]|[?])*", re.ASCII,
)

CRLF = "\r\n"

# Defining exceptions for HTTP errors
class BadRequestException(Exception):
    pass


class VersionNotSupported(Exception):
    pass


class ContentLengthNotFound(Exception):
    pass


class MethodNotImplemented(Exception):
    pass


class http_session:
    def __init__(self,):
        self.http_body = None
        self.location_header_path = None
        self.http_response_to_send = None
        self.http_request_method = None
        self.http_fullpath = None
        self.http_query = None

        # Logger

    def http_request_logger(self, request_line):
        with open("http_log.txt", "wba") as http_log:
            datetime_NY = datetime.now(tz_NY)
            datetime_NY_str = datetime_NY.strftime("%d %b, %Y, %H:%M:%S")
            http_log.write(
                bytes(datetime_NY_str + " HTTP Request " + request_line, "UTF-8")
            )

    # Parses HTTP request
    def http_request_message(self, input_http_str):
        try:
            print(input_http_str)
            first_CRLF = input_http_str.find(CRLF)
            if first_CRLF != -1:
                self.request_start_line_http(input_http_str[:first_CRLF])
                self.header_block_http(input_http_str[first_CRLF + 2 :])
        except BadRequestException:
            print("the HTTP request is ill-formed")
            self.http_response_to_send = http_response_400()
        except MethodNotImplemented:
            print("The HTTP method in the request is not supported")
            self.http_response_to_send = http_response_501()
        except VersionNotSupported:
            print("The HTTP version of the request is not supported")
            self.http_response_to_send = http_response_505()
        except Exception as error_500:
            print(error_500)
            self.http_response_to_send = http_response_500()
        finally:
            return self.http_response_to_send

    # Parses HTTP Request Line
    def request_start_line_http(self, input_str):
        if input_str.find(" ") != -1:
            str_segments = input_str.split(" ")
            self.http_method(str_segments[0])
            self.request_target(str_segments[1])
            self.http_version(str_segments[2])
            self.http_request_logger(input_str)
        else:
            raise BadRequestException

    # HTTP responses for different HTTP request
    def http_method(self, input: str):
        if re.fullmatch(token_regex, input) != None:
            if input == "GET":
                self.http_request_method = self.GET_request
            elif input == "POST":
                self.http_request_method = self.POST_request
            elif input == "PUT":
                self.http_request_method = self.PUT_request
            elif input == "DELETE":
                self.http_request_method = self.DELETE_request
            elif input == "HEAD":
                self.http_request_method = self.HEAD_request
            else:
                raise MethodNotImplemented
        else:
            raise BadRequestException

    # Parses URI from request line
    def request_target(self, input_str):
        if re.match("/", input_str) != None:
            if input_str == "/":
                URI_path = "/index.html"
                self.http_fullpath = (
                    "/media/sf_Ubuntu_Web_Assignment/Documents" + URI_path
                )
                self.location_header_path = URI_path
            else:
                if input_str.find("?") != -1:
                    input_str_seg = input_str.split("?")
                    URI_path = input_str_seg[0]
                    query_str = input_str_seg[1]
                    if re.fullmatch(absolute_path_regex, URI_path) == None:
                        raise BadRequestException
                    if re.fullmatch(query_regex, query_str) == None:
                        raise BadRequestException
                    self.http_fullpath = (
                        "/media/sf_Ubuntu_Web_Assignment/Documents" + URI_path
                    )
                    self.location_header_path = URI_path
                    self.http_query = query_str
                else:
                    URI_path = input_str
                    if re.fullmatch(absolute_path_regex, URI_path) == None:
                        raise BadRequestException
                    self.http_fullpath = (
                        "/media/sf_Ubuntu_Web_Assignment/Documents" + URI_path
                    )
                    self.location_header_path = URI_path
        else:
            raise BadRequestException

    # Parses http version
    def http_version(self, input_str):
        global server_minor_ver
        if re.fullmatch("HTTP/[\d].[\d]", input_str, re.ASCII) != None:
            segments = input_str.split("/")
            version_no = segments[1]
            version_no_seg = version_no.split(".")
            if (
                int(version_no_seg[0]) != 1
                or int(version_no_seg[1]) > 1
                or int(version_no_seg[1]) < 0
            ):
                raise VersionNotSupported
            server_minor_ver = version_no_seg[1]
        else:
            raise BadRequestException

    # Parses Header field
    def header_block_http(self, header_block_str):
        body_index = None
        http_headers_dict = {}
        host_str = None
        header_CRLF_index = header_block_str.find(CRLF)
        while header_CRLF_index != -1:
            header_temp_str = header_block_str[: header_CRLF_index + 2]
            header_re_test = re.fullmatch(
                "[!#$%&’*+\-.^‘|~\w]+:( |\t)*([\S* ](( |\t)+[\S* ])?)*( |\t)*" + CRLF,
                header_temp_str,
                re.ASCII,
            )
            if header_re_test == None:
                raise BadRequestException
            else:
                temp = header_temp_str.split(":")
                if host_str == None:
                    # Checks for existence of 'host' header field
                    host_str = re.fullmatch(
                        "host", temp[0], re.IGNORECASE
                    ).string.lower()
                http_headers_dict[temp[0].lower()] = temp[1].strip()
            # Checks for second CRLF to indicate end of header block
            if header_block_str[header_CRLF_index + 2 : header_CRLF_index + 4] == CRLF:
                if "content-length" in http_headers_dict.keys():
                    body_index = header_CRLF_index + 4
                    http_body_length = http_headers_dict["content-length"]
                    self.http_body = header_block_str[
                        body_index : body_index + int(http_body_length)
                    ]
                    self.http_body = self.http_body.rstrip()
                break
            else:
                # Shifting the overall header string forward to position right after
                # the current CRLF
                header_block_str = header_block_str[header_CRLF_index + 2 :]
                header_CRLF_index = header_block_str.find(CRLF)

        if host_str == None:
            raise BadRequestException
        if http_headers_dict[host_str].find(":") != -1:
            host_seg = http_headers_dict[host_str].split(":")
            name = host_seg[0]
            port_no = host_seg[1]
            # Checks the syntax of the host header field for hostname and port
            if re.fullmatch(host, name) == None:
                raise BadRequestException
            if re.fullmatch(port, port_no) == None:
                raise BadRequestException
        elif http_headers_dict[host_str].find(":") == -1:
            name = http_headers_dict[host_str]
            if re.fullmatch(host, name) == None:
                raise BadRequestException
        else:
            raise BadRequestException
        self.http_response_to_send = self.http_request_method(
            self.http_fullpath,
            http_headers_dict,
            self.http_response_to_send,
            self.http_body,
        )

    # Running PHP for POST request
    def php_exec_post(self, php_fname, length, body_php):
        if length == len(body_php):
            php_post_env = {
                "GATEWAY_INTERFACE": "CGI/1.1",
                "SERVER_PROTOCOL": "HTTP/1.1",
                "SCRIPT_FILENAME": f"{php_fname}",
                "REQUEST_METHOD": "POST",
                "REMOTE_HOST": "127.0.0.1",
                "CONTENT_LENGTH": f"{length}",
                "BODY": f"{body_php}",
                "CONTENT_TYPE": "application/x-www-form-urlencoded",
            }
            out = subprocess.run(
                "exec echo $BODY | php-cgi",
                capture_output=True,
                text=True,
                shell=True,
                env=php_post_env,
            ).stdout.split("\n\n")
            content_type_out = out[0]
            body_out = out[1]
            return (content_type_out, body_out)
        else:
            raise BadRequestException

    # Running PHP for GET request
    def php_exec_get(self, php_fname, php_query):
        cmd_str = f"php-cgi {php_fname}" + " " + " ".join(php_query.split("&"))
        out = subprocess.run(
            cmd_str, capture_output=True, text=True, shell=True
        ).stdout.split("\n\n")
        content_type_out = out[0]
        body_out = out[1]
        return (content_type_out, body_out)

    # Request Methods
    def GET_request(self, filepath, headers_dict, response, body):
        if response != None:
            return response
        try:
            filepath_seg = filepath.split("/")
            filename_seg = filepath_seg[len(filepath_seg) - 1].split(".")
            file_ext = filename_seg[len(filename_seg) - 1]
            if file_ext.lower() != "php":
                requested_file = open(filepath, "rb")
                resp_body = requested_file.read().decode("UTF-8").rstrip()
                response = http_response_200(resp_body, len(resp_body))
            else:
                requested_file = open(filepath, "r")
                php_output = self.php_exec_get(filepath, self.http_query)
                response = http_response_200(php_output[1], len(php_output[1]))
        except FileNotFoundError:
            print("The file requested is not found")
            response = http_response_404()
            return response
        except PermissionError:
            print("Not Allowed to access the file")
            response = http_response_403()
            return response
        except Exception as error_500:
            print(error_500)
            response = http_response_500()
            return response
        else:
            requested_file.close()
            return response

    def PUT_request(self, filepath, headers_dict, response, body):
        if response != None:
            return response
        try:
            if os.access(filepath, os.F_OK):
                requested_file = open(filepath, "wb")
                requested_file.write(bytes(body, "UTF-8"))
                requested_file.close()
                response = http_response_204()
            else:
                requested_file = open(filepath, "wb")
                requested_file.write(bytes(body, "UTF-8"))
                requested_file.close()
                response = http_response_201(self.location_header_path, body)
            return response
        except PermissionError:
            print("Not Allowed to access the file")
            response = http_response_403()
            return response
        except Exception as error_500:
            print(error_500)
            response = http_response_500()
            return response

    def POST_request(self, filepath, headers_dict, response, body):
        if response != None:
            return response
        try:
            if headers_dict["content-length"]:
                requested_file = open(filepath, "r")
                php_output = self.php_exec_post(
                    filepath, int(headers_dict["content-length"]), body
                )
                response = http_response_200(php_output[1], len(php_output[1]))
            else:
                raise ContentLengthNotFound
        except ContentLengthNotFound:
            print("The Content-Length header for POST request was not found")
            response = http_response_411()
            return response
        except FileNotFoundError:
            print("The file requested is not found")
            response = http_response_404()
            return response
        except PermissionError:
            print("Not Allowed to access the file")
            response = http_response_403()
            return response
        else:
            requested_file.close()
            return response

    def DELETE_request(self, filepath, headers_dict, response, body):
        if response != None:
            return response
        try:
            os.remove(filepath)
        except FileNotFoundError:
            print("The file requested is not found")
            response = http_response_404()
            return response
        except PermissionError:
            print("Not Allowed to access the file")
            response = http_response_403()
            return response
        else:
            text = "<html><body><h1>File Deleted</h1></body></html>"
            response = http_response_200(text, len(text))
            return response

    def HEAD_request(self, filepath, headers_dict, response, body):
        if response != None:
            return response
        try:
            filepath_seg = filepath.split("/")
            filename_seg = filepath_seg[len(filepath_seg) - 1].split(".")
            file_ext = filename_seg[len(filename_seg) - 1]
            if file_ext.lower() != "php":
                requested_file = open(filepath, "rb")
                resp_body = requested_file.read().decode("UTF-8").rstrip()
                response = http_response_200_head(len(resp_body))
            else:
                php_output = self.php_exec_get(filepath, self.http_query)
                response = http_response_200_head(len(php_output[1]))
        except FileNotFoundError:
            print("The file requested is not found")
            response = http_response_404()
            return response
        except PermissionError:
            print("Not Allowed to access the file")
            response = http_response_403()
            return response
        else:
            requested_file.read()
            requested_file.close()
            return response


# HTTP responses for 200(OK)
def http_response_200(resp_body, body_len):
    resp = f"HTTP/1.{server_minor_ver} 200 OK\r\n"
    resp += "Python Custom Server/Ubuntu 22.04 LTS\r\n"
    resp += "Accept-Ranges: bytes\r\n"
    resp += f"Content-Length: {body_len}\r\n"
    resp += "Content-Type: text/html; charset=UTF-8\r\n\r\n"
    resp += resp_body
    return resp


# HTTP response for 204 No Content for PUT
def http_response_204():
    resp = f"HTTP/1.{server_minor_ver} 204 No Content\r\n"
    resp += "Python Custom Server/Ubuntu 22.04 LTS\r\n\r\n"
    return resp


# Bad Request - error
def http_response_400():
    resp = f"HTTP/1.{server_minor_ver} 400 Bad Request\r\n"
    resp += "Python Custom Server/Ubuntu 22.04 LTS\r\n"
    text = "<html><body><h1>400: Bad Request</h1></body></html>"
    resp += f"Content-Length: {len(text)}\r\n"
    resp += "Connection: close\r\n"
    resp += "Content-Type: text/html; charset=UTF-8\r\n\r\n"
    resp += text
    return resp


# HTTP HEAD Response
def http_response_200_head(body_len):
    resp = f"HTTP/1.{server_minor_ver} 200 OK\r\n"
    resp += "Python Custom Server/Ubuntu 22.04 LTS\r\n"
    resp += "Accept-Ranges: bytes\r\n"
    resp += f"Content-Length: {body_len}\r\n"
    resp += "Content-Type: text/html; charset=UTF-8\r\n\r\n"
    return resp


# Internal Server Error - error
def http_response_500():
    resp = f"HTTP/1.{server_minor_ver} 500 Internal Server Error\r\n"
    resp += "Python Custom Server/Ubuntu 22.04 LTS\r\n"
    text = "<html><body><h1>500: Internal Server Error</h1></body></html>"
    resp += f"Content-Length: {len(text)}\r\n"
    resp += "Connection: close\r\n"
    resp += "Content-Type: text/html; charset=UTF-8\r\n\r\n"
    resp += text
    return resp


# PUT success code
def http_response_201(put_location, put_body):
    resp = f"HTTP/1.{server_minor_ver} 201 Created\r\n"
    resp += "Python Custom Server/Ubuntu 22.04 LTS\r\n"
    resp += f"Location: {put_location}\r\n"
    resp += "Accept-Ranges: bytes\r\n"
    resp += f"Content-Length: {len(put_body)}\r\n"
    resp += "Content-Type: text/html; charset=UTF-8\r\n\r\n"
    resp += put_body
    return resp


# No Permission to access file - error
def http_response_403():
    resp = f"HTTP/1.{server_minor_ver} 403 Access Denied\r\n"
    resp += "Python Custom Server/Ubuntu 22.04 LTS\r\n"
    text = "<html><body><h1>403 Access Denied</h1></body></html>"
    resp += f"Content-Length: {len(text)}\r\n"
    resp += "Connection: close\r\n"
    resp += "Content-Type: text/html; charset=UTF-8\r\n\r\n"
    resp += text
    return resp


# Not Found - error
def http_response_404():
    resp = f"HTTP/1.{server_minor_ver} 404 Not Found\r\n"
    resp += "Python Custom Server/Ubuntu 22.04 LTS\r\n"
    text = "<html><body><h1>404 Not Found</h1></body></html>"
    resp += f"Content-Length: {len(text)}\r\n"
    resp += "Connection: close\r\n"
    resp += "Content-Type: text/html; charset=UTF-8\r\n\r\n"
    resp += text
    return resp


# POST - No Content Length - Error
def http_response_411():
    resp = f"HTTP/1.{server_minor_ver} 411 Length Required\r\n"
    resp += "Python Custom Server/Ubuntu 22.04 LTS\r\n"
    resp += "Connection: close\r\n\r\n"
    return resp


# HTTP Method Not Implemented - Error
def http_response_501():
    resp = f"HTTP/1.{server_minor_ver} 501 HTTP Method Not Supported\r\n"
    resp += "Python Custom Server/Ubuntu 22.04 LTS\r\n"
    text = "<html><body><h1>501 HTTP Method Not Supported</h1></body></html>"
    resp += f"Content-Length: {len(text)}\r\n"
    resp += "Connection: close\r\n"
    resp += "Content-Type: text/html; charset=UTF-8\r\n\r\n"
    resp += text
    return resp


# Version not supported - Error
def http_response_505():
    resp = f"HTTP/1.{server_minor_ver} 505 Version Not Supported\r\n"
    resp += "Python Custom Server/Ubuntu 22.04 LTS\r\n"
    text = "<html><body><h1>505 Version Not Supported</h1></body></html>"
    resp += f"Content-Length: {len(text)}\r\n"
    resp += "Connection: close\r\n"
    resp += "Content-Type: text/html; charset=UTF-8\r\n\r\n"
    resp += text
    return resp


def https_conn_handler(conn, x509, privatekey):
    http_obj = http_session()
    resp = ""
    with warnings.catch_warnings():
        warnings.simplefilter(action="ignore", category=DeprecationWarning)
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile=x509, keyfile=privatekey, password=None)
    tls_conn = context.wrap_socket(conn, server_side=True)
    recv_req = tls_conn.recv(2048)
    if recv_req != None:
        resp = http_obj.http_request_message(recv_req.decode("UTF-8"))
    tls_conn.send(resp.encode("UTF-8"))
    del http_obj
    tls_conn.close()


def http_conn_handler(conn):
    http_obj = http_session()
    resp = ""
    recv_req = conn.recv(2048)
    if recv_req != None:
        resp = http_obj.http_request_message(recv_req.decode("UTF-8"))
    print(resp)
    conn.send(resp.encode("UTF-8"))
    del http_obj
    conn.close()


def main(
    ip_addr_listen: str, port_listen: int, x509_file_path=None, private_key_path=None,
):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((ip_addr_listen, port_listen))
        server.listen(5)
        if x509_file_path:
            if private_key_path:
                while True:
                    conn, addr = server.accept()
                    t = threading.Thread(
                        target=https_conn_handler,
                        args=(conn, x509_file_path, private_key_path,),
                    )
                    t.start()
            else:
                sys.exit(15)  # Private key not provided
        else:
            while True:
                conn, addr = server.accept()
                t = threading.Thread(target=http_conn_handler, args=(conn,))
                t.start()
    except Exception as error:
        print(error)
        server.close()

    # with open(file_name, "rb") as http_request_txt:
    #     request_text = http_request_txt.read().decode("UTF-8")
    #     http_request_message(request_text)
    #     print(http_response_to_send)


if __name__ == "__main__":
    typer.run(main)

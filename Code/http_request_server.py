import re
import typer
import socket
import threading
import warnings
import pytz
import ssl
import sys
import os
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
# Global flag for HEAD HTTP method
http_head_flag = 0
token_regex = re.compile("[!#$%&’*+\-.^‘|~\w]+", re.ASCII)
# Regex for the URI in the request
absolute_path_regex = re.compile(
    "(/([\w.\-~]|[%][0-9A-Fa-f][0-9A-Fa-f]|[!$&'()*+,;=]|[:]|[@])*)+", re.ASCII,
)
query_regex = re.compile(
    "([\w.\-~]|[%][0-9A-Fa-f][0-9A-Fa-f]|[!$&'()*+,;=]|[:]|[@]|[/]|[?])*", re.ASCII,
)
body_index = None
http_response_to_send = None
CRLF = "\r\n"

# Defining exceptions for HTTP errors
class BadRequestException(Exception):
    print("the HTTP request is ill-formed")


class VersionNotSupported(Exception):
    print("The HTTP version of the request is not supported")


class MethodNotImplemented(Exception):
    print("The HTTP method in the request is not supported")


# Parses HTTP request
def http_request_message(input_http_str: str):
    global http_response_to_send
    first_CRLF = input_http_str.find(CRLF)
    if first_CRLF != -1:
        request_start_line_http(input_http_str[:first_CRLF])
        header_block_http(input_http_str[first_CRLF + 2 :])
    return http_response_to_send
    # if http_response_to_send == None:
    #     if http_head_flag:
    #         http_response_to_send = http_response_200_head()
    #     else:
    #         http_response_to_send = http_response_200()


# Parses HTTP Request Line
def request_start_line_http(input_str: str):
    if input_str.find(" ") != -1:
        str_segments = input_str.split(" ")
        http_method(str_segments[0])
        request_target(str_segments[1])
        http_version(str_segments[2])


# HTTP responses for different HTTP request
def http_method(input: str):
    global http_response_to_send
    global http_head_flag
    try:
        if re.fullmatch(token_regex, input) != None:
            if input == "GET":
                pass
            elif input == "POST":
                pass
            elif input == "PUT":
                pass
            elif input == "DELETE":
                pass
            elif input == "HEAD":
                # Sets the flag to send the response for HEAD request
                http_head_flag = 1
            else:
                raise MethodNotImplemented
        else:
            raise BadRequestException
    except BadRequestException:
        http_response_to_send = http_response_400()
    except:
        http_response_to_send = http_response_500()
    finally:
        pass


# Parses URI from request line
def request_target(input_str: str):
    global http_response_to_send
    try:
        if re.match("/", input_str) != None:
            if input_str == "/":
                pass
            else:
                if input_str.find("?") != -1:
                    input_str_seg = input_str.split("?")
                    URI_path = input_str_seg[0]
                    query_str = input_str_seg[1]
                    if re.fullmatch(absolute_path_regex, URI_path) == None:
                        raise BadRequestException
                    if re.fullmatch(query_regex, query_str) == None:
                        raise BadRequestException
                else:
                    URI_path = input_str
                    if re.fullmatch(absolute_path_regex, URI_path) == None:
                        raise BadRequestException
        else:
            raise BadRequestException
    except BadRequestException:
        http_response_to_send = http_response_400()
    except:
        http_response_to_send = http_response_500()
    finally:
        pass


# Parses http version
def http_version(input_str: str):
    global http_response_to_send
    global server_minor_ver
    try:
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
    except BadRequestException:
        http_response_to_send = http_response_400()
    except:
        http_response_to_send = http_response_500()
    finally:
        pass


# Parses Header field
def header_block_http(header_block_str: str):
    global http_response_to_send
    global body_index
    http_headers_dict = {}
    host_str = None
    header_CRLF_index = header_block_str.find(CRLF)
    try:
        while header_CRLF_index != -1:
            header_temp_str = header_block_str[: header_CRLF_index + 2]
            if (
                re.fullmatch(
                    "[!#$%&’*+\-.^‘|~\w]+:( |\t)*([\S ](( |\t)+[\S ])?)*( |\t)*" + CRLF,
                    header_temp_str,
                    re.ASCII,
                )
                == None
            ):
                raise BadRequestException
            else:
                temp = header_temp_str.split(":")
                if host_str == None:
                    # Checks for existence of 'host' header field
                    host_str = re.fullmatch("host", temp[0], re.IGNORECASE).string
                http_headers_dict[temp[0]] = temp[1].strip()
            # Checks for second CRLF to indicate end of header block
            if header_block_str[header_CRLF_index + 2 : header_CRLF_index + 4] == CRLF:
                body_index = header_CRLF_index + 4
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
            port = host_seg[1]
            # Checks the syntax of the host header field for hostname and port
            if host_name_verify(name) == None:
                raise BadRequestException
            if host_port_verify(port) == None:
                raise BadRequestException
        elif http_headers_dict[host_str].find(":") == -1:
            name = http_headers_dict[host_str]
            host_name_verify(name)
        else:
            raise BadRequestException
    except BadRequestException:
        http_response_to_send = http_response_400()
    except:
        http_response_to_send = http_response_500()
    finally:
        pass


def host_name_verify(name):
    return re.fullmatch(host, name)


def host_port_verify(port_no):
    return re.fullmatch(port, port_no)


# Request Methods
def GET_request(filepath):
    try:
        requested_file = open(filepath, "r")
    except FileNotFoundError:
        print("The file requested is not found")
        http_response_404()
    except PermissionError:
        print("Not Allowed to access the file")
        http_response_403()
    except:
        http_response_500()
    else:
        requested_file.read()
        requested_file.close()
    pass


def PUT_request(filepath, content):
    try:
        requested_file = open(filepath, "w")
    except FileNotFoundError:
        print("The file requested is not found")
        http_response_404()
    except PermissionError:
        print("Not Allowed to access the file")
        http_response_403()
    except:
        http_response_500()
    else:
        requested_file.write(content)
        requested_file.close()


def POST_request():
    pass


def DELETE_request(filepath):
    try:
        os.remove(filepath)
    except FileNotFoundError:
        print("The file requested is not found")
        http_response_404()
    except PermissionError:
        print("Not Allowed to access the file")
        http_response_403()
    except:
        http_response_500()


# HTTP responses for 200(OK)
def http_response_200():
    resp = f"HTTP/1.{server_minor_ver} 200 OK\r\n"
    resp += "Server: Apache/2.4.54 (Unix)\r\n"
    resp += "Content-Location: index.html.en\r\n"
    resp += "Accept-Ranges: bytes\r\n"
    resp += "Content-Length: 45\r\n"
    resp += "Content-Type: text/html\r\n\r\n"
    resp += "<html><body><h1>It works!</h1></body></html>"
    return resp


# Bad Request
def http_response_400():
    resp = f"HTTP/1.{server_minor_ver} 400 Bad Request\r\n"
    resp += "Server: Apache/2.4.54 (Unix)\r\n"
    resp += "Content-Location: index.html.en\r\n"
    resp += "Accept-Ranges: bytes\r\n"
    resp += "Content-Length: 45\r\n"
    resp += "Content-Type: text/html\r\n\r\n"
    resp += "<html><body><h1>It works!</h1></body></html>"
    return resp


# HTTP HEAD Response
def http_response_200_head():
    resp = f"HTTP/1.{server_minor_ver} 200 OK\r\n"
    resp += "Server: Apache/2.4.54 (Unix)\r\n"
    resp += "Content-Location: index.html.en\r\n"
    resp += "Accept-Ranges: bytes\r\n"
    resp += "Content-Length: 45\r\n"
    resp += "Content-Type: text/html\r\n\r\n"
    return resp


# Internal Server Error
def http_response_500():
    resp = f"HTTP/1.{server_minor_ver} 500 Internal Server Error\r\n"
    resp += "Server: Apache/2.4.54 (Unix)\r\n"
    resp += "Content-Length: 226\r\n"
    resp += "Connection: close\r\n"
    resp += "Content-Type: text/html; charset=iso-8859-1\r\n\r\n"
    resp += "<html><body><h1>500: Internal Server Error</h1></body></html>"
    return resp


# PUT success code
def http_response_201():
    pass


# No Permission to access file
def http_response_403():
    pass


# Not Found
def http_response_404():
    pass


# POST - No Content Length
def http_response_411():
    pass


# HTTP Method Not Implemented
def http_response_501():
    pass


# Version not supported
def http_response_505():
    pass


def https_conn_handler(conn, x509, privatekey):
    with warnings.catch_warnings():
        warnings.simplefilter(action="ignore", category=DeprecationWarning)
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile=x509, keyfile=privatekey, password=None)
    tls_conn = context.wrap_socket(conn, server_side=True)
    recv_req = tls_conn.recv(2048)
    while recv_req:
        resp += recv_req.decode("UTF-8")
        recv_req = tls_conn.recv(2048)
    resp = http_request_message(recv_req)
    tls_conn.send(resp.encode("UTF-8"))
    tls_conn.close()


def http_conn_handler(conn):
    recv_req = conn.recv(2048)
    while recv_req:
        resp += recv_req.decode("UTF-8")
        recv_req = conn.recv(2048)
    resp = http_request_message(recv_req)
    conn.send(resp.encode("UTF-8"))
    conn.close()


# Logger
def http_request_logger(request):
    with open("http_log.txt", "w") as http_log:
        if request.find(CRLF) != -1:
            datetime_NY = datetime.now(tz_NY)
            datetime_NY_str = datetime_NY.strftime("%d %b, %Y", "%H:%M:%S")
            http_log.write(datetime_NY_str + request[0, request.find(CRLF)])


# Accepts a file name from the user
def main(
    ip_addr_listen: str,
    port_listen: int,
    x509_file_path: str = None,
    private_key_path: str = None,
):

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
        else:
            sys.exit(15)  # Private key not provided
    else:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=http_conn_handler, args=(conn,))

    # with open(file_name, "rb") as http_request_txt:
    #     request_text = http_request_txt.read().decode("UTF-8")
    #     http_request_message(request_text)
    #     print(http_response_to_send)


if __name__ == "__main__":
    typer.run(main)
import re

server_minor_ver = None
token_regex = re.compile("[!#$%&’*+\-.^‘|~\w]+")
absolute_path_regex = re.compile(
    "(/ ( [\w.\-~] | [%][0-9A-Fa-f][0-9A-Fa-f] | [!$&'()*+,;=] |\
     [:] | [@] )* )+",
    re.X,
)
query_regex = re.compile(
    "( [\w.\-~] | [%][0-9A-Fa-f][0-9A-Fa-f] | [!$&'()*+,;=] |\
     [:] | [@] | [/] | [?] )*",
    re.X,
)
body_index = None
CRLF = "\r\n"

# Parses HTTP request
def http_request_message(input_http_str: str):
    first_CRLF = input_http_str.find(CRLF)
    if first_CRLF != -1:
        request_start_line_http(input_http_str[:first_CRLF])
        header_block_http(input_http_str[first_CRLF + 2 :])
    else:
        raise Exception("Invalid Syntax")


# Parses HTTP Request Line
def request_start_line_http(input_str: str):
    if input_str.find(" ") != -1:
        str_segments = input_str.split(" ")
        http_method(str_segments[0])
        request_target(str_segments[1])
        http_version(str_segments[2])


# TODO: Add HTTP responses
def http_method(input: str):
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
            pass
        else:
            raise Exception("Invalid Method")
    else:
        raise Exception("Invalid Method")


# Parses URI from request line
def request_target(input_str: str):
    if re.match("/", input_str) != None:
        if input_str == "/":
            pass
        else:
            if input_str.find("?") != -1:
                input_str_seg = input_str.split("?")
                URI_path = input_str_seg[0]
                query_str = input_str_seg[1]
                if re.match(absolute_path_regex, URI_path) == None:
                    raise Exception("Invalid syntax")
                if re.match(query_regex, query_str) == None:
                    raise Exception("Invalid syntax")
                # if query_str.find("&") != -1:
                #     query_str_seg = query_str.split("&")
                #     for query_pair in query_str_seg:
                #         if re.match("([\S]+)=([\S]+)", query_pair) == None:
                #             raise Exception("Invalid syntax")
            else:
                URI_path = input_str
                if re.match(absolute_path_regex, URI_path) == None:
                    raise Exception("Invalid syntax")
    else:
        raise Exception("Invalid syntax")


# Parses http version
def http_version(input_str: str):
    global server_minor_ver
    if re.fullmatch("HTTP/[\d].[\d]", input_str) != None:
        segments = input_str.split("/")
        version_no = segments[1]
        version_no_seg = version_no.split(".")
        if int(version_no_seg[0]) > 1:
            raise Exception("Invalid version")
        server_minor_ver = version_no_seg[1]
    else:
        raise Exception("Invalid version")


def host_name_verify(name):
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
    host = re.compile(f"{IP_literal}|{IPv4addr}|{reg_name}")
    return re.match(host, name)


def host_port_verify(port_no):
    port = re.compile("[\d]*")
    return re.match(port, port_no)


# Parses Header field
def header_block_http(header_block_str: str):
    global body_index
    http_headers_dict = {}
    host_str = None
    header_CRLF_index = header_block_str.find(CRLF)
    while header_CRLF_index != -1:
        header_temp_str = header_block_str[: header_CRLF_index + 2]
        # for header_field in header_field_list:
        if (
            re.match(
                "[!#$%&’*+\-.^‘|~\w]+:( |\t)*([\S ](( |\t)+[\S ])?)*( |\t)*" + CRLF,
                header_temp_str,
                re.ASCII,
            )
            == None
        ):
            raise Exception("Invalid Header field")
        else:
            temp = header_temp_str.split(":")
            if host_str == None:
                # Checks for existence of 'host' header field
                host_str = re.match("host", temp[0], re.IGNORECASE)
            http_headers_dict[temp[0]] = temp[1]
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
        raise Exception("Bad Request")
    if http_headers_dict[host_str].find(":") != -1:
        host_seg = http_headers_dict[host_str].split(":")
        name = host_seg[0]
        port = host_seg[1]
        host_name_verify(name)
        host_port_verify(port)
    elif http_headers_dict[host_str].find(":") == -1:
        name = http_headers_dict[host_str]
        host_name_verify(name)
    else:
        raise Exception("Invalid Host")


def http_response_200():
    resp = "HTTP/1.1 200 OK\r\n\
        Server: Apache/2.4.54 (Unix)\r\n\
        Content-Location: index.html.en\r\n\
        Accept-Ranges: bytes\r\n\
        Content-Length: 45\r\n\
        Content-Type: text/html\r\n\r\n\
        <html><body><h1>It works!</h1></body></html>"
    return resp


def http_response_400():
    resp = "HTTP/1.1 400 Bad Request\r\n\
        Server: Apache/2.4.54 (Unix)\r\n\
            Content-Length: 226\r\n\
                Connection: close\r\n\
                    Content-Type: text/html; charset=iso-8859-1\r\n\r\n\
                        <html><body><h1>400:Bad Request</h1></body></html>"
    return resp


def http_response_200_head():
    resp = "HTTP/1.1 200 OK\r\n\
        Server: Apache/2.4.54 (Unix)\r\n\
        Content-Location: index.html.en\r\n\
        Accept-Ranges: bytes\r\n\
        Content-Length: 45\r\n\
        Content-Type: text/html\r\n\r\n"
    return resp


def http_response_500():
    resp = "HTTP/1.1 500 Internal Server Error\r\n\
        Server: Apache/2.4.54 (Unix)\r\n\
            Content-Length: 226\r\n\
                Connection: close\r\n\
                    Content-Type: text/html; charset=iso-8859-1\r\n\r\n\
                        <html><body><h1>500: Internal Server Error</h1></body></html>"
    return resp

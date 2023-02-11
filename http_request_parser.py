import re

server_minor_ver = None

# Parses HTTP request
def http_request_message(input_http_str: str):
    if input_http_str.find("\r\n") != -1:
        str_segments = input_http_str.split("\r\n")
        segment_no = len(str_segments)
        request_line_http(str_segments[0])
        header_http(str_segments[1 : segment_no - 2])
        body = str_segments[segment_no - 1]
    else:
        raise Exception("Invalid Syntax")


# Parses HTTP Request Line
def request_line_http(input_str: str):
    if input_str.find(" ") != -1:
        str_segments = input_str.split(" ")
        http_method(str_segments[0])
        request_target(str_segments[1])
        http_version(str_segments[2].rstrip())


# TODO: Add HTTP responses
def http_method(input: str):
    if re.match("[\w]+", input) != None:
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
                if re.match("(/[\S]+)+/?", URI_path) == None:
                    raise Exception("Invalid syntax")
                if query_str.find("&") != -1:
                    query_str_seg = query_str.split("&")
                    for query_pair in query_str_seg:
                        if re.match("([\S]+)=([\S]+)", query_pair) == None:
                            raise Exception("Invalid syntax")
            else:
                URI_path = input_str
                if re.match("(/[\S]+)+/?", URI_path) == None:
                    raise Exception("Invalid syntax")
    else:
        raise Exception("Invalid syntax")


# Parses http version
def http_version(input_str: str):
    global server_minor_ver
    if re.match("[\w]+/[\d].[\d]", input_str) != None:
        segments = input_str.split("/")
        name = segments[0]
        version_no = segments[1]
        if name != "HTTP":
            raise Exception("Invalid Protocol")
        version_no_seg = version_no.split(".")
        if int(version_no_seg[0]) > 1:
            raise Exception("Invalid version")
        server_minor_ver = version_no_seg[1]


# Parses Header field
def header_http(header_field_list: list):
    http_headers_dict = {}
    host_str = None
    for header_field in header_field_list:
        if re.match("[\S]+:( |\t)*[\S]+( |\t)*", header_field) == None:
            raise Exception("Invalid Header field")
        else:
            temp = header_field.split(":")
            temp[1] = temp[1].strip()
            if host_str == None:
                # Checks for existence of 'host' header field
                host_str = re.match("host", temp[0], re.IGNORECASE)
            http_headers_dict[temp[0]] = temp[1]

    if host_str == None:
        raise Exception("Bad Request")
    if re.match("[\S]+(:[\d]+)?", http_headers_dict[host_str]) == None:
        raise Exception("Invalid Host")


def http_response(method_str: int):
    pass

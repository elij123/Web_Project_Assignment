import re

def http_request_message(input_http_str:str):
    str_segments = input_http_str.split("\r\n")
    segment_no = len(str_segments)
    request_line_http(str_segments[0])
    header_http(str_segments[1:segment_no-1])
    # request_body_http = str_segments[segment_no-1] 

def request_line_http(input_str:str):
    str_segments = input_str.split(" ")
    http_method(str_segments[0])
    request_target(str_segments[1])
    http_version(str_segments[2].rstrip())

def http_method(input:str):
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

def request_target(input_str:str):
    if input_str == "/":
        pass
    else:
        absolute_path_pattern = re.compile("(/[\w]+)+")
        query_pattern = re.compile("(\?([\w]+)=([\w]+))")
        pass

def http_version(input_str:str):
    segments = input_str.split("/")
    name = segments[0]
    version_no = segments[1]
    if name == "HTTP":
        pass
    if version_no == "1.1" or version_no == "1.0":
        pass

def header_http(input_str:list):
    host_ = re.compile("host", flags=re.IGNORECASE)
    cache_control = re.compile("Cache-Control", flags=re.IGNORECASE)
    expect = re.compile("Expect", re.IGNORECASE)
    max_forwards = re.compile("Max-Forwards", flags=re.IGNORECASE)
    pragma = re.compile("pragma", flags=re.IGNORECASE)
    range_ = re.compile("range", flags=re.IGNORECASE)
    TE = re.compile("TE", flags=re.IGNORECASE)
    If_match = re.compile("If-match", flags=re.IGNORECASE)
    If_none_match = re.compile("If-None-Match", flags=re.IGNORECASE)
    If_Modified_Since = re.compile("If-Modified-Since", flags=re.IGNORECASE)
    If_Unmodified_Since = re.compile("If-Unmodified-Since", flags=re.IGNORECASE)
    If_Range = re.compile("If-Range", flags=re.IGNORECASE)
    Accept = re.compile("Accept", re.IGNORECASE)
    Accept_Charset = re.compile("Accept-Charset", flags=re.IGNORECASE)
    Accept_Encoding = re.compile("Accept-Encoding", flags=re.IGNORECASE)
    Accept_Language = re.compile("Accept-Language", flags=re.IGNORECASE)
    Authorization = re.compile("Authorization", flags=re.IGNORECASE)
    Proxy_Authorization = re.compile("Proxy-Authorization", re.IGNORECASE)
    From = re.compile("From", flags=re.IGNORECASE)
    Referer = re.compile("Referer", flags=re.IGNORECASE)
    User_Agent = re.compile("User-Agent", flags=re.IGNORECASE)


    for header_line in input_str:
        if re.match(host_, header_line):
            pass
        elif re.match(cache_control, header_line):
            pass
        elif re.match(expect, header_line):
            pass
        elif re.match(max_forwards, header_line):
            pass
        elif re.match(pragma, header_line):
            pass
        elif re.match(range_, header_line):
            pass
        elif re.match(TE, header_line):
            pass
        elif re.match(If_match, header_line):
            pass
        elif re.match(If_none_match, header_line):
            pass
        elif re.match(If_Modified_Since, header_line):
            pass
        elif re.match(If_Unmodified_Since, header_line):
            pass
        elif re.match(If_Range, header_line):
            pass
        elif re.match(Accept, header_line):
            pass
        elif re.match(Accept_Charset, header_line):
            pass
        elif re.match(Accept_Encoding, header_line):
            pass
        elif re.match(Accept_Language, header_line):
            pass
        elif re.match(Authorization, header_line):
            pass
        elif re.match(Proxy_Authorization, header_line):
            pass
        elif re.match(From, header_line):
            pass
        elif re.match(Referer, header_line):
            pass
        elif re.match(User_Agent, header_line):
            pass
        else:
            raise Exception("Invalid Header field")

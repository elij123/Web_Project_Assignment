with open("http_request_test_file.txt", "wb") as http_file:
    http_file.write(bytes("GET / HTTP/1.1\r\nhost: localhost\r\n\r\n", "UTF-8"))
# Writes basic GET Request


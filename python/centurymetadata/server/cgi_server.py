# cgi_server.py
import http.server
import socketserver
import os

PORT = 8001
CGI_DIR = '/home/user/Documents/Coding/Projects/centurymetadata/python/centurymetadata/server'
CGI_SCRIPT = 'server.py'

class CGIHTTPRequestHandler(http.server.CGIHTTPRequestHandler):
    def is_cgi(self):
        # This method determines if a request is for a CGI script
        return self.path.startswith('/cgi-bin/')

    def translate_path(self, path):
        # Translate the path to CGI_DIR
        path = super().translate_path(path)
        if path.startswith('/cgi-bin/'):
            path = os.path.join(CGI_DIR, path[len('/cgi-bin/'):])
        return path

def run(server_class=http.server.HTTPServer, handler_class=CGIHTTPRequestHandler):
    server_address = ('', PORT)
    httpd = server_class(server_address, handler_class)
    print(f'Starting CGI server on port {PORT}...')
    httpd.serve_forever()

if __name__ == "__main__":
    run()

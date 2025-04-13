import http.server
import socketserver
import os

PORT = 8000

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Redirect root URL to PrototypePollution/index.html
        if self.path == '/':
            self.path = '/PrototypePollutionLab/index.html'
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    print(f"Server started at http://localhost:{PORT}")
    print(f"Opening PrototypePollution/index.html by default")
    httpd.serve_forever()
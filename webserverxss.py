from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
          
            # Inicio do Corpo HTML com o formulário de pesquisa vulnerável para teste
          
            self.wfile.write(b'''
                <html>
                    <body>
                        <h1>Meu Blog</h1>
                        <section class="search">
                            <form action="/" method="GET">
                                <input type="text" placeholder="Search the blog..." name="search">
                                <button type="submit" class="button">Search</button>
                            </form>
                        </section>
                    </body>
                </html>
            ''')
        else:
            if '?' in self.path:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                if 'search' in params:
                    search_query = params['search'][0]
                    self.wfile.write(b'''
                        <html>
                            <body>
                                <h1>Search Results</h1>
                                <p>Your search query: %s</p>
                            </body>
                        </html>
                    ''' % search_query.encode('utf-8'))
                else:
                    self.wfile.write(b'<html><body><h1>No search query provided</h1></body></html>')
            else:
                self.send_response(404)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<html><body><h1>Page not found</h1></body></html>')

# função http.server do python para publicar localmente
def run():
    print('Starting server...')
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RequestHandler)
    print('Server running on localhost:8000')
    httpd.serve_forever()

if __name__ == '__main__':
    run()

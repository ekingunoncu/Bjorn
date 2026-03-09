#webapp.py
import json
import threading
import http.server
import socketserver
import logging
import sys
import signal
import os
import gzip
import io
import mimetypes
from logger import Logger
from init_shared import shared_data
from utils import WebUtils

logger = Logger(name="webapp.py", level=logging.DEBUG)

# SPA build directory
SPA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web', 'dist')

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.shared_data = shared_data
        self.web_utils = WebUtils(shared_data, logger)
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        if 'GET' not in format % args:
            logger.info("%s - - [%s] %s\n" %
                        (self.client_address[0],
                         self.log_date_time_string(),
                         format % args))

    def gzip_encode(self, content):
        out = io.BytesIO()
        with gzip.GzipFile(fileobj=out, mode="w") as f:
            f.write(content)
        return out.getvalue()

    def send_gzipped_response(self, content, content_type):
        gzipped_content = self.gzip_encode(content)
        self.send_response(200)
        self.send_header("Content-type", content_type)
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(gzipped_content)))
        self.end_headers()
        self.wfile.write(gzipped_content)

    def serve_file_gzipped(self, file_path, content_type):
        with open(file_path, 'rb') as file:
            content = file.read()
        self.send_gzipped_response(content, content_type)

    def _serve_spa_file(self, rel_path):
        """Serve a file from the SPA build directory."""
        file_path = os.path.join(SPA_DIR, rel_path)
        if os.path.isfile(file_path):
            ctype = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
            self.serve_file_gzipped(file_path, ctype)
            return True
        return False

    def _serve_spa_index(self):
        """Serve the SPA index.html for client-side routing."""
        index = os.path.join(SPA_DIR, 'index.html')
        if os.path.isfile(index):
            self.serve_file_gzipped(index, 'text/html')
            return True
        return False

    def _send_json(self, data):
        """Send a JSON response."""
        body = json.dumps(data).encode('utf-8')
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # ── API endpoints ─────────────────────────────────────
        if self.path == '/api/status':
            self.web_utils.handle_api_status(self)
        elif self.path == '/load_config':
            self.web_utils.serve_current_config(self)
        elif self.path == '/restore_default_config':
            self.web_utils.restore_default_config(self)
        elif self.path == '/get_web_delay':
            self._send_json({"web_delay": self.shared_data.web_delay})
        elif self.path == '/scan_wifi':
            self.web_utils.scan_wifi(self)
        elif self.path == '/network_data':
            self.web_utils.serve_network_data(self)
        elif self.path == '/netkb_data':
            self.web_utils.serve_netkb_data(self)
        elif self.path == '/netkb_data_json':
            self.web_utils.serve_netkb_data_json(self)
        elif self.path.startswith('/screen.png'):
            self.web_utils.serve_image(self)
        elif self.path == '/favicon.ico':
            self.web_utils.serve_favicon(self)
        elif self.path == '/manifest.json':
            self.web_utils.serve_manifest(self)
        elif self.path == '/apple-touch-icon':
            self.web_utils.serve_apple_touch_icon(self)
        elif self.path == '/get_logs':
            self.web_utils.serve_logs(self)
        elif self.path == '/list_credentials':
            self.web_utils.serve_credentials_data(self)
        elif self.path.startswith('/list_files'):
            self.web_utils.list_files_endpoint(self)
        elif self.path.startswith('/download_file'):
            self.web_utils.download_file(self)
        elif self.path.startswith('/download_backup'):
            self.web_utils.download_backup(self)
        elif self.path == '/tool_log':
            self.web_utils.handle_tool_log(self)
        # ── Legacy HTML pages ─────────────────────────────────
        elif self.path.endswith('.html'):
            legacy = os.path.join(
                self.shared_data.webdir, os.path.basename(self.path)
            )
            if os.path.isfile(legacy):
                self.serve_file_gzipped(legacy, 'text/html')
            else:
                self._serve_spa_index()
        # ── SPA static assets (/assets/*.js, *.css, fonts) ───
        elif self.path.startswith('/assets/'):
            if not self._serve_spa_file(self.path.lstrip('/')):
                self.send_response(404)
                self.end_headers()
        # ── SPA: root and all other paths → index.html ────────
        elif self.path == '/' or self.path == '/index.html':
            if not self._serve_spa_index():
                # Fallback to legacy index.html
                self.serve_file_gzipped(
                    os.path.join(self.shared_data.webdir, 'index.html'),
                    'text/html'
                )
        else:
            # Try SPA file first, then legacy, then SPA index
            if not self._serve_spa_file(self.path.lstrip('/')):
                super().do_GET()

    def do_POST(self):
        if self.path == '/save_config':
            self.web_utils.save_configuration(self)
        elif self.path == '/connect_wifi':
            self.web_utils.connect_wifi(self)
            self.shared_data.wifichanged = True
        elif self.path == '/disconnect_wifi':
            self.web_utils.disconnect_and_clear_wifi(self)
        elif self.path == '/clear_files':
            self.web_utils.clear_files(self)
        elif self.path == '/clear_files_light':
            self.web_utils.clear_files_light(self)
        elif self.path == '/initialize_csv':
            self.web_utils.initialize_csv(self)
        elif self.path == '/reboot':
            self.web_utils.reboot_system(self)
        elif self.path == '/shutdown':
            self.web_utils.shutdown_system(self)
        elif self.path == '/restart_bjorn_service':
            self.web_utils.restart_bjorn_service(self)
        elif self.path == '/backup':
            self.web_utils.backup(self)
        elif self.path == '/restore':
            self.web_utils.restore(self)
        elif self.path == '/stop_orchestrator':
            self.web_utils.stop_orchestrator(self)
        elif self.path == '/start_orchestrator':
            self.web_utils.start_orchestrator(self)
        elif self.path == '/execute_manual_attack':
            self.web_utils.execute_manual_attack(self)
        else:
            self.send_response(404)
            self.end_headers()

class WebThread(threading.Thread):
    def __init__(self, handler_class=CustomHandler, port=8000):
        super().__init__()
        self.shared_data = shared_data
        self.port = port
        self.handler_class = handler_class
        self.httpd = None

    def run(self):
        while not self.shared_data.webapp_should_exit:
            try:
                with socketserver.TCPServer(
                    ("", self.port), self.handler_class
                ) as httpd:
                    self.httpd = httpd
                    logger.info(f"Serving at port {self.port}")
                    while not self.shared_data.webapp_should_exit:
                        httpd.handle_request()
            except OSError as e:
                if e.errno == 98:
                    logger.warning(
                        f"Port {self.port} is in use, "
                        "trying the next port..."
                    )
                    self.port += 1
                else:
                    logger.error(f"Error in web server: {e}")
                    break
            finally:
                if self.httpd:
                    self.httpd.server_close()
                    logger.info("Web server closed.")

    def shutdown(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.info("Web server shutdown initiated.")

def handle_exit_web(signum, frame):
    shared_data.webapp_should_exit = True
    if web_thread.is_alive():
        web_thread.shutdown()
        web_thread.join()
    logger.info("Server shutting down...")
    sys.exit(0)

web_thread = WebThread(port=8000)

signal.signal(signal.SIGINT, handle_exit_web)
signal.signal(signal.SIGTERM, handle_exit_web)

if __name__ == "__main__":
    try:
        web_thread.start()
        logger.info("Web server thread started.")
    except Exception as e:
        logger.error(f"An exception occurred during web server start: {e}")
        handle_exit_web(signal.SIGINT, None)
        sys.exit(1)

import http.client
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

import auth_store
import multi_app

class WebAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.old_path = auth_store.DB_PATH
        cls.old_all_olts = multi_app.all_olts
        auth_store.DB_PATH = Path(cls.temp.name) / "auth.db"
        auth_store.initialize()
        auth_store.seed_user("admin", "test-admin-secret", "admin")
        auth_store.seed_user("viewer", "test-viewer-secret", "viewer")
        multi_app.all_olts = lambda: []
        cls.server = ThreadingHTTPServer(("127.0.0.1",0),multi_app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        multi_app.all_olts = cls.old_all_olts
        auth_store.DB_PATH = cls.old_path
        cls.temp.cleanup()

    def request(self, method, path, body=None, cookie=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {}
        if body is not None:
            body = urlencode(body)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie: headers["Cookie"] = cookie
        connection.request(method,path,body=body,headers=headers)
        response = connection.getresponse()
        result = (response.status,dict(response.getheaders()),response.read())
        connection.close()
        return result

    def login(self, username, password):
        status,headers,_ = self.request("POST","/login",{"username":username,"password":password})
        self.assertEqual(status,303)
        return headers["Set-Cookie"].split(";",1)[0]

    def test_unauthenticated_and_viewer_permissions(self):
        self.assertEqual(self.request("GET","/")[0],303)
        self.assertEqual(self.request("GET","/api/state")[0],401)
        cookie = self.login("viewer","test-viewer-secret")
        status,_,body = self.request("GET","/api/state",cookie=cookie)
        self.assertEqual(status,200)
        self.assertEqual(body,b"[]")
        self.assertEqual(self.request("GET","/admin",cookie=cookie)[0],403)
        token = cookie.split("=",1)[1]
        csrf = auth_store.current_session(token)["csrf"]
        self.assertEqual(self.request("POST","/admin/viewer/enable",{"enabled":"0","csrf":csrf},cookie)[0],403)

    def test_admin_and_csrf(self):
        cookie = self.login("admin","test-admin-secret")
        self.assertEqual(self.request("GET","/admin",cookie=cookie)[0],200)
        self.assertEqual(self.request("POST","/admin/viewer/enable",{"enabled":"0","csrf":"wrong"},cookie)[0],403)

if __name__ == "__main__": unittest.main()

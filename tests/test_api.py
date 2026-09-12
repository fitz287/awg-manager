import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app

class TestFastAPIEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        from app.database import set_setting
        from app.auth import hash_password, DEFAULT_ADMIN_PASS, DEFAULT_ADMIN_USER
        set_setting("admin_username", DEFAULT_ADMIN_USER)
        set_setting("admin_password_hash", hash_password(DEFAULT_ADMIN_PASS))

    def test_01_unauthorized_redirect(self):
        # Unauthenticated request to / should redirect to /login
        res = self.client.get("/", follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.headers["location"], "/login")

        # Unauthenticated request to API should return 401
        res_api = self.client.get("/api/settings")
        self.assertEqual(res_api.status_code, 401)

    def test_02_login_and_access(self):
        # Login
        login_res = self.client.post("/api/auth/login", json={"username": "admin", "password": "password"})
        self.assertEqual(login_res.status_code, 200)
        self.assertIn("session_token", self.client.cookies)

        # Now access /
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("AmneziaWG", res.text)
        self.assertIn("Подключения AWG", res.text)

        # Access settings
        res_settings = self.client.get("/api/settings")
        self.assertEqual(res_settings.status_code, 200)

    def test_03_create_connection_api(self):
        # Make sure client is authenticated
        self.client.post("/api/auth/login", json={"username": "admin", "password": "password"})

        payload = {
            "name": "awg99",
            "protocol_version": "3.1",
            "x_subnet": 99,
            "listen_port": 51899,
            "xray_port": 7099,
            "table_num": 199,
            "fwmark": 99,
        }
        res = self.client.post("/api/connections", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["name"], "awg99")

        # Cleanup
        del_res = self.client.delete(f"/api/connections/{data['id']}")
        self.assertEqual(del_res.status_code, 200)

    def test_04_multi_user_access_and_permissions(self):
        # 1. Login as admin and create connection + user with password
        self.client.post("/api/auth/login", json={"username": "admin", "password": "password"})

        # Create connection for testing
        conn_res = self.client.post("/api/connections", json={
            "name": "awg77",
            "protocol_version": "1.0",
            "x_subnet": 77,
            "listen_port": 51877,
            "xray_port": 7077,
            "table_num": 177,
            "fwmark": 77,
        })
        self.assertEqual(conn_res.status_code, 200)
        conn_id = conn_res.json()["id"]

        # Create user with password
        user_res = self.client.post("/api/users", json={
            "connection_id": conn_id,
            "username": "client_tester",
            "notes": "Test client",
            "password": "secret_password_123",
        })
        self.assertEqual(user_res.status_code, 200)
        user_data = user_res.json()
        user_id = user_data["user_id"]
        user_y = user_data["user_index_y"]
        self.assertTrue(user_data["has_password"])

        # 2. Logout admin
        self.client.post("/api/auth/logout")

        # 3. Try logging in with wrong password
        bad_login = self.client.post("/api/auth/login", json={
            "username": "client_tester",
            "password": "wrong_password",
        })
        self.assertEqual(bad_login.status_code, 401)

        # 4. Login with correct password
        good_login = self.client.post("/api/auth/login", json={
            "username": "client_tester",
            "password": "secret_password_123",
        })
        self.assertEqual(good_login.status_code, 200)
        self.assertEqual(good_login.json()["role"], "user")

        # 5. Check /api/auth/me
        me_res = self.client.get("/api/auth/me")
        self.assertEqual(me_res.status_code, 200)
        self.assertEqual(me_res.json()["username"], "client_tester")
        self.assertEqual(me_res.json()["role"], "user")

        # 6. Verify RBAC restrictions: regular user CANNOT access admin endpoints
        self.assertEqual(self.client.get("/api/connections").status_code, 403)
        self.assertEqual(self.client.get("/api/settings").status_code, 403)
        self.assertEqual(self.client.get("/api/users").status_code, 403)
        self.assertEqual(self.client.post("/api/connections", json={"x_subnet": 50}).status_code, 403)

        # 7. User accesses Client Portal API (/api/my/*)
        info_res = self.client.get("/api/my/info")
        self.assertEqual(info_res.status_code, 200)
        self.assertEqual(info_res.json()["subnet"], f"10.77.{user_y}.0/24")

        # 8. User creates their own device
        dev_res = self.client.post("/api/my/devices", json={"label": "Tester Phone", "use_psk": True})
        self.assertEqual(dev_res.status_code, 200)
        peer_id = dev_res.json()["peer_id"]
        self.assertEqual(dev_res.json()["client_ip"], f"10.77.{user_y}.1")

        # 9. User fetches config and downloads .conf
        cfg_res = self.client.get(f"/api/my/devices/{peer_id}/config")
        self.assertEqual(cfg_res.status_code, 200)
        self.assertIn("[Interface]", cfg_res.text)
        self.assertIn(f"10.77.{user_y}.1/32", cfg_res.text)

        # 10. User changes password
        pw_res = self.client.post("/api/my/change-password", json={
            "old_password": "secret_password_123",
            "new_password": "new_secret_password_456",
        })
        self.assertEqual(pw_res.status_code, 200)

        # 11. User deletes device
        del_dev_res = self.client.delete(f"/api/my/devices/{peer_id}")
        self.assertEqual(del_dev_res.status_code, 200)

        # 12. Cleanup: Login as admin and delete connection & user
        self.client.post("/api/auth/login", json={"username": "admin", "password": "password"})
        self.client.delete(f"/api/users/{user_id}")
        self.client.delete(f"/api/connections/{conn_id}")

    def test_05_servers_api_and_multi_node(self):
        # 1. Login as admin
        res = self.client.post("/api/auth/login", json={"username": "admin", "password": "password"})
        self.assertEqual(res.status_code, 200)

        # 2. List servers
        res_list = self.client.get("/api/servers")
        self.assertEqual(res_list.status_code, 200)
        servers = res_list.json()
        self.assertIsInstance(servers, list)

        # 3. Create a test node
        node_payload = {
            "name": "Node Test 01",
            "host": "127.0.0.1",
            "ssh_port": 2222,
            "ssh_user": "root",
            "ssh_password": "testpassword",
            "api_port": 8089,
        }
        res_create = self.client.post("/api/servers", json=node_payload)
        self.assertEqual(res_create.status_code, 200)
        node_id = res_create.json()["server_id"]

        # 4. Get server info & logs
        res_get = self.client.get(f"/api/servers/{node_id}")
        self.assertEqual(res_get.status_code, 200)
        self.assertEqual(res_get.json()["name"], "Node Test 01")

        res_logs = self.client.get(f"/api/servers/{node_id}/logs")
        self.assertEqual(res_logs.status_code, 200)

        # 5. Create connection on this node
        conn_res = self.client.post("/api/connections", json={
            "name": "awgtestnode",
            "protocol_version": "3.1",
            "x_subnet": 99,
            "server_id": node_id,
        })
        self.assertEqual(conn_res.status_code, 200)
        conn_id = conn_res.json()["id"]

        # 6. Deleting server with active connection must fail
        del_server_res = self.client.delete(f"/api/servers/{node_id}")
        self.assertEqual(del_server_res.status_code, 400)

        # 7. Cleanup connection then delete server
        del_conn_res = self.client.delete(f"/api/connections/{conn_id}")
        self.assertEqual(del_conn_res.status_code, 200)

        del_server_ok = self.client.delete(f"/api/servers/{node_id}")
        self.assertEqual(del_server_ok.status_code, 200)

    def test_06_custom_params_and_connection_status(self):
        self.client.post("/api/auth/login", json={"username": "admin", "password": "password"})

        custom_params = {
            "Jc": "4",
            "Jmin": "50",
            "Jmax": "1000",
            "S1": "123",
            "S2": "52",
            "S3": "24",
            "S4": "12",
            "H1": "691076",
            "H2": "3050423",
            "H3": "48076392",
            "H4": "710707124",
            "ContentPaddingAddition": "10-100",
            "RekeyAfterTime": "100-120",
            "RekeyTimeout": "3-7",
            "RejectAfterTime": "150-180",
            "KeepaliveTimeout": "5-15",
            "MaxHandshakeAttempts": "15-20",
            "RandomTrailers": "on",
        }

        payload = {
            "name": "awg88",
            "protocol_version": "3.1",
            "x_subnet": 88,
            "listen_port": 51888,
            "xray_port": 7088,
            "table_num": 188,
            "fwmark": 88,
            "params": custom_params,
        }

        res = self.client.post("/api/connections", json=payload)
        self.assertEqual(res.status_code, 200)
        conn_id = res.json()["id"]

        # Check status endpoint
        status_res = self.client.get(f"/api/connections/{conn_id}/status")
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.json()
        self.assertEqual(status_data["name"], "awg88")
        self.assertEqual(status_data["listen_port"], 51888)
        self.assertEqual(status_data["params"]["Jc"], 4)
        self.assertEqual(status_data["params"]["S1"], 123)
        self.assertEqual(status_data["params"]["RekeyAfterTime"], "100-120")
        self.assertIn("peers", status_data)

        # Cleanup
        del_res = self.client.delete(f"/api/connections/{conn_id}")
        self.assertEqual(del_res.status_code, 200)

    def test_07_update_connection_params(self):
        # 1. Login
        self.client.post("/api/auth/login", json={"username": "admin", "password": "password"})

        # 2. Create initial connection
        payload = {
            "name": "awg91",
            "protocol_version": "1.0",
            "x_subnet": 91,
            "listen_port": 51891,
            "xray_port": 7091,
            "table_num": 191,
            "fwmark": 91,
        }
        res = self.client.post("/api/connections", json=payload)
        self.assertEqual(res.status_code, 200)
        conn_id = res.json()["id"]

        # 3. Update parameters via PUT
        new_params = {
            "protocol_version": "3.1",
            "Jc": 4,
            "Jmin": 50,
            "Jmax": 1000,
            "S1": 123,
            "S2": 52,
            "S3": 24,
            "S4": 12,
            "H1": 691076,
            "H2": 3050423,
            "H3": 48076392,
            "H4": 710707124,
            "HeaderProtectionKey": "abcdef1234567890abcdef1234567890abcdef12345=",
            "ContentPaddingAddition": "10-100",
            "RekeyAfterTime": "100-120",
            "RekeyTimeout": "3-7",
            "RejectAfterTime": "150-180",
            "KeepaliveTimeout": "5-15",
            "MaxHandshakeAttempts": "15-20",
            "RandomTrailers": "on",
        }
        put_res = self.client.put(f"/api/connections/{conn_id}", json={
            "listen_port": 20091,
            "protocol_version": "3.1",
            "params": new_params,
        })
        self.assertEqual(put_res.status_code, 200)
        data = put_res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["connection"]["listen_port"], 20091)
        self.assertEqual(data["connection"]["protocol_version"], "3.1")
        self.assertEqual(data["connection"]["params"]["Jc"], 4)
        self.assertEqual(data["connection"]["params"]["S1"], 123)
        self.assertEqual(data["connection"]["params"]["RekeyAfterTime"], "100-120")

        # 4. Verify server config text contains new params
        conf_res = self.client.get(f"/api/connections/{conn_id}/config")
        self.assertEqual(conf_res.status_code, 200)
        conf_text = conf_res.text
        self.assertIn("ListenPort = 20091", conf_text)
        self.assertIn("Jc = 4", conf_text)
        self.assertIn("S1 = 123", conf_text)
        self.assertIn("S4 = 12", conf_text)
        self.assertIn("H1 = 691076", conf_text)
        self.assertIn("RekeyAfterTime = 100-120", conf_text)

        # Cleanup
        del_res = self.client.delete(f"/api/connections/{conn_id}")
        self.assertEqual(del_res.status_code, 200)

    def test_08_awg2_ranges_and_signatures(self):
        # Authenticate
        self.client.post("/api/auth/login", json={"username": "admin", "password": "password"})

        # Clean up if leftover exists
        from app.database import get_connection_by_name, delete_connection
        existing = get_connection_by_name("awg2test")
        if existing:
            delete_connection(existing["id"])

        awg2_params = {
            "Jc": 6,
            "Jmin": 10,
            "Jmax": 50,
            "S1": 24,
            "S2": 133,
            "S3": 10,
            "S4": 6,
            "H1": "1776002204-1856261239",
            "H2": "2131483220-2139616315",
            "H3": "2145540006-2146234083",
            "H4": "2146328963-2146998719",
            "I1": "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>",
        }
        create_res = self.client.post("/api/connections", json={
            "name": "awg2test",
            "protocol_version": "2.0",
            "x_subnet": 82,
            "listen_port": 51882,
            "xray_port": 7082,
            "table_num": 182,
            "fwmark": 82,
            "params": awg2_params,
        })
        self.assertEqual(create_res.status_code, 200)
        conn_id = create_res.json()["id"]

        try:
            # Verify ranges are preserved in DB
            get_res = self.client.get(f"/api/connections/{conn_id}/status")
            self.assertEqual(get_res.status_code, 200)
            c_data = get_res.json()
            self.assertEqual(c_data["params"]["H1"], "1776002204-1856261239")
            self.assertEqual(c_data["params"]["H2"], "2131483220-2139616315")
            self.assertEqual(c_data["params"]["H3"], "2145540006-2146234083")
            self.assertEqual(c_data["params"]["H4"], "2146328963-2146998719")
            self.assertEqual(c_data["params"]["I1"], awg2_params["I1"])

            # Verify config text generation contains the exact ranges
            conf_res = self.client.get(f"/api/connections/{conn_id}/config")
            self.assertEqual(conf_res.status_code, 200)
            self.assertIn("H1 = 1776002204-1856261239", conf_res.text)
            self.assertIn("H2 = 2131483220-2139616315", conf_res.text)
            self.assertIn("H3 = 2145540006-2146234083", conf_res.text)
            self.assertIn("H4 = 2146328963-2146998719", conf_res.text)
            self.assertIn(awg2_params["I1"], conf_res.text)
        finally:
            # Cleanup
            self.client.delete(f"/api/connections/{conn_id}")

if __name__ == "__main__":
    unittest.main()


import os
import sys
import unittest
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import (
    init_db,
    create_connection,
    get_all_connections,
    get_next_connection_index,
    get_next_table_and_mark,
    create_user,
    get_all_users_with_peers,
    create_peer,
    get_peer_by_id,
    get_connection_by_id,
)
from app.awg_crypto import (
    generate_keypair,
    generate_awg_params,
)
from app.awg_manager import (
    write_server_config,
    generate_server_config_text,
    generate_client_config_text,
    get_interface_conf_file,
    get_interface_symlink,
)


class TestAWGPanel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        from app.database import get_db
        with get_db() as conn:
            conn.execute("DELETE FROM peer_configs")
            conn.execute("DELETE FROM users")
            conn.execute("DELETE FROM connections")

    def test_01_connection_and_table_increment(self):
        print("\n--- Testing Connection Creation & Table Increment ---")
        # Connection 1
        t1, m1 = get_next_table_and_mark()
        self.assertEqual(t1, 101)
        self.assertEqual(m1, 1)

        p1_priv, p1_pub = generate_keypair()
        params_v1 = generate_awg_params("1.0")
        
        c1_id = create_connection(
            name="awg1",
            index_num=1,
            protocol_version="1.0",
            x_subnet=13,
            listen_port=51820,
            server_private_key=p1_priv,
            server_public_key=p1_pub,
            xray_port=7010,
            table_num=t1,
            fwmark=m1,
            params=params_v1,
        )
        self.assertTrue(c1_id > 0)

        # Connection 2: table should be 102, mark should be 2
        t2, m2 = get_next_table_and_mark()
        self.assertEqual(t2, 102)
        self.assertEqual(m2, 2)

        p2_priv, p2_pub = generate_keypair()
        params_v2 = generate_awg_params("2.0")
        c2_id = create_connection(
            name="awg2",
            index_num=2,
            protocol_version="2.0",
            x_subnet=14,
            listen_port=51821,
            server_private_key=p2_priv,
            server_public_key=p2_pub,
            xray_port=7010,
            table_num=t2,
            fwmark=m2,
            params=params_v2,
        )
        self.assertTrue(c2_id > 0)

        # Connection 3: AWG 3.1, table 103, mark 3
        t3, m3 = get_next_table_and_mark()
        self.assertEqual(t3, 103)
        self.assertEqual(m3, 3)

        p3_priv, p3_pub = generate_keypair()
        params_v3 = generate_awg_params("3.1")
        self.assertIn("HeaderProtectionKey", params_v3)
        self.assertIn("ContentPaddingAddition", params_v3)
        self.assertGreaterEqual(params_v3["S4"], 12)
        self.assertGreaterEqual(params_v3["H1"], 100000)

        c3_id = create_connection(
            name="awg3",
            index_num=3,
            protocol_version="3.1",
            x_subnet=15,
            listen_port=51822,
            server_private_key=p3_priv,
            server_public_key=p3_pub,
            xray_port=7015,
            table_num=t3,
            fwmark=m3,
            params=params_v3,
        )
        self.assertTrue(c3_id > 0)
        print("Connections created: awg1 (table 101), awg2 (table 102), awg3 (table 103)")

    def test_02_server_config_and_xray_rules(self):
        print("\n--- Testing Server Config & Xray Rules Output ---")
        conns = get_all_connections()
        c2 = next(c for c in conns if c["name"] == "awg2")
        
        conf_text = generate_server_config_text(c2["id"])
        print(f"Generated server config snippet for awg2:\n{conf_text[:350]}...\n")

        # Check required Xray rules in awg2
        self.assertIn("PostUp = ip rule add fwmark 2 table 102 || true", conf_text)
        self.assertIn("PostUp = ip route add local 0.0.0.0/0 dev lo table 102 || true", conf_text)
        self.assertIn("PostUp = iptables -t mangle -N XRAY_TPROXY_2 || true", conf_text)
        self.assertIn("PostUp = iptables -t mangle -A XRAY_TPROXY_2 -d 10.14.0.0/24 -j RETURN", conf_text)
        self.assertIn("PostUp = iptables -t mangle -A XRAY_TPROXY_2 -p tcp -j TPROXY --on-port 7010 --tproxy-mark 2/2", conf_text)
        self.assertIn("PostUp = iptables -t mangle -A XRAY_TPROXY_2 -p udp -j TPROXY --on-port 7010 --tproxy-mark 2/2", conf_text)
        self.assertIn("PostUp = iptables -t mangle -A PREROUTING -i awg2 -j XRAY_TPROXY_2 || true", conf_text)
        self.assertIn("PostDown = iptables -t mangle -D PREROUTING -i awg2 -j XRAY_TPROXY_2 || true", conf_text)

        # Write to disk and check file + symlink creation
        write_server_config(c2["id"])
        conf_file = get_interface_conf_file("awg2")
        symlink_file = get_interface_symlink("awg2")

        self.assertTrue(conf_file.exists(), f"File {conf_file} does not exist")
        self.assertTrue(symlink_file.exists(), f"Symlink {symlink_file} does not exist")
        print(f"Verified files: {conf_file} and {symlink_file}")

    def test_03_users_and_devices_subnets(self):
        print("\n--- Testing User Subnets and Devices ---")
        conns = get_all_connections()
        c1 = next(c for c in conns if c["name"] == "awg1") # x_subnet = 13

        # User 1 -> should have user_index_y = 1 -> 10.13.1.0
        u1_id = create_user(c1["id"], username="Иван", notes="Тестовый пользователь 1")
        # User 2 -> should have user_index_y = 2 -> 10.13.2.0
        u2_id = create_user(c1["id"], username="Сергей", notes="Тестовый пользователь 2")

        users = get_all_users_with_peers()
        u1 = next(u for u in users if u["id"] == u1_id)
        u2 = next(u for u in users if u["id"] == u2_id)

        self.assertEqual(u1["user_index_y"], 1)
        self.assertEqual(u2["user_index_y"], 2)
        print(f"User 1 subnet: 10.{u1['x_subnet']}.{u1['user_index_y']}.0/24")
        print(f"User 2 subnet: 10.{u2['x_subnet']}.{u2['user_index_y']}.0/24")

        # Create Devices under User 1:
        # Device 1 -> 10.13.1.1
        dev1_priv, dev1_pub = generate_keypair()
        p1_id = create_peer(
            user_id=u1_id,
            connection_id=c1["id"],
            label="iPhone 15",
            client_ip=f"10.{u1['x_subnet']}.{u1['user_index_y']}.1",
            client_private_key=dev1_priv,
            client_public_key=dev1_pub,
        )

        # Device 2 -> 10.13.1.2
        dev2_priv, dev2_pub = generate_keypair()
        p2_id = create_peer(
            user_id=u1_id,
            connection_id=c1["id"],
            label="Ноутбук",
            client_ip=f"10.{u1['x_subnet']}.{u1['user_index_y']}.2",
            client_private_key=dev2_priv,
            client_public_key=dev2_pub,
        )

        # Check client config
        client_conf = generate_client_config_text(p1_id)
        print(f"Generated client config for device 1:\n{client_conf}\n")
        self.assertIn("Address = 10.13.1.1/32", client_conf)
        self.assertIn("AllowedIPs = 0.0.0.0/0", client_conf)

        # Check server config updated with both peers
        updated_server_conf = generate_server_config_text(c1["id"])
        self.assertIn("AllowedIPs = 10.13.1.1/32", updated_server_conf)
        self.assertIn("AllowedIPs = 10.13.1.2/32", updated_server_conf)
        self.assertIn("# Peer: Иван - iPhone 15", updated_server_conf)
        self.assertIn("# Peer: Иван - Ноутбук", updated_server_conf)
        print("Server config verified with all active peers.")

    def test_04_mobile_preset_and_direct_nat(self):
        print("\n--- Testing Mobile Preset & Direct NAT (No Xray) ---")
        # 1. Test bivlked mobile preset generation
        mob_31 = generate_awg_params("3.1", preset="mobile")
        self.assertEqual(mob_31["Jc"], 3)
        self.assertTrue(30 <= mob_31["Jmin"] <= 50)
        self.assertTrue(mob_31["Jmin"] + 20 <= mob_31["Jmax"] <= mob_31["Jmin"] + 80)
        self.assertEqual(mob_31["H1"], 1)
        self.assertEqual(mob_31["H2"], 2)
        self.assertEqual(mob_31["H3"], 3)
        self.assertEqual(mob_31["H4"], 4)
        self.assertIn("<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>", mob_31["I1"])
        self.assertIn("HeaderProtectionKey", mob_31)

        mob_20 = generate_awg_params("2.0", preset="mobile")
        self.assertEqual(mob_20["Jc"], 3)
        self.assertTrue("-" in str(mob_20["H1"]))
        self.assertIn("I1", mob_20)

        # 2. Test Connection with enable_xray = False (Direct NAT)
        t_next, m_next = get_next_table_and_mark()
        priv, pub = generate_keypair()
        c_direct_id = create_connection(
            name="awg_direct",
            index_num=10,
            protocol_version="3.1",
            x_subnet=50,
            listen_port=51850,
            server_private_key=priv,
            server_public_key=pub,
            xray_port=7050,
            table_num=t_next,
            fwmark=m_next,
            params=mob_31,
            enable_xray=False,
        )

        conf_direct = generate_server_config_text(c_direct_id)
        self.assertIn("POSTROUTING -s 10.50.0.0/16 -j MASQUERADE", conf_direct)
        self.assertNotIn(f"table {t_next}", conf_direct)
        self.assertNotIn("fwmark", conf_direct.lower())

        # 3. Test Connection with enable_xray = True (Xray TProxy)
        t2, m2 = get_next_table_and_mark()
        priv2, pub2 = generate_keypair()
        c_xray_id = create_connection(
            name="awg_xray",
            index_num=11,
            protocol_version="3.1",
            x_subnet=51,
            listen_port=51851,
            server_private_key=priv2,
            server_public_key=pub2,
            xray_port=7051,
            table_num=t2,
            fwmark=m2,
            params=mob_31,
            enable_xray=True,
        )

        conf_xray = generate_server_config_text(c_xray_id)
        self.assertIn(f"table {t2}", conf_xray)
        self.assertIn(f"fwmark {m2}", conf_xray)
        self.assertIn("TPROXY --on-port 7051", conf_xray)

        print("Mobile preset and Direct NAT routing verified successfully.")


if __name__ == "__main__":
    unittest.main()

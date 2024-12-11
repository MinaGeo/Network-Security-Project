from pymongo import MongoClient
from hashing import MD5  # Import the MD5 class from hashing.py


class DB:
    def __init__(self):
        self.client = MongoClient('mongodb://localhost:27017/')
        self.db = self.client['network_security']
        self.hasher = MD5()  # Create an instance of the MD5 class

    def is_account_exist(self, username):
        return self.db.accounts.count_documents({'username': username}) > 0

    def register(self, username, password, totp_secret=None):
        hashed_password = self.hasher.calculate_md5(password)
        account = {
            "username": username,
            "password": hashed_password,
            "totp_secret": totp_secret  # Store TOTP secret during registration
        }
        self.db.accounts.insert_one(account)

    def get_password(self, username):
        user_data = self.db.accounts.find_one({"username": username})
        return user_data["password"] if user_data else None

    def get_totp_secret(self, username):
        user_data = self.db.accounts.find_one({"username": username})
        return user_data["totp_secret"] if user_data else None

    def is_account_online(self, username):
        return self.db.online_peers.count_documents({"username": username}) > 0

    def user_login(self, username, ip, port):
        online_peer = {
            "username": username,
            "ip": ip,
            "port": port
        }
        self.db.online_peers.insert_one(online_peer)

    def user_logout(self, username):
        self.db.online_peers.delete_one({"username": username})

    def get_peer_ip_port(self, username):
        res = self.db.online_peers.find_one({"username": username})
        return (res["ip"], res["port"]) if res else (None, None)

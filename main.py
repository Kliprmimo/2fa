import bcrypt
import base64
import json
from getpass import getpass
'''
passwords are stored as base64 representation of bcrypt hash
'''


def generate_hash(password: str):
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(password_bytes, salt)
    return (hash, salt)


def check_hashe_pass(password: str, password_hash: bytes, password_salt: bytes):
    password_bytes = password.encode('utf-8')
    new_hash = bcrypt.hashpw(password_bytes, password_salt)
    if password_hash == new_hash:
        return True
    return False


class user:
    def __init__(self, username: str, password_hash: str, password_salt: str):
        self.username = username
        self.password_hash = password_hash
        self.password_salt = password_salt


class usersData:
    def __init__(self, users: list[user]):
        self.users = users

    def check_if_username_exists(self, username: str):
        index = 0
        for account in self.users:
            if account.username == username:
                return index
            index += 1
        return -1

    def register(self, username: str, password: str):
        if self.check_if_username_exists(username) != -1:
            print('user with this username already exists, try different one')
            return False
        hash, salt = generate_hash(password)
        new_user = user(username, base64.b64encode(hash).decode(), base64.b64encode(salt).decode())
        self.users.append(new_user)
        return True

    def login(self, username: str, password: str):
        if -1 == (idx := self.check_if_username_exists(username)):
            return False
        password_hash = base64.b64decode(self.users[idx].password_hash)
        password_salt = base64.b64decode(self.users[idx].password_salt)
        return check_hashe_pass(password, password_hash, password_salt)


def open_db(filename: str):
    with open(filename, 'r') as f:
        data = json.load(f)
    data = data['user_data']
    db = usersData([])
    for account in data:
        new_user = user(account['username'], account['password_hash'], account['password_salt'])
        db.users.append(new_user)
    return db


def save_db(filename: str, db: usersData):
    data = []
    for account in db.users:
        data.append(account.__dict__)

    with open(filename, 'w') as f:
        json.dump({"user_data": data}, f)


if __name__ == '__main__':
    db = open_db('test_db.json')
    while True:
        action = input('login/register/save/exit\n>').strip()
        if action == 'login':
            login = input('username: ').strip()
            password = getpass('password: ').strip()
            if db.login(login, password):
                print(f'Successfully logged in as {login}!')
            else:
                print('login or username incorrect')
        elif action == 'register':
            login = input('username: ').strip()
            password = getpass('password: ').strip()
            print(password)
            if db.register(login, password):
                print(f'Successfully registered in as {login}!')
            else:
                print('login or username incorrect')
        elif action == 'exit':
            exit(0)
        elif action == 'save':
            name = input('filename: ').strip()
            save_db(name, db)
        else:
            print('we dont support this acction')

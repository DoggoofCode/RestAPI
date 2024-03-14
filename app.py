from flask import Flask, request, jsonify
import json
import base64

app = Flask(__name__)


class users:
    def __init__(self):
        pass

    def getData(self):
        with open('user.json') as dataFromFile:
            data = dataFromFile.read()
        return json.loads(data)

    def addData(self, username: str, password: str) -> None:
        datum = self.getData()
        print(username, password, datum)
        hashing = base64.b64encode(f'{username}.{password}'.encode())
        new_data = [f'{username}',
                    {'username': f'{username}',
                     'password': f'{password}',
                     'userToken': f'{hashing.decode()}'}]
        datum[new_data[0]] = new_data[1]
        with open('user.json', 'w') as dataToFile:
            dataToFile.write(json.dumps(datum))
        return None

    def validateData(self, username: str, password: str) -> bool:
        datum = self.getData()
        if username in datum and datum[username]['password'] == password:
            return True
        else:
            return False

    def deleteAccount(self, token: str) -> None:
        datum = self.getData()
        username = base64.b64decode(token)
        username = username.split(b'.')[0]
        if username.decode() in datum:
            del datum[username.decode()]
            with open('user.json', 'w') as dataToFile:
                dataToFile.write(json.dumps(datum))
            return None
        raise Exception('User not found')


@app.route('/add-user', methods=['POST'])
def add_user():
    data = request.get_json()

    username = data['username']
    password = data['password']

    users().addData(username, password)

    return jsonify({"message": "User added successfully"}), 201


@app.route('/')
def home():
    return jsonify({"message": "Welcome to the user management system this is a simple user management system"}), 200


@app.route('/validate-user-entry', methods=['GET'])
def validate_user_entry():
    username = request.args.get('username')
    password = request.args.get('password')

    if users().validateData(username, password):
        return jsonify({"message": "Valid user", "token": users().getData()[username]['userToken']}), 200
    else:
        return jsonify({"message": "Invalid user"}), 401


@app.route('/admin-debug', methods=['GET'])
def admin_debug():
    password = request.args.get('password')

    if password == 'root':
        return users().getData(), 200
    else:
        return jsonify({"message": "Wrong Password"}), 401


@app.route('/remove-account', methods=['PUT'])
def delete_account():
    data = request.get_json()

    userToken = data['userToken']
    userToken = base64.b64decode(userToken)
    userToken = userToken.split(b'.')
    userToken = [item.decode() for item in userToken]

    if users().getData()[userToken[0]]['userToken'] != data['userToken']:  # Verify user token
        print(users().getData()[userToken[0]]['userToken'], userToken)
        return jsonify({"message": "Invalid user token"}), 401
    users().deleteAccount(data['userToken'])

    return jsonify({"message": "Account deleted successfully"}), 200


if __name__ == '__main__':
    users().addData('admin', 'admin')
    app.run(debug=True)

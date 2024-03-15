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

    def changePassword(self, token: str, newPassword: str) -> None or Exception:
        datum = self.getData()
        username = base64.b64decode(token)
        username = username.split(b'.')[0]
        if username.decode() in datum:
            datum[username.decode()]['password'] = newPassword
            datum[username.decode()]['userToken'] = base64.b64encode(
                f'{username.decode()}.{newPassword}'.encode()).decode()
            with open('user.json', 'w') as dataToFile:
                dataToFile.write(json.dumps(datum))
            return None
        return Exception('User not found')


@app.route('/add-user', methods=['POST'])
def add_user():
    data = request.get_json()

    username: str = data['username']
    password: str = data['password']
    # check for existing user with same name
    if users().getData().get(username):
        return jsonify({"message": "User already exists"}), 409
    users().addData(username, password)

    return jsonify({"message": "User added successfully"}), 201


@app.route('/')
def home():
    return "Welcome to the user management system this is a simple user management system, go to /documentation to see t\
    he documentation for the user management system"


@app.route('/documentation')
def documentation():
    documentation_for_api = """
    <h1>Documentation for the user management system</h1>
    <p>This is a general user management system that allows you to add, remove, change password and validate users for the \
    application "Slagg". This aims to provide a comprehensive user management system for the application. The following \
    are the endpoints for the user management system:
     - <strong>/user-identification/add-user:</strong> This endpoint is used to add a user to the user management system. It accepts a PO\
        ST request with the following parameters:
        - username: This is the username of the user to be added to the user management system.
        - password: This is the password of the user to be added to the user management system.
    - <strong>/user-identification/validate-user-entry:</strong> This endpoint is used to validate a user in the user management system. \
        It accepts a GET request with the following parameters:
        - username: This is the username of the user to be validated in the user management system.
        - password: This is the password of the user to be validated in the user management system.
    - <strong>/user-identification/admin-debug:</strong> This endpoint is used to debug the user management system. It accepts a GET requ\
        est with the following parameters:
        - password: This is the password to debug the user management system.
        (Note: This endpoint is only for debugging purposes and should not be used in production, it is not secure)
    - <strong>/user-identification/remove-account:</strong> This endpoint is used to remove a user from the user management system. It ac\
        cepts a PUT request with the following parameters:
        - userToken: This is the user token of the user to be removed from the user management system.
    - <strong>/user-identification/change-account-password:</strong> This endpoint is used to change the password of a user in the user \
        management system. It accepts a PUT request with the following parameters:
        - userToken: This is the user token of the user to change the password in the user management system.
        - newPassword: This is the new password of the user to change the password in the user management system.
    - <strong>/user-identification/get-current-token:</strong> This endpoint is used to get the current token of a user in the user mana\
        gement system. It accepts a GET request with the following parameters:
        - username: This is the username of the user to get the current token in the user management system.
        - password: This is the password of the user to get the current token in the user management system.</p>
    
    """
    return documentation_for_api


@app.route('/user-identification/validate-user-entry', methods=['GET'])
def validate_user_entry():
    username = request.args.get('username')
    password = request.args.get('password')

    if users().validateData(username, password):
        return jsonify({"message": "Valid user", "token": users().getData()[username]['userToken']}), 200
    else:
        return jsonify({"message": "Invalid user"}), 401


@app.route('/user-identification/admin-debug', methods=['GET'])
def admin_debug():
    password = request.args.get('password')

    if password == 'root':
        return users().getData(), 200
    else:
        return jsonify({"message": "Wrong Password"}), 401


@app.route('/user-identification/remove-account', methods=['PUT'])
def delete_account():
    data = request.get_json()

    userToken = data['userToken']
    userToken = base64.b64decode(userToken)
    userToken = userToken.split(b'.')
    userToken = [item.decode() for item in userToken]

    if users().getData()[userToken[0]]['userToken'] != data['userToken']:  # Verify user token
        # print(users().getData()[userToken[0]]['userToken'], userToken)
        return jsonify({"message": "Invalid user token"}), 401
    users().deleteAccount(data['userToken'])

    return jsonify({"message": "Account deleted successfully"}), 200


@app.route('/user-identification/change-account-password', methods=['PUT'])
def change_account_password():
    data = request.get_json()

    userToken = data['userToken']
    userToken = base64.b64decode(userToken)
    userToken = userToken.split(b'.')
    userToken = [item.decode() for item in userToken]
    new_password = data['newPassword']

    if users().getData()[userToken[0]]['userToken'] != data['userToken']:  # Verify user token
        return jsonify({"message": "Invalid user token", "userToken": "_"}), 401

    result = users().changePassword(data['userToken'], new_password)
    if type(result) is Exception:
        return jsonify({"message": "User not found", "userToken": "_"}), 404
    else:
        return jsonify({"message": "Account password changed successfully",
                        "userToken": f"{users().getData()[userToken[0]]['userToken']}"}), 200


@app.route('/user-identification/get-current-token', methods=['GET'])
def get_current_token():
    username = request.args.get('username')
    password = request.args.get('password')
    datum = users().getData()
    if username in datum and datum[username]['password'] == password:
        return jsonify({"message": "Valid user", "token": datum[username]['userToken']}), 200
    else:
        return jsonify({"message": "Invalid user"}), 401


if __name__ == '__main__':
    app.run(debug=True)

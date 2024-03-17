import os

from flask import Flask, request, jsonify
import json
import base64
import random

VERSION_NUMBER = "0.0.1"

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
                     'userToken': f'{hashing.decode()}',
                     'versionJoined': VERSION_NUMBER,
                     'serversJoined': []}]
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

    def addServerToServerList(self, userToken: str, serverID: str) -> None:
        try:
            userToken = base64.b64decode(userToken)
            userToken = userToken.split(b'.')
            userToken = [item.decode() for item in userToken]
            serverToken = serverID
            datum = self.getData()
            datum[userToken[0]]['serversJoined'].append(serverToken)
            with open('user.json', 'w') as dataToFile:
                dataToFile.write(json.dumps(datum))
            return None
        except Exception as e:
            raise e


# This is the code for the user management system,


@app.route('/user-identification/add-user', methods=['POST'])
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
    <h1>NOTE: THIS DOES NOT INCLUDE THE DOCS FOR SERVER MAKING. AVAILABLE IN GITHUB</h1>
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


# This is the code for the chat management system

class serverUtil:
    def __init__(self):
        pass

    def x(self):
        pass

    def hierarchizeServerRoles(self, serverID: str) -> dict[str: int]:
        serverData = self.getServerData(serverID)
        serverData = serverData['roles']
        hierarchy = {}
        for index, item in enumerate(serverData):
            hierarchy[item] = index
        return hierarchy

    def userTokenRoleAuthentication(self, userToken, serverID):
        try:
            serverData = self.getServerData(serverID)
            return serverData['communityMembers'][userToken]['role']
        except KeyError:
            return None
        except Exception as e:
            raise e

    def userToken2Username(self, userToken: str) -> str:
        self.x()
        userToken = base64.b64decode(userToken)
        userToken = userToken.split(b'.')
        return userToken[0].decode()

    def getServerData(self, serverID: str) -> dict:
        with open(fr'communities\{serverID}\userManifest.json') as dataFromFile:
            data = dataFromFile.read()
        return json.loads(data)

    def addMemberToServer(self, serverID: str, userToken: str) -> None:
        try:
            serverData = self.getServerData(serverID)
            serverData['communityMembers'][userToken] = {
                "role": "default"
            }
            with open(fr'communities\{serverID}\userManifest.json', 'w') as fileWrite:
                fileWrite.write(json.dumps(serverData))
        except Exception as e:
            raise e

    def removeMemberFromServer(self, serverID: str, userToken: str) -> None:
        try:
            serverData = self.getServerData(serverID)
            del serverData['communityMembers'][userToken]
            with open(fr'communities\{serverID}\userManifest.json', 'w') as fileWrite:
                fileWrite.write(json.dumps(serverData))
        except Exception as e:
            raise e

    def changeMemberRole(self, serverID: str, userToken: str, newRole: str) -> None:
        try:
            serverData = self.getServerData(serverID)
            serverData['communityMembers'][userToken]['role'] = newRole
            with open(fr'communities\{serverID}\userManifest.json', 'w') as fileWrite:
                fileWrite.write(json.dumps(serverData))
        except Exception as e:
            raise e

    def addTextChannelToManifest(self, serverID: str, channelName: str, channelDescription: str,
                                 permissionToRead: list[str], permissionToSend: list[str]) -> None:
        try:
            serverData = self.getServerData(serverID)
            serverData['textChannels'].append({
                "channelName": channelName,
                "channelDescription": channelDescription,
                "permissionToRead": permissionToRead,
                "permissionToSend": permissionToSend
            })
            with open(fr'communities\{serverID}\userManifest.json', 'w') as fileWrite:
                fileWrite.write(json.dumps(serverData))
        except Exception as e:
            raise e

    def createTextChannelFile(self, serverID: str, channelName: str) -> None:
        self.x()
        try:
            with open(fr'communities\{serverID}\{channelName}.json', 'x') as _:
                pass
            with open(fr'communities\{serverID}\{channelName}.json', 'w') as channel:
                channel.write(json.dumps({"chat": []}))  # This is the default data for the text channel
        except Exception as e:
            raise e

    def sendMessage(self, serverID: str, channelName: str, userToken: str, message: str) -> None:
        self.x()
        try:
            # check if the user has the permission to send
            serverManifest = self.getServerData(serverID)

            with open(fr'communities\{serverID}\{channelName}.json', 'r') as fileRead:
                data = json.loads(fileRead.read())
            data['chat'].append({
                "userToken": userToken,
                "message": message
            })
            with open(fr'communities\{serverID}\{channelName}.json', 'w') as fileWrite:
                fileWrite.write(json.dumps(data))
        except Exception as e:
            raise e


"""
INPUTS:
    - ownerToken
    - communityName
    - communityDescription
"""


@app.route('/chat-management/make-community', methods=['POST'])
def make_community():
    data = request.get_json()

    ownerToken = data['ownerToken']
    ownerCreds: list[str] = (base64.b64decode(ownerToken)).decode().split('.')
    community_name = data['communityName']
    community_description = data['communityDescription']
    # creates folder
    try:
        shuffling_letters = [letter for letter in community_name if letter.isalnum()]
        random.shuffle(shuffling_letters)
        SERVER_IDENTIFICATION = ''.join(shuffling_letters)
        print('we did it!')
        os.mkdir(fr'communities\{SERVER_IDENTIFICATION}')
        with open(fr'communities\{SERVER_IDENTIFICATION}\userManifest.json', 'x') as _:
            pass
    except FileExistsError:
        print("File already exists, how did this happen?")
        return jsonify({"message": "Internal Server Error Please Try Again"}), 500
    # except Exception as e:
    #     print(e)
    #     return jsonify("message": f"Internal Server Error @ {e}"}), 500
    # Generates userManifest.json

    """
    WHAT ARE THE PERMISSIONS FOR THE TEXT CHANNELS?
        WE NEED TO ADD THESE :(
    """

    userManifest = {
        "server_owner": ownerToken,
        "communityName": community_name,
        "communityDescription": community_description,
        "note_for_all": "NO MEMES IN GENERAL CHAT!!!!",
        "communityMembers": {
            ownerToken: {
                "role": "owner",
            }
        },
        "textChannels": [
            {
                "channelName": "general",
                "channelDescription": "The general channel for the community",
                "permissionToRead": ["everyone", "moderator", "administrator", "owner"],
                "permissionToSend": ["everyone", "moderator", "administrator", "owner"],
            },
            {
                "channelName": "adminOnly",
                "channelDescription": "The admin only channel for the community",
                "permissionToRead": ["administrator", "owner"],
                "permissionToSend": ["administrator", "owner"],
            },
            {
                "channelName": "Announcements",
                "channelDescription": "The announcements channel for the community",
                "permissionToRead": ["everyone", "moderator", "administrator", "owner"],
                "permissionToSend": ["administrator", "owner"],
            }
        ],
        "roles": [
            'default',
            'moderator',
            'administrator',
            'owner'
        ],
        "bannedUserList": [],
        "permission_to_kick": ["moderator", "administrator", "owner"],
        "permission_to_ban": ["administrator", "owner"],
        "permission_to_change_role": ["administrator", "owner"],
        "permission_to_create_text_channel": ["owner"],
    }
    with open(fr'communities\{SERVER_IDENTIFICATION}\userManifest.json', 'w') as fileWrite:
        fileWrite.write(json.dumps(userManifest))

    # Adds this server to the user's server list
    users().addServerToServerList(ownerToken, SERVER_IDENTIFICATION)

    for channel in userManifest['textChannels']:
        serverUtil().createTextChannelFile(SERVER_IDENTIFICATION, channel['channelName'])

    return jsonify({"message": "Community created successfully", "serverID": SERVER_IDENTIFICATION}), 201


"""
INPUTS:
    - serverID
    - userToken
"""


@app.route('/chat-management/add-member-to-community', methods=['POST'])
def add_member_to_community():
    data = request.get_json()

    serverID = data['serverID']
    userToken = data['userToken']

    try:
        serverUtil().addMemberToServer(serverID, userToken)
    except Exception as e:
        return jsonify({"message": f"Internal Server Error @ {e}"}), 500
    return jsonify({"message": "User added to server successfully"}), 200


"""
INPUTS:
    - serverID
    - userToken
    - userRemoving
"""


@app.route('/chat-management/remove-member-from-community', methods=['DELETE'])
def remove_member():
    data = request.get_json()

    serverID = data['serverID']
    userToken = data['userToken']
    user_removing = data['userRemoving']
    datum = serverUtil().getServerData(serverID)

    # authenticate the removing the user
    try:
        if serverUtil().userTokenRoleAuthentication(user_removing, serverID) not in datum['permission_to_kick']:
            return jsonify({"message": "User does not have permission to remove users"}), 401
    except Exception as e:
        return jsonify({"message": f"Internal Server Error @ {e}"}), 500

    if user_removing == userToken:
        return jsonify({"message": "User does not have permission to remove themselves"}), 401
    if datum['communityMembers'][userToken]['role'] == 'owner':
        return jsonify({"message": "User does not have permission to remove server owner"}), 401

    try:
        serverUtil().removeMemberFromServer(serverID, userToken)
    except Exception as e:
        return jsonify({"message": f"Internal Server Error @ {e}"}), 500
    return jsonify({"message": "User removed from server successfully"}), 200


"""
INPUTS:
    - serverID
    - userToken
    - newRole
    - userChanging
"""


@app.route('/chat-management/change-member-role', methods=['PUT'])
def change_member_role():
    data = request.get_json()

    serverID = data['serverID']
    userToken = data['userToken']
    newRole = data['newRole']
    user_changing = data['userChanging']
    serverHierarchy = serverUtil.hierarchizeServerRoles(serverUtil().getServerData(serverID)['roles'], serverID)
    user_changing_role = serverUtil().userTokenRoleAuthentication(user_changing, serverID)
    if serverHierarchy[user_changing_role] < serverHierarchy[newRole]:
        return jsonify({"message": "User does not have permission to change user role"}), 401
    if user_changing == userToken:
        return jsonify({
            "message": "User does not have permission to change their own role NOTE: You are not allowed to change your own role ever"}), 401

    try:
        serverUtil().changeMemberRole(serverID, userToken, newRole)
    except Exception as e:
        return jsonify({"message": f"Internal Server Error @ {e}"}), 500
    return jsonify({"message": "User role changed successfully"}), 200


"""
INPUTS:
    -userCreating
    -serverID
    -channelName
    -channelDescription
    -permissionToRead
    -permissionToSend
"""


@app.route('/chat-management/add-text-channel', methods=['POST'])
def add_text_channel():
    data = request.get_json()

    user_creating = data['userCreating']
    serverID = data['serverID']
    channelName = data['channelName']
    channelDescription = data['channelDescription']
    permissionToRead = data['permissionToRead']
    permissionToSend = data['permissionToSend']
    if serverUtil().userTokenRoleAuthentication(user_creating, serverID) not in serverUtil().getServerData(serverID)[
        "permission_to_create_text_channel"]:
        return jsonify({"message": "User does not have permission to create text channel"}), 401
    try:
        serverUtil().addTextChannelToManifest(serverID, channelName, channelDescription, permissionToRead,
                                              permissionToSend)
        serverUtil().createTextChannelFile(serverID, channelName)
    except Exception as e:
        return jsonify({"message": f"Internal Server Error @ {e}"}), 500
    return jsonify({"message": "Text channel added successfully"}), 201


"""
INPUTS:
    -userToken
    -serverID
    -channelName
    -message
"""


@app.route('/chat-management/send-message', methods=['POST'])
def send_msg():
    data = request.get_json()

    serverID = data['serverID']
    channelName = data['channelName']
    userToken = data['userToken']
    message = data['message']

    # check if the user has the permission to send
    if serverUtil().userTokenRoleAuthentication(userToken, serverID) not in \
            serverUtil().getServerData(serverID)["textChannels"][channelName]["permissionToSend"]:
        return jsonify({"message": "User does not have permission to send"}), 401

    serverManifest = serverUtil().getServerData(serverID)
    text_channels: list[dict] = serverManifest['textChannels']
    for channel in text_channels:
        if channel['channelName'] == channelName:
            try:
                if serverManifest['communityMembers'][userToken]['role'] in channel['permissionToSend']:
                    pass
                else:
                    return jsonify({"message": "User does not have permission to send"}), 401
            except KeyError:
                return jsonify({"message": "User does not have permission to send"}), 401

    try:
        serverUtil().sendMessage(serverID, channelName, userToken, message)
    except Exception as e:
        return jsonify({"message": f"Internal Server Error @ {e}"}), 500
    return jsonify({"message": "Message sent successfully"}), 200


"""
INPUTS:
    -serverID
"""


@app.route('/chat-management/get-manifest', methods=['GET'])
def get_manifest():
    serverID = request.args.get('serverID')
    try:
        return jsonify(serverUtil().getServerData(serverID)), 200
    except Exception as e:
        return jsonify({"message": f"Internal Server Error @ {e}"}), 500


"""
INPUTS:
    -serverID
    -channelName
    -userToken
"""


@app.route('/chat-management/get-text-channel', methods=['GET'])
def get_text_channel():
    serverID = request.args.get('serverID')
    channelName = request.args.get('channelName')
    userToken = request.args.get('userToken')

    # check if the user has the permission to do it

    serverData = serverUtil().getServerData(serverID)
    try:
        if serverData['communityMembers'][userToken]['role'] in serverData['textChannels'][channelName][
            'permissionToRead']:
            pass
        else:
            return jsonify({"message": "User does not have permission to read"}), 401
    except KeyError:
        return jsonify({"message": "User does not have permission to read"}), 401

    try:
        with open(fr'communities\{serverID}\{channelName}.json', 'r') as fileRead:
            return jsonify(json.loads(fileRead.read())), 200
    except Exception as e:
        return jsonify({"message": f"Internal Server Error @ {e}"}), 500


if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, request, jsonify
import os
import json

import functions

# Class for user object creation
class User:
    def __init__(self, username, password, policy):
        self._username = username
        self._password = password
        self._appliedpolicy = policy

    def user_to_json(self):
        # JSON to dict
        return {
            "username": self._username,
            "password": self._password,
            "applied policy": self._appliedpolicy
        }

# class for policy object vreation
class Policy:
    def __init__(self, policy_name, password_length,
                 punctuation, required_numbers):
        self._password_length = password_length
        self._punctuation = punctuation
        self._policy_name = policy_name
        self._numbers = required_numbers

    def policy_to_json(self):
        # JSON to dict
        return {
            "policy_name": self._policy_name,
            "password_length": self._password_length,
            "punctuation": self._punctuation,
            "numbers": self._numbers
        }


app = Flask(__name__)


@app.route("/createuser", methods=["POST"])
def generate_user():
   try:
        apiData = request.get_json()
        username = apiData["username"]
        newPasswordMode = apiData["newPasswordMode"]
        policy = apiData["policy"]
        account = apiData["account"]
        accountPassword = apiData["accountPassword"]


        access = functions.authentication(account, accountPassword)
        policyExists = functions.check_policy_existence(policy)
        if policyExists == False:
            return "Invalid policy"

        if access is False :
            return "You don't have permission to do that"
        if not (username and newPasswordMode and policy):
            return "Invalid request. Please provide username, password, and policy."

        generated_password = functions.generate_password(newPasswordMode, policy)
        # check if password is not None
        if generated_password == None:
            return "invalid password"

        user = User(username, generated_password, policy)
        user_json = user.user_to_json()

        with open("users.json", "r") as f:
            data = json.load(f)

        data.append(user_json)

        with open("users.json", "w") as f:
            json.dump(data, f, indent=2)

        return jsonify(user_json)

   except Exception as e:
    return f"An error occurred: {str(e)}"



@app.route("/readuser", methods=["GET"])
def read_user():
    apiData = request.get_json()

    read_username = apiData["username"]
    account = apiData["account"]
    accountPassword = apiData["accountPassword"]

    access = functions.authentication(account, accountPassword)
    if access is False:
        return "You don't have permission to do that"

    if os.path.isfile("users.json"):
        with open("users.json", "r") as file:
            data = json.load(file)

            for user in data:
                if user["username"] == read_username:
                    return jsonify(user)

    return "User not found"


@app.route("/edituser", methods=["POST"])
def edit_user():
    password = None
    apiData = request.get_json()
    username = apiData["username"]
    newPasswordMode = apiData["newPasswordMode"]
    newPolicy = apiData["new_policy"]
    account = apiData["account"]
    accountPassword = apiData["accountPassword"]

    access = functions.authentication(account, accountPassword)
    if access is False:
        return "You don't have permission to do that"

    policyCheck = functions.check_policy_existence(newPolicy)

    if policyCheck is False:
        return "The policy does not exist"

    with open("policies.json", 'r') as f:
        policies_data = json.load(f)

    if os.path.isfile("users.json"):
        with open("users.json", "r") as file:
            data = json.load(file)

        for user in data:
            if user["username"] == username:
                for policy in policies_data:
                    if newPolicy != policy["policy_name"]:
                        policy["policy_name"] = newPolicy
                        password = functions.generate_password(newPasswordMode, newPolicy)
                        user["password"] = password
                    elif newPolicy == policy["policy_name"]:
                        policy["policy_name"] = newPolicy
                        password = functions.generate_password(newPasswordMode, newPolicy)

                user["applied_policy"] = newPolicy

                # Check password history
                if "password_history" not in user:
                    user["password_history"] = []

                if password and password not in user["password_history"]:
                    user["password_history"].append(password)

                # Save changes to users.json
                with open("users.json", "w") as file:
                    json.dump(data, file, indent=2)

                return "Success"

    return "An error occurred. Don't worry, it's not your fault"


@app.route("/readpolicy", methods=["GET"])
def read_policy():
    apiData = request.get_json()
    policyName = apiData["policyname"]
    account = apiData["account"]
    accountPassword = apiData["accountPassword"]

    access = functions.authentication(account, accountPassword)
    if access is False:
        return "You don't have permission to do that"
    try:
        if os.path.isfile("policies.json"):
            with open("policies.json", "r") as file:
                data = json.load(file)

                for policy in data:
                    if policy["policy_name"] == policyName:
                        return jsonify(policy)
    except:
        return "Policy not found"


@app.route("/checkcredentials", methods=["GET"])
def check_credentials():
    try:
        apiData = request.get_json()
        username = apiData["username"]
        password_temp = apiData["password"]
        password_temp = functions.hash_passwordsha256(password_temp)

        with open('users.json', 'r') as f:
            data = json.load(f)

            for user in data:
                if user["username"] == username and user["password"] == password_temp:
                    return "True"
    except:
        return "Wrong password. If you can not login or forgot your password, please contact your System administrator"


@app.route("/createpolicy", methods=["POST"])
def create_policy():
    apiData = request.get_json()
    policyName = apiData["policyName"]
    passwordLength = apiData["passwordLength"]
    punctuation = apiData["punctuation"]
    numbers = apiData["numbers"]
    account = apiData["account"]
    accountPassword = apiData["accountPassword"]

    access = functions.authentication(account, accountPassword)
    if access is False:
        return "You don't have permission to do that"

    integerCheck = functions.check_int(passwordLength, punctuation, numbers)

    if integerCheck is False:
        return "Invalid Parameters"

    newpolicy = Policy(policyName, passwordLength, punctuation, numbers)
    policy_json = newpolicy.policy_to_json()
    if os.path.isfile("policies.json"):
        with open("policies.json", "r") as f:
            data = json.load(f)

    data.append(policy_json)
    with open("policies.json", "w") as f:
        json.dump(data, f, indent=2)

    return jsonify(policy_json)


@app.route("/editpolicy", methods=["POST"])
def edit_policy():
    apiData = request.get_json()
    policyName = apiData["policyName"]
    passwordLength = apiData["passwordLength"]
    punctuation = apiData["punctuation"]
    numbers = apiData["numbers"]
    account = apiData["account"]
    accountPassword = apiData["accountPassword"]

    access = functions.authentication(account, accountPassword)
    if access is False:
        return "You don't have permission to do that"

    if os.path.isfile("policies.json"):
        with open("policies.json", "r") as f:
            data = json.load(f)

            for policy in data:
                if policy["policy_name"] == policyName:
                    policy["password_length"] = passwordLength
                    policy["punctuation"] = punctuation
                    policy["numbers"] = numbers
                    with open("policies.json", "w") as file:
                        json.dump(data, file, indent=2)
                        return "success"


if __name__ == '__main__':
    app.run(debug=False)

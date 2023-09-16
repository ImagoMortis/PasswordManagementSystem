import string
import json
import secrets
import hashlib
import requests


def generate_password(newPasswordMode, newPolicy):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    choose_policy = newPolicy
    choose_mode = newPasswordMode

    with open("policies.json", 'r') as f:
        policies_data = json.load(f)
        if choose_mode == "auto":
             for policy in policies_data:
                if policy['policy_name'] == choose_policy:
                    punctuation = int(policy['punctuation'])
                    password_length = int(policy['password_length'])
                    numbers = int(policy['numbers'])
                    valid = False


                    while not valid:
                         password = ''.join(secrets.choice(alphabet) for __ in range(password_length))
                         if password is not None:
                            punctuationCounter = check_punctuation(password)
                            passwordLengthCheck = len(password)
                            numbersCheck = check_numbers(password)
                         if (
                        punctuationCounter >= punctuation
                        and passwordLengthCheck >= password_length
                        and numbersCheck >= numbers
                             and check_password(password) == False
                            ):
                             valid = True
                             password = hash_passwordsha256(password)
                             return password


        elif choose_mode != "auto":
            for policy in policies_data:
                if policy['policy_name'] == choose_policy:
                    punctuation = int(policy['punctuation'])
                    password_length = int(policy['password_length'])
                    numbers = int(policy['numbers'])
            punctuationCounter = check_punctuation(newPasswordMode)
            passwordLengthCheck = len(newPasswordMode)
            numbersCheck = check_numbers(newPasswordMode)
            if (
                    punctuationCounter >= punctuation
                    and passwordLengthCheck >= password_length
                    and numbersCheck >= numbers
            ):
                password = newPasswordMode
                password = hash_password(password)
                valid = True
                return password
    return None



def check_punctuation(password):
    punctuation = string.punctuation
    counter = 0
    try:
        for i in password:
            if i in punctuation:
                counter += 1
    except:
        return "error"

    return counter


def check_numbers(password):
    numbers = string.digits
    counter = 0
    for i in password:
        if i in numbers:
            counter += 1

    return counter


def hash_password(password):
    hashedPassword = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return hashedPassword


def check_policy_existence(policy):
    with open('policies.json', 'r') as f:
        data = json.load(f)

    for policyObject in data:
        if policy == policyObject["policy_name"]:
            return True
    return False

def authentication(account, accountPassword):
    hash = hash_passwordsha256(accountPassword)
    with open('authorizedUser.json', 'r') as f:
        data = json.load(f)

    for user in data:
        if user["username"] == account and user["password"] == hash:
            return True

    return False


def check_int(passwordLength, punctuation, numbers):
    if (passwordLength.isdigit() and punctuation.isdigit() and numbers.isdigit()):
        return True

    return False

def hash_passwordsha256(password):
    password = hashlib.sha256(password.encode()).hexdigest()
    return password


def check_password(password):
    tempHash = hash_password(password)
    firstCharacters = tempHash[0:5]
    response = requests.get("https://api.pwnedpasswords.com/range/{}".format(firstCharacters))
    response = response.text.splitlines()
    for h in response:
        if tempHash[5:] in h:
            return True
    return False














import unittest
import os
import json
from functions import check_password,check_policy_existence, authentication, hash_passwordsha256

from main import app, User

class TestPMS(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_read_user(self):
        jsonData = {"username": "Manuel",
                     "account": "Admin",
                     "accountPassword":"admin"}
        response = self.client.get('/readuser', json=jsonData)
        result = json.loads(response.data.decode())
        expectedResult = {
            "username": "Manuel",
            "password": "e702e65aea9aac375318b7eec06e84e3c7d024eacca6d5f2fa0ba693a879cbae",
            "applied policy": "Test"
        }
        self.assertEqual(result, expectedResult)

    def test_check_passwords(self):
        password = "Passwort123"
        response = check_password(password)
        expectedResult = True
        self.assertEqual(response, expectedResult)

    def test_check_policy_existence(self):
        policy = "Test"
        response = check_policy_existence(policy)
        expectedResult = True
        self.assertEqual(expectedResult, response)

    def test_authentication(self):
        account = "Admin"
        accountPassword = "admin"
        response = authentication(account,accountPassword)
        expectedResult = True
        self.assertEqual(expectedResult, response)

    def test_hash_passwordsha256(self):
        password = "IchTesteMeineHashFunktion"
        expectedResult = "8d0c0ba3353dcc23bea7acd40cf52dca632283f279aacb1351da9d433737e310"
        response = hash_passwordsha256(password)
        self.assertEqual(expectedResult, response)

    def test_generate_user_invalidInput(self):
        jsonData = {"username": "Manuel",
                     "newPasswordMode": "auto",
                     "policy": "DiesePolicyGibtEsNicht",
                     "account": "Admin",
                     "accountPassword": "admin"}
        response = self.client.post('/createuser', json=jsonData)
        expectedResult = "Invalid policy"
        response = response.data.decode("utf-8")
        self.assertEqual(expectedResult, response)

    def test_String_library(self):
        string = "IchBinEinString"
        expectedResult = "ICHBINEINSTRING"
        result = string.upper()
        self.assertEqual(result, expectedResult)

    def test_os_library(self):
        oldName = "old.txt"
        newName = "new.txt"
        with open(oldName, "w") as f:
            f.write("Test file")
        os.rename(oldName, newName)
        existsOld = os.path.exists(oldName)
        existsNew = os.path.exists(newName)
        self.assertFalse(existsOld)
        self.assertTrue(existsNew)
        os.remove(newName)

    def test_json_library(self):
        testJson = '{"username": "Manuel", "password":"IchBinEinPasswort"}'
        expectedResult = {"username": "Manuel", "password":"IchBinEinPasswort"}
        result = json.loads(testJson)
        self.assertEqual(result, expectedResult)

    def test_user_class(self):
        username = "Manuel"
        password = "password123"
        policy = "admin"
        expectedResult = {
            "username": username,
            "password": password,
            "applied policy": policy
        }
        user = User(username, password, policy)
        result = user.user_to_json()
        self.assertEqual(result,expectedResult)







if __name__ == '__main__':
    unittest.main()
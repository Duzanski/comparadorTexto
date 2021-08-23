from os import error
from flask import Flask, json, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient('mongodb://db:27017')
db = client.Bank  # Db name
users = db['BankAccount']  # table name


def UserExist(username):
    if users.find({'username': username}).count() == 0:
        return False
    else:
        return True


def verifyPW(username, password):
    if not UserExist(username):
        return False

    hashed_pass = users.find({'username': username})[0]['password']

    if bcrypt.hashpw(password.encode('utf8'), hashed_pass) == hashed_pass:
        return True
    else:
        return False


def cashWithUser(username):
    cash = users.find({'username': username})[0]['own']
    return cash


def debtWithUser(username):
    debt = users.find({'username': username})[0]['debt']
    return debt


def generateReturnDictionary(status, msg):
    retJson = {
        'status': status,
        'msg': msg
    }
    return retJson


def verifyCredentials(username, password):
    if not UserExist(username):
        return generateReturnDictionary(301, 'Invalid username'), True

    correct_pw = verifyPW(username, password)
    if not correct_pw:
        return generateReturnDictionary(302, 'Invalid password'), True

    return None, False


def updateAccount(username, balance):
    users.update({'username': username}, {'$set': {'own': balance}})


def updateDebt(username, balance):
    users.update({'username': username}, {'$set': {'debt': balance}})


class Add(Resource):
    def post(self):

        postedeData = request.get_json()

        username = postedeData['username']
        password = postedeData['password']
        money = postedeData['amount']

        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        if money == 0:
            return jsonify(generateReturnDictionary(304, 'The money amount must be > 0'))

        cash = cashWithUser(username)
        money -= 1
        bank_cash = cashWithUser('bank')
        updateAccount('bank', bank_cash+1)
        updateAccount(username, cash + money)

        return jsonify(generateReturnDictionary(200, 'Amount added succesfully'))


class Transfer(Resource):
    def post(self):

        postedeData = request.get_json()

        username = postedeData['username']
        password = postedeData['password']
        to = postedeData['to']
        money = postedeData['amount']

        retJson, error = verifyCredentials(username, password)

        if error:
            return jsonify(retJson)

        cash = cashWithUser(username)
        if cash == 0:
            return jsonify(generateReturnDictionary(304, 'You are out of money'))

        if not UserExist(to):
            return jsonify(generateReturnDictionary(301, 'Ivalid username'))

        cahs_from = cashWithUser(username)
        cash_to = cashWithUser(to)
        bank_cash = cashWithUser('bank')

        updateAccount('bank', bank_cash + 1)
        updateAccount(to, cash_to + money - 1)
        updateAccount(username, cahs_from - money)

        return jsonify(generateReturnDictionary(200, 'Amount transfered'))


class TakeLoan(Resource):
    def post(self):

        postedeData = request.get_json()

        username = postedeData['username']
        password = postedeData['password']
        money = postedeData['amount']

        retJson, error = verifyCredentials(username, password)

        if error:
            return jsonify(retJson)

        cash = cashWithUser(username)
        debt = debtWithUser(username)
        updateAccount(username, cash + money)
        updateDebt(username, debt + money)

        return jsonify(generateReturnDictionary(200, 'Loan added'))


class PayLoan(Resource):
    def post(self):

        postedeData = request.get_json()

        username = postedeData['username']
        password = postedeData['password']
        money = postedeData['amount']

        retJson, error = verifyCredentials(username, password)

        if error:
            return jsonify(retJson)

        cash = cashWithUser(username)

        if cash < money:
            return jsonify(generateReturnDictionary(303, 'Not enought cash'))

        debt = debtWithUser(username)

        updateAccount(username, cash - money)
        updateDebt(username, debt - money)

        return jsonify(generateReturnDictionary(200, 'You succesfully paid'))


class Balance(Resource):
    def post(self):

        postedeData = request.get_json()

        username = postedeData['username']
        password = postedeData['password']

        retJson, error = verifyCredentials(username, password)

        if error:
            return jsonify(retJson)

        retJson = users.find({'username': username}, {
            'password': 0, '_id': 0})[0]

        return jsonify(retJson)


class Register(Resource):
    def post(self):

        postedeData = request.get_json()

        username = postedeData['username']
        password = postedeData['password']

        if UserExist(username):
            retJson = {
                'status': 301,
                'msg': 'Invalid username'
            }
            return jsonify(retJson)

        hashed_pass = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert_one({
            'username': username,
            'password': hashed_pass,
            'own': 0,
            'debt': 0,
        })

        retJson = {
            'status': 200,
            'msg': 'You have signed up to the API'
        }
        return jsonify(retJson)


api.add_resource(Register, '/register')
api.add_resource(Add, '/add')
api.add_resource(Transfer, '/transfer')
api.add_resource(Balance, '/balance')
api.add_resource(TakeLoan, '/takeloan')
api.add_resource(PayLoan, '/payloan')

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')

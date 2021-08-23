"""
Registration of a user 0 tokens
Each user gets 10 tokens
Store a sentence on our database for 1 token
Retrieve his stored sentence on out database for 1 token

RESOURCE            ADDRES          PROTOCOL        PARAM       RESPONSE/STATUS CODE
Register user       /register       POST            Username    200 OK
                                                    Password    

Store sentence      /store          POST            Username    200 OK
                                                    Password    301 out of tokens
                                                    Sentence    302 wrong username or pass

Retrieve sentence   /get            GET             Username    200 OK
                                                    Password    301 out of tokens
                                                    302 wrong username or pass
"""
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient('mongodb://db:27017')
db = client.SentencesDatabase  # Db name
users = db['Users']  # table name


def verifyPass(username, password):
    hashed_pass = users.find({'username': username})[0]['password']

    if bcrypt.hashpw(password.encode('utf8'), hashed_pass) == hashed_pass:
        return True
    else:
        return False


def countTokens(username):
    tokens = users.find({'username': username})[0]['tokens']
    return tokens


class Get(Resource):
    def post(self):
        # Getting posted data by the user
        postedData = request.get_json()

        # Get the data
        username = postedData['username']
        password = postedData['password']

        correct_pw = verifyPass(username, password)
        if not correct_pw:
            retJson = {
                'status': 302
            }
            return jsonify(retJson)

        num_tokens = countTokens(username)
        if num_tokens == 0:
            retJson = {
                'status': 301
            }
            return jsonify(retJson)

        users.update_many({'username': username}, {
                          '$set': {'tokens': num_tokens-1}})

        sentence = users.find({'username': username})[0]['sentence']

        retJson = {
            'status': 200,
            'msg': sentence
        }
        return jsonify(retJson)


class Store(Resource):
    def post(self):
        # Get the posted data
        postedData = request.get_json()

        # Reading the data
        username = postedData['username']
        password = postedData['password']
        sentence = postedData['sentence']

        # Verify if the username matches password
        correct_pw = verifyPass(username, password)
        if not correct_pw:
            retJson = {
                'status': 302
            }
            return jsonify(retJson)

        # Verify if user has enough tokens
        num_tokens = countTokens(username)
        if num_tokens == 0:
            retJson = {
                'status': 301
            }
            return jsonify(retJson)

        # Store the sentence, take one token away and return code 200
        users.update_many({'username': username}, {
                          '$set': {'sentence': sentence, 'tokens': num_tokens-1}})

        retJson = {
            'status': 200,
            'msg': 'Sentence saved successfully'
        }
        return jsonify(retJson)


class Register(Resource):
    def post(self):
        # Getting posted data by the user
        postedData = request.get_json()

        # Get the data
        username = postedData['username']
        password = postedData['password']

        # hash (passord + salt)
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # Store de username and pass into the database
        users.insert_one({
            'username': username,
            'password': hashed_pw,
            'sentence': '',
            'tokens': 6,
        })

        retJson = {
            'status': 200,
            'msg': 'You sucessfully signed up for the API'
        }

        return jsonify(retJson)


api.add_resource(Register, '/register')
api.add_resource(Store, '/store')
api.add_resource(Get, '/get')


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')

"""
Registration of a user 0 tokens
Each user gets 10 tokens
Verify the similarities between 2 files

RESOURCE            ADDRES          PROTOCOL        PARAM           RESPONSE/STATUS CODE
Register user       /register       POST            Username        200 OK
                                                    Password        301 invalid username

Detect similarity   /detect         POST            Username        200 OK
                                                    Password        301 invalid username
                                                    Text 1 and 3    302 invalid pass
                                                                    303 out of tokens

refill tokens       /refill         POST            Username        200 OK
                                                    Adm pass        301 invalid username
                                                    Refill amoit    304 invalid_adm
"""
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app = Flask(__name__)
api = Api(app)

client = MongoClient('mongodb://db:27017')
db = client.SimilarityDB
users = db['Users']


def UserExist(username):
    if users.find({'username': username}).count() == 0:
        return False
    else:
        return True


def verifyPass(username, password):
    hashed_pass = users.find({'username': username})[0]['password']

    if bcrypt.hashpw(password.encode('utf8'), hashed_pass) == hashed_pass:
        return True
    else:
        return False


def countTokens(username):
    tokens = users.find({'username': username})[0]['tokens']
    return tokens


class Refil(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData['username']
        password = postedData['password']
        refill = postedData['refill']

        if not UserExist(username):
            retJson = {
                'status': 301,
                'msg': 'Invalid username'
            }
            return jsonify(retJson)

        correct_pass = 'abc123'
        if not correct_pass == password:
            retJson = {
                'status': 304,
                'msg': 'Invalid Adm pass'
            }
            return jsonify(retJson)

        users.update_many({'username': username}, {
                          '$set': {'tokens': refill}})

        retJson = {
            'status': 200,
            'msg': "Refilled"
        }
        return jsonify(retJson)


class Register(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData['username']
        password = postedData['password']

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
            'tokens': 6,
        })

        retJson = {
            'status': 200,
            'msg': 'You have signed up to the API'
        }
        return jsonify(retJson)


class Detect(Resource):
    def post(self):

        postedDate = request.get_json()

        username = postedDate['username']
        password = postedDate['password']
        text1 = postedDate['text1']
        text2 = postedDate['text2']

        if not UserExist(username):
            retJson = {
                'status': 301,
                'msg': 'Invalid username'
            }
            return jsonify(retJson)

        correct_pw = verifyPass(username, password)
        if not correct_pw:
            retJson = {
                'status': 302
            }
            return jsonify(retJson)

        num_tokens = countTokens(username)
        if num_tokens == 0:
            retJson = {
                'status': 303,
                'msg': 'Out of tokens'
            }
            return jsonify(retJson)

        # Calculate the edit distance
        nlp = spacy.load('en_core_web_sm')

        text1 = nlp(text1)
        text2 = nlp(text2)

        # Ratio is a number between 0 and 1. The closer to 1 the similar text1 and text2 are
        ratio = text1.similarity(text2)

        retJson = {
            'status': 200,
            'similarity': ratio,
            'msg': 'Success'
        }

        users.update_many({'username': username}, {
                          '$set': {'tokens': num_tokens-1}})

        return jsonify(retJson)


api.add_resource(Register, '/register')
api.add_resource(Detect, '/detect')
api.add_resource(Refil, '/refil')


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')

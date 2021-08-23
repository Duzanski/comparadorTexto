"""
Registration of a user 0 tokens
Each user gets 10 tokens
Verify the image

RESOURCE            ADDRES          PROTOCOL        PARAM           RESPONSE/STATUS CODE
Register user       /register       POST            Username        200 OK
                                                    Password        301 invalid username

classify            /classify       POST            Username        200 OK
                                                    Password        301 invalid username
                                                    Url             302 invalid pass
                                                                    303 out of tokens

refill tokens       /refill         POST            Username        200 OK
                                                    Adm pass        301 invalid username
                                                    Refill amoit    304 invalid_adm
"""
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import requests
import subprocess
import json

app = Flask(__name__)
api = Api(app)

client = MongoClient('mongodb://db:27017')
db = client.ImageReco
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


def verifyCredentials(username, password):
    if not UserExist(username):
        return generateReturnDictionary(301, 'Invalid username'), True

    correct_pw = verifyPass(username, password)
    if not correct_pw:
        return generateReturnDictionary(302, 'Invalid password'), True

    return None, False


def generateReturnDictionary(status, msg):
    retJson = {
        'status': status,
        'msg': msg
    }
    return retJson


class Classify(Resource):
    def post(self):

        postedeData = request.get_json()

        username = postedeData['username']
        password = postedeData['password']
        url = postedeData['url']

        retJson, error = verifyCredentials(username, password)
        if error:
            jsonify(retJson)

        tokens = users.find({'username': username})[0]['tokens']
        if tokens == 0:
            return jsonify(generateReturnDictionary(303, 'Not enough tokens'))

        # Donwloading the image
        r = requests.get(url)
        retJson = {}
        with open('temp.jpg', 'wb') as f:
            f.write(r.content)
            proc = subprocess.Popen(
                'python classify_image.py --model_dir=. --image_file=./temp.jpg')
            proc.communicate()[0]
            proc.wait()
            with open('text.txt') as g:
                retJson = json.load(g)

        users.update({'username': username}, {'$set': {'token': tokens-1}})

        return retJson


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
            'tokens': 6,
        })

        retJson = {
            'status': 200,
            'msg': 'You have signed up to the API'
        }
        return jsonify(retJson)


class Refill(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData['username']
        password = postedData['password']
        refill = postedData['refill']

        if not UserExist(username):
            return jsonify(generateReturnDictionary(301, 'Invalid username'))

        correct_pass = 'abc123'
        if not correct_pass == password:
            return jsonify(generateReturnDictionary(304, 'Invalid Adm pass'))

        users.update_many({'username': username}, {
                          '$set': {'tokens': refill}})

        return jsonify(generateReturnDictionary(200, 'Refilled'))


api.add_resource(Register, '/register')
api.add_resource(Classify, '/classify')
api.add_resource(Refill, '/refill')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

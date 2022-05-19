from datetime import datetime, timedelta
from functools import wraps
import hashlib
import json
from bson import ObjectId
from flask import Flask, abort, jsonify, request, Response
from flask_cors import CORS
import jwt
from pymongo import MongoClient, mongo_client



SECRET_KEY = 'turtle'


app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})
client = MongoClient('localhost', 27017)
db = client.turtlegram




def authorize(f):
    @wraps(f)
    def decorated_function():
        if not 'Authorization' in request.headers:
            abort(401)
        token = request.headers['Authorization']
        print(token)
        try:
            user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except:
            abort(401)
        return f(user)
        
    return decorated_function




@app.route("/")
@authorize
def hello_world(user):
    print(user)
    return jsonify({'message': 'success'})




@app.route("/signup", methods=["POST"])
def sign_up():
    data = json.loads(request.data)
    # 이메일/패스워드가 없을때 에러처리
    
        
    
    pw = data.get('password', None)
    hashed_password = hashlib.sha256(pw.encode('utf-8')).hexdigest()
    
    doc = {
        'email': data.get('email'),
        'password': hashed_password
    }

    
    print(doc)
    user = db.users.insert_one(doc)
    print(doc)
    
    return jsonify({'status': 'success'})




@app.route("/login", methods=["POST"])
def login():
    print(request)
    data = json.loads(request.data)
    print(data)
    
    email = data.get("email")
    password = data.get("password")
    hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
    print(hashed_pw)
    
    result = db.users.find_one({
        'email': email,
        'password': hashed_pw
    })
    print(result)
    
    if result is None:
        return jsonify({"message": "아이디나 비밀번호가 옳지 않습니다."}), 401

    payload = {
        'id': str(result["_id"]),
        'exp': datetime.utcnow() + timedelta(seconds= 60 * 20)
    }
    
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256').decode('utf-8')
    print(token)
    
    return jsonify({"message": "success", "token":token})
    
    

@app.route("/getuserinfo", methods=["GET"])
@authorize
def get_user_info(user):
    result = db.users.find_one({
        '_id': ObjectId(user["id"])
    })

    return jsonify({"message": "success", "email": result["email"]})


@app.route("/article", methods=["POST"])
@authorize
def post_article(user):
    data = json.loads(request.data)
    print(data)
    
    db_user = db.users.find_one({'_id': ObjectId(user.get('id'))})
    
    now = datetime.now().strftime("%H:%M:%S")
    doc = {
        'title': data.get('title', None),
        'content': data.get('content', None),
        'user': user['id'],
        'user_email': db_user['email'],
        'time': now,
    }
    print(doc)
    
    db.article.insert_one(doc)
    
    
    return jsonify({"message": "success"})



@app.route("/article", methods=["GET"])
def get_article():
    
    articles = list(db.article.find())
    print(articles)
    
    for article in articles:
        print(article.get("title"))
        article["_id"] = str(article["_id"])
        print(article["_id"])
    return jsonify({"message": "success", "articles": articles})
    # "articles": articles를 해줘야 articles값을 넘겨준다



# 변수명 url을 사용해서 app.py 에서 html로 넘어갈떄 article 데이터 전부를 넘겨주는 방법

@app.route("/article/<article_id>", methods=["GET"]) #변수명 url사용하려면 <>안에 변수를 넣어준뒤 GET으로 받기
# <article_id>에 넣은 값이 밑에 함수로 들어감
def get_article_detail(article_id): # 받은 변수명을 함수안에 꼭 넣어줘야함
    print(article_id) # 변수명 url이 그대로 들어옴
    article = db.article.find_one({"_id": ObjectId(article_id)}) # ObjectId(article_id)를 db에서 검색해서 해당 아이디를 가진 article 전체 데이터를 가져옴.
    print(article) 
    article["_id"] = str(article["_id"])
    
    
    return jsonify({"message": "success", "article": article})




if __name__ == '__main__':
    app.run('0.0.0.0', port=5001, debug=True)

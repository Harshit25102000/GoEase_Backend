from flask_cors import CORS, cross_origin
import json
from common_functions import return_success,return_error,check_student_email,read_credentials_from_file,extract_year_from_email,logged_in,check_prn
from flask import Flask, render_template_string, request, session, redirect, url_for
from mongo_connection import *
from flask_session import Session
import bcrypt
from flask_bcrypt import Bcrypt
app = Flask(__name__)
app.secret_key = "harshit25102000"
CORS(app, supports_credentials=True)
import datetime
import pytz
import threading



# Configuration
#file_path = 'Credentials.txt'
#EMAIL_ADDRESS, EMAIL_PASSWORD = read_credentials_from_file(file_path)



@app.route("/student/signup",methods=["POST"])
def student_signup():

        print(request)
        data = request.get_json()
        print(data)
        name = data["name"]
        email = data["email"]
        password = data["password1"]
        password2=data["password2"]
        prn = data["prn"]

        login_user = student_credentials.find_one({'email': email})
        if login_user is not None:
            print("one")
            return return_error(error="ACCOUNT_ALREADY_EXIST", message="Account already exists")
        if not check_student_email(email):
            print("2")
            return return_error(error="WRONG_EMAIL", message="Wrong email for student")
        if not check_prn(prn):
            print("3")
            return return_error(error="WRONG_PRN", message="Wrong format for PRN")
        if not password==password2:
            print("4")
            return return_error(error="PASSWORD_DON'T_MATCH", message="Passwords do not match")
        # converting password to array of bytes

        bytes = password.encode('utf-8')

        # generating the salt
        salt = bcrypt.gensalt()
        hashpass=bcrypt.hashpw(bytes, salt)
        batch=extract_year_from_email(email)

        query={"name":name, "password":hashpass,"email":email,"prn":prn,"batch":batch}
        print(query)
        student_credentials.insert_one((query))
        session["email"]=email
        return return_success({"email":email})
    # except Exception as e:
    #     return return_error(message=str(e))

@app.route("/student/logout")
@logged_in
def logout():
    try:
        del session["email"]
        return return_success(status="LOGOUT")
    except Exception as e:
        return return_error(message=str(e))


@app.route("/student/login",methods=["POST"])
def student_login():
    try:
        data = request.get_json()

        email = data["email"]
        password = data["password"]


        if not check_student_email(email):
            return return_error(error="WRONG_EMAIL", message="Wrong email for student")
        login_user=student_credentials.find_one({'email':email})
        if login_user is None:
            return return_error(error="ACCOUNT_DOES_NOT_EXIST", message="No account exists with this email address")
        # converting password to array of bytes
        given_password=password.encode('utf-8')
        result=bcrypt.checkpw(given_password, login_user["password"])

        if not result:
            return return_error(error="WRONG_PASSWORD", message="Wrong password for this email")

        session["email"]=email
        return return_success({"email":email})
    except Exception as e:
        return return_error(message=str(e))








if __name__=="__main__":
    app.run(debug=False)
    app.run(host="0.0.0.0", port=5000)



    app.config['DEBUG'] = False
    app.secret_key = "harshit25102000"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
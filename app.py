from flask_cors import CORS, cross_origin
import json
from common_functions import return_success,return_error,check_student_email,read_credentials_from_file,extract_year_from_email,logged_in,check_prn,generate_otp,generate_unique_id
from flask import Flask, render_template_string, request, session, redirect, url_for,send_file, Response
from mongo_connection import *
from flask_session import Session
import bcrypt
import csv
import io

import pandas as pd
from flask_bcrypt import Bcrypt
app = Flask(__name__)
app.secret_key = "harshit25102000"
CORS(app,supports_credentials=True)
import random
import datetime
import pytz
from io import BytesIO
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from OpenSSL import SSL
# # Create a client context
# context = SSL.Context(SSL.SSLv23_METHOD)
#
# # Load private key and certificate
# context.use_privatekey_file('key.pem')
# context.use_certificate_file('cert.pem')

# Configuration
file_path = 'credentials.txt'
EMAIL_ADDRESS, EMAIL_PASSWORD = read_credentials_from_file(file_path)



@app.route("/student/signup",methods=["POST"])
def student_signup():
    try:
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
    except Exception as e:
         return return_error(message=str(e))

@app.route("/student/logout")
@logged_in
def student_logout():
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
            print("one")
            return return_error(error="WRONG_EMAIL", message="Wrong email for student")
        login_user=student_credentials.find_one({'email':email})
        print("running")
        if login_user is None:
            print("two")
            return return_error(error="ACCOUNT_DOES_NOT_EXIST", message="No account exists with this email address")
        # converting password to array of bytes
        given_password=password.encode('utf-8')
        result=bcrypt.checkpw(given_password, login_user["password"])

        if not result:
            return return_error(error="WRONG_PASSWORD", message="Wrong password for this email")

        session["email"]=email
        print("suc")
        return return_success({"email":email})
    except Exception as e:
        return return_error(message=str(e))

@app.route("/student/mark_attendance",methods=["POST"])
def mark_attendance():
    try:
        data = request.get_json()

        class_name = data["class_name"]
        date = data["date"]
        teacher=data["teacher"]
        unique_id=data["unique_id"]
        device_id=data["deviceID"]
        student=data["email"]
        query = {'unique_id':unique_id}
        if student_credentials.find_one({'email':student}) is None:
            return return_error(error="STUDENT DOES NOT EXIST", message="Student's email does not exist")
        if unique_db.find_one(query) is None:
            return return_error(error="WRONG_UNIQUE_ID", message="Unique Id of QR is expired")
        del data["unique_id"]
        x = student_credentials.find_one({'email': student})
        if attendance_db.find_one({"class_name":class_name,"date":date,"teacher":teacher,"student":x["name"]}) is not None:
            return return_error(error="ATTENDANCE_ALREADY_MARKED", message="Attendance already marked")
        if attendance_db.find_one({"class_name":class_name,"date":date,"teacher":teacher}) is not None:
            return return_error(error="ATTENDANCE_ALREADY_MARKED_WITH_THIS_DEVICE", message="Attendance already marked with this device")
        else:

            del data["email"]
            data["student"]=x["name"]
            data["prn"]=x["prn"]
            data["batch"]=x["batch"]
            attendance_db.insert_one(data)
            return return_success()
    except Exception as e:
        return return_error(message=str(e))

"""--------------------------------------------------------------Teachers Code Below--------------------------------------------------------------"""

@app.route("/teacher/send_signup_otp",methods=["POST"])
def teacher_send_signup_otp():
    try:
        print(request)
        data = request.get_json()
        email = data["email"]
        if not email.endswith("sitpune.edu.in"):

            return return_error(error="WRONG_EMAIL", message="Email not associated with college")
        otp=generate_otp()
        otp_db.insert_one({"otp":otp})
        # sending mail----------------------------
        subject = "GoEase OTP for Professors"
        body = f"Your OTP for GoEase Signup Process is\n{otp}\nIf this was not you then please contact us at :\nharshit25102000@gmail.com"

        msg = MIMEMultipart()
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = email
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain"))

        # Connect to the SMTP server and send the email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(email, email, msg.as_string())
        return return_success()
    except Exception as e:
         return return_error(message=str(e))

@app.route("/teacher/verify_signup_otp",methods=["POST"])
def teacher_verify_signup_otp():
    try:

        data = request.get_json()
        email = data["email"]
        otp = data["otp"]
        if not isinstance(otp,str):
            return return_error(error="OTP_MUST_BE_STRING", message="OTP must be a string datatype")
        value=otp_db.find_one({"otp":otp})
        if value is None:
            return return_error(error="INVALID_OTP", message="No such otp exists in the database")
        otp_db.delete_one({"otp":otp})
        verified_emails.insert_one({"email":email})
        return return_success()
    except Exception as e:
         return return_error(message=str(e))
@app.route("/teacher/signup",methods=["POST"])
def teacher_signup():
    try:

        data = request.get_json()
        name = data["name"]
        email = data["email"]
        password = data["password1"]
        password2=data["password2"]
        login_user = teacher_credentials.find_one({'email': email})
        if login_user is not None:

            return return_error(error="ACCOUNT_ALREADY_EXIST", message="Account already exists")
        verify=verified_emails.find_one({'email': email})
        if verify is None:
            return return_error(error="EMAIL_NOT_VERIFIED", message="Email not verified with OTP")
        if not password==password2:

            return return_error(error="PASSWORDS_DON'T_MATCH", message="Passwords do not match")
        # converting password to array of bytes

        bytes = password.encode('utf-8')

        # generating the salt
        salt = bcrypt.gensalt()
        hashpass=bcrypt.hashpw(bytes, salt)
        query={"name":name, "password":hashpass,"email":email}
        teacher_credentials.insert_one(query)
        session["email"]=email
        verified_emails.delete_one({"email":email})
        return return_success({"email":email})
    except Exception as e:
         return return_error(message=str(e))


@app.route("/teacher/login",methods=["POST"])
def teacher_login():
    try:
        data = request.get_json()

        email = data["email"]

        password = data["password"]


        if not email.endswith("sitpune.edu.in"):

            return return_error(error="WRONG_EMAIL_FORMAT", message="Email not associated with college")
        login_user=teacher_credentials.find_one({'email':email})

        if login_user is None:

            return return_error(error="ACCOUNT_DOES_NOT_EXIST", message="No account exists with this email address")
        # converting password to array of bytes
        given_password=password.encode('utf-8')
        result=bcrypt.checkpw(given_password, login_user["password"])

        if not result:
            return return_error(error="WRONG_PASSWORD", message="Wrong password for this email")



        session["email"]=email
        return return_success({"email":session["email"]})
    except Exception as e:
        return return_error(message=str(e))

@app.route("/teacher/logout",methods=["GET"])
@logged_in
def teacher_logout():
    try:
        del session["email"]
        return return_success(status="LOGOUT")
    except Exception as e:
        return return_error(message=str(e))

@app.route("/teacher/@me",methods=["GET"])
@logged_in
def at_me():
    user_id = session.get("email")
    if not user_id:
        return return_error(error="UNAUTHORIZED",code=401)
    else:
        return return_success(data={"email": user_id})

@app.route("/teacher/add_class",methods=["POST"])
@logged_in
def add_class():
    try:
        data = request.get_json()
        name = data["name"]
        description=data.get("description","")
        low_attendance=data["low_attendance"]
        warning=data["warning"]
        students=data["students"]
        schedule=data["schedule"]
        print(data)
        data["teacher"]=session["email"]

        if class_db.find_one({"teacher":session["email"],"name":name}):
            return return_error(error="CLASS_ALREADY_EXIST", message="Class already exists , use edit option instead")
        class_db.insert_one(data)
        return return_success()
    except Exception as e:
        return return_error(message=str(e))

@app.route("/teacher/get_classes",methods=["GET"])
@logged_in
def get_classes():


        print(session["email"])
        x=class_db.find({"teacher":session["email"]},{ "_id": 0, "name": 1,"description":1 })


        ls=[]
        for i in x:
            ls.append(i)
            print(i)
        if len(ls) == 0:
            return return_error(error="NO_CLASSES_FOUND", message="No classes exist for this teacher")

        print(ls)
        return return_success(ls)
@app.route("/teacher/get_upcoming_classes",methods=["GET"])
@logged_in
def get_upcoming_classes():
    current_day = datetime.datetime.now().strftime("%A").lower()  # Get the current day (e.g., "friday")
    current_time = datetime.datetime.now().strftime("%H:%M")  # Get the current time in HH:MM format
    print(current_time)
    print(current_day)

    x=class_db.find({"teacher":session["email"]},{ "_id": 0 })
    ls=[]
    for i in x:
        isday=i["schedule"]
        if isday.get(current_day) is not None:
        # if current_day in i["schedule"]:

            timing=isday[current_day]["time"]
            cur_time = datetime.datetime.strptime(current_time, "%H:%M")
            stored_time=datetime.datetime.strptime(timing["start"], "%H:%M")
            if stored_time>cur_time:
                ls.append(i)
    print(ls)

    if len(ls) == 0:
        return return_error(error="NO_CLASSES_FOUND", message="No classes exist for this teacher")


    return return_success(ls)
@app.route("/teacher/get_timetable",methods=["GET"])
@logged_in
def get_timetable():
    print(session)
    try:
        print(session["email"])
        x=class_db.find({"teacher":session["email"]},{ "_id": 0, "name": 1 ,"schedule":1})


        ls=[]
        for i in x:
            ls.append(i)
            print(i)
        if len(ls) == 0:
            return return_error(error="NO_CLASSES_FOUND", message="No classes exist for this teacher")

        print(ls)
        return return_success(ls)
    except Exception as e:
        return return_error(message=str(e))

@app.route("/teacher/generate_qr",methods=["POST"])
@logged_in
def generate_qr():

    try:
        data = request.get_json()
        class_name = data["class_name"]
        auth_type=data["auth_type"]
        additional=data.get("additional","")
        today = datetime.datetime.today()
        today=today.strftime("%d/%m/%Y")
        query = {'teacher':session['email'],'class':class_name,'date':today,'auth_type':auth_type,'additional':additional}
        if unique_db.find_one(query) is None:
            print("first time")
            query["unique_id"] = generate_unique_id()
            unique_db.insert_one(query)
            del query["_id"]
            return return_success(query)
        else:
            print("not first time")
            query["unique_id"] = generate_unique_id()
            new_data = {"$set": query}
            unique_db.update_one({'teacher':session['email'],'class':class_name,'date':today}, new_data)
            print(query)
            return return_success(query)
    except Exception as e:
        return return_error(message=str(e))


@app.route("/teacher/get_attendance_dates",methods=["POST"])
@logged_in
def get_attendance_dates():

    try:
        data = request.get_json()
        class_name = data["className"]
        x= attendance_db.find({"class_name": class_name})
        res=[]
        if x is not None:
            for i in x:
                print(i)
                res.append(i["date"])
            return return_success(res)
        else:
            return return_error(error="NO_ATTENDANCE_FOUND", message="No attendance exist for this class")

    except Exception as e:
        return return_error(message=str(e))

@app.route("/teacher/stop_qr",methods=["POST"])
@logged_in
def stop_qr():

    try:
        data = request.get_json()
        class_name = data["class_name"]
        auth_type=data["auth_type"]
        additional=data.get("additional","")
        today = datetime.datetime.today()
        today=today.strftime("%d/%m/%Y")
        query = {'teacher':session['email'],'class':class_name,'date':today,'auth_type':auth_type,'additional':additional}
        if unique_db.find_one(query) is None:
            return return_error(error="NO_QR_FOUND", message="No QR data found to stop")
        else:
            unique_db.delete_one(query)
            return return_success()
    except Exception as e:
        return return_error(message=str(e))

@app.route("/teacher/download_attendance",methods=["POST"])
@logged_in
def download_attendance():

        print("running")
        data = request.get_json()
        class_name = data["className"]
        date=data["date"]
        print(class_name,date)
        filter = {
            "class_name": class_name,
            "date": date,
            "teacher": session["email"]
        }


        projection = {
            "prn": 1,
            "batch": 1,
            "student": 1,
            "_id": 0
        }

        # Query the collection with the filter and projection
        results = attendance_db.find(filter, projection)

        # exceldata = [
        #     {"name": "Item 1", "value": 100},
        #     {"name": "Item 2", "value": 200},
        #     # Add more data as needed
        # ]
        csv_output = io.StringIO()
        csv_writer = csv.writer(csv_output)


        # Write the CSV header
        csv_writer.writerow(["prn", "batch", "student"])
        for result in results:
            csv_writer.writerow([result["prn"], result["batch"], result["student"]])

        # # Write the data rows to the CSV file
        # for row in exceldata:
        #     csv_writer.writerow([row[field] for field in fieldnames])

        # Prepare the CSV response
        response = Response(csv_output.getvalue(), content_type='text/csv')
        response.headers['Content-Disposition'] = f'attachment; filename={date}.csv'
        print(response)
        return response


@app.route("/teacher/get_attendance_names",methods=["POST"])
@logged_in
def get_attendance_names():

    try:
        data = request.get_json()
        class_name = data["class_name"]

        date = datetime.datetime.today()
        date = date.strftime("%d/%m/%Y")

        teacher = session["email"]

        x = attendance_db.find({"class_name": class_name,'date': date,'teacher': teacher})
        res = []
        if x is not None:
            print("true")
            for i in x:
                temp={}
                temp["name"]=i["student"]
                temp["prn"]=i["prn"]
                print(temp)
                res.append(temp)
            print(res)
            return return_success(res)
        else:
            return return_error(error="NO_NAME_FOUND", message="No attendance exist for this class")

    except Exception as e:
        return return_error(message=str(e))



context = ('cert.pem', 'key.pem')
if __name__=="__main__":

    app.config['DEBUG'] = True
    app.secret_key = "harshit25102000"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
    app.config["SESSION_PERMANENT"] = True
    app.config["SESSION_TYPE"] = "mongodb"
    app.config["SESSION_MONGODB"] = client
    app.config["SESSION_MONGODB_DB"] = 'userData'
    app.config["SESSION_MONGODB_COLLECTION"] = 'sessions'
    Session(app)
    app.run(debug=True)




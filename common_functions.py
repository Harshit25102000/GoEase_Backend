import re
from flask import jsonify
from flask import session
from functools import wraps
def return_error(error="SOMETHING_WENT_WRONG", message="Error", data={}, code=200):
    return jsonify({"success": False, "error": error, "message": message, "data": data})


def return_success(data={}, status="SUCCESS", code=200):
    if isinstance(data, (dict, list)):
        if isinstance(data, (list)):
            l_data = {}
            l_data['status'] = status
            l_data['data'] = data
            return jsonify({"success": True, "data": l_data})
        if data.get('status', False):
            return jsonify({"success": True, "data": data})
        else:
            data['status'] = status
            return jsonify({"success": True, "data": data})
    else:
        raise Exception(f'data obj must be list or dict but got {type(data)}')



import re


def check_student_email(email):
    # Define the regular expression pattern for the email format
    pattern = r'^[a-zA-Z]+\.[a-zA-Z]+\.btech\d{4}@sitpune\.edu\.in$'

    # Use re.match to check if the email matches the pattern
    if re.match(pattern, email):
        return True
    else:
        return False

def read_credentials_from_file(file_path):
    with open(file_path, 'r') as file:
        email = file.readline().strip()
        password = file.readline().strip()
    return email, password


def extract_year_from_email(email):
    # Define the regular expression pattern for the email format
    pattern = r'^[a-zA-Z]+\.[a-zA-Z]+\.btech(\d{4})@sitpune\.edu\.in$'

    # Use re.match to find the year in the email
    match = re.match(pattern, email)

    if match:
        year = match.group(1)  # Extract the year from the first capturing group
        return int(year)  # Convert the extracted year to an integer
    else:
        return None  # Return None if the email format doesn't match

def logged_in(f):
    @wraps(f)
    def decorated_func(*args, **kwargs):
        email = session.get("email",None)
        if email:
            return f(*args, **kwargs)
        else:
            return return_error('LOGIN_REQUIRED',"Session not found login again")
    return decorated_func

def check_prn(string):
    if string.isdigit() and len(string) == 11:
        return True
    else:
        return False
from flask import Flask, render_template, request, url_for, redirect, session , flash
from pymongo import MongoClient
import bcrypt
from flask_bootstrap import Bootstrap
import requests

phoneNo='8426811477'

legSchema={
    'type':'object',
    'properties':{
        "PositionType": {'type': 'string'},
        "Lots": {'type': 'integer'},
        "LegStopLoss": {'type': 'object'},
        "LegTarget": {'type': 'object'},
        "LegTrailSL":{'type': 'object'},
        "LegMomentum": {'type': 'object'},
        "ExpiryKind": {'type': 'string'},
        "EntryType": {'type': 'string'},
        "StrikeParameter": {'type':'string'|'object'|'number'},
        "InstrumentKind": {'type': 'string'},
        "LegReentrySL": {'type': 'object'},
        "LegReentryTP": {'type': 'object'}
    }
}


def create_app():
  app = Flask(__name__)
  Bootstrap(app)

  return app
app=create_app()
#encryption relies on secret keys so they could be run
app.secret_key = "testing"

# #connect to your Mongo DB database
def MongoDB():
    client = MongoClient("mongodb+srv://sahilm:sahilm123@records.gihqcee.mongodb.net/?retryWrites=true&w=majority")
    db = client.get_database('total_records')
    records = db.register
    legs=db.lists
    return records,legs
records = MongoDB()




#assign URLs to have a particular route 
@app.route("/", methods=['post', 'get'])
def index():
    global phoneNo
    message = ''
    #if method post in index
    if "email" in session:
        return redirect(url_for("logged_in"))
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")
        phoneNumber=request.form.get("phoneNumber")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        #if found in database showcase that it's found 
        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            return render_template('index.html', message=message)
        if email_found:
            message = 'This email already exists in database'
            return render_template('index.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('index.html', message=message)
        else:
            #hash the password and encode it
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            #assing them in a dictionary in key value pairs
            user_input = {'name': user, 'email': email, 'password': hashed, 'phoneNumber': phoneNumber}
            phoneNo=phoneNumber
            #insert it in the record collection
            records.insert_one(user_input)
            #get OTP and confirm it
            #find the new created account and its email
            user_data = records.find_one({"email": email})
            new_email = user_data['email']
            #if registered redirect to logged in as the registered user
            return render_template('verifyOtp.html')
    return render_template('index.html')

@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    if "email" in session:
        return redirect(url_for("logged_in"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        #check if email exists in database
        email_found = records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            passwordcheck = email_found['password']
            #encode the password and check if it matches
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                return redirect(url_for('logged_in'))
            else:
                if "email" in session:
                    return redirect(url_for("logged_in"))
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)

@app.route('/logged_in')
def logged_in():
    if "email" in session:
        email = session["email"]
        return render_template('logged_in.html', email=email)
    else:
        return redirect(url_for("login"))

@app.route('/verify-otp', methods=["POST", "GET"])
async def verify_otp():
    if request.method=='POST':
        url = f"https://2factor.in/API/V1/030b4466-87ef-11ed-9158-0200cd936042/SMS/+91{phoneNo}/AUTOGEN"
        payload={}
        headers = {}
        await requests.get(url,headers=headers,data=payload)
        phoneNumber=request.form.get('PhoneNumber')
        OTP=request.form.get('OTPLogin')
        verifyUrl=f"https://2factor.in/API/V1/030b4466-87ef-11ed-9158-0200cd936042/SMS/VERIFY3/+91{phoneNumber}/{OTP}"
        verifyResponse=await requests.get(verifyUrl,headers=headers,data=payload)
        if verifyResponse.text.Details == 'OTP Matched':
            return render_template('logged_in.html')
        else:
            return render_template('index.html')

@app.route("/forgot-password",methods=["POST","GET"])
async def forgotPassword(): 
    return render_template("verifyOtp.html")

@app.route("/store-lists",methods=["POST"])
@expects_json(schema)
def storeLists():
    


@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
        return render_template("signout.html")
    else:
        return render_template('index.html')




if __name__ == "__main__":
  app.run(debug=True, host='0.0.0.0', port=5000)

from flask import Flask, render_template, url_for, request, session, redirect, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, validators, IntegerField
from wtforms.validators import InputRequired, Email, Length, ValidationError, Regexp
from flask_pymongo import PyMongo
import bcrypt
import pickle
from sklearn.feature_extraction.text import CountVectorizer
import numpy
import os

app = Flask(__name__, static_folder='static')

app.config["SECRET_KEY"] = "ursecretkey"
ENV = 'dev'

if ENV == 'dev':
    app.debug = True
    app.config["MONGO_URI"] = "your mongo uri"
else:
    app.debug = False
#    app.config['MONGO_URI'] = ''

app.config["MONGO_DBNAME"] = 'your database'
Bootstrap(app)
mongo = PyMongo(app)


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[
                             InputRequired(), Length(min=8, max=50)])


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
                           InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Length 4 to 15 characters"})
    password = PasswordField('Password', validators=[
                             InputRequired(), Length(min=8, max=50)], render_kw={"placeholder": "Length 8 to 50 characters"})
    email = StringField('Email', validators=[InputRequired(), Email(
        message="INVALID EMAIL"), Length(max=50)], render_kw={"placeholder": "example@email.com"})
    name = StringField('Name', validators=[
        InputRequired(), Length(min=2, max=50)], render_kw={"placeholder": "Length 2 to 50 characters"})
    phone = StringField('Phone number', validators=[Regexp(
        "^[0-9]{10}$", message="Enter valid phone number of 10 digits")], render_kw={"placeholder": "Length 10 digits"})


class SmsSpamForm(FlaskForm):
    ip = StringField('Enter Message', validators=[
                     InputRequired(), Length(max=1000000)], render_kw={"placeholder": "Example: Hello How are you,long time no see."})


class EmailSpamForm(FlaskForm):
    ipe = StringField('Enter Email', validators=[
        InputRequired(), Length(max=1000000)], render_kw={"placeholder": "Example: Subject:Regarding the newspaper Advertisement Good Morning sir...message continues.."})


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        users = mongo.db.userinfo
        login_user = users.find_one({'username': request.form['username']})
        if login_user:
            if bcrypt.hashpw(request.form['password'].encode('utf-8'), login_user['password']) == login_user['password']:
                session['username'] = request.form['username']
                return redirect(url_for('dash'))
        else:
            error = 'Invalid username/password combination'
            flash('Invalid username/password combination')
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    error = None
    if form.validate_on_submit() and request.method == 'POST':
        users = mongo.db.userinfo
        existuser = users.find_one({'username': request.form['username']})
        if existuser is None:
            hashpass = bcrypt.hashpw(
                request.form['password'].encode('utf-8'), bcrypt.gensalt())
            users.insert({'username': request.form['username'], 'password': hashpass,
                          'email': request.form['email'], 'name': request.form['name'], 'phone': request.form['phone']})
            return redirect(url_for('login'))
        else:
            error = 'That username already exists!'
            flash('That username already exists!')
    return render_template('signup.html', form=form)


@app.route('/dash')
def dash():
    if 'username' in session:
        return render_template('dash3.html')
    else:
        return render_template('index.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')


@app.route('/spamsmsdetect', methods=['GET', 'POST'])
def spamsmsdetect():
    if 'username' in session:
        form = SmsSpamForm()
        p = ""
        if form.validate_on_submit():
            print("Submitted")
            cv = CountVectorizer()
            model = pickle.load(open('model/modeldec.pkl', 'rb'))
            model2 = pickle.load(open('model/vec.pkl', 'rb'))
            ii = request.form['ip']
            f = [str(ii)]
            print(f)
            final = model2.transform(f).toarray()
            if(model.predict(final) == 0):
                p = "Not Spam"
            else:
                p = "Spam"
            smspred = mongo.db.smsprediction
            smspred.insert_one(
                {'username': session['username'], 'ipstring': ii, 'Prediction': p})
        return render_template('smsspam.html', form=form, p=p)
    else:
        return render_template('index.html')

@app.route('/api_pred_sms', methods=['GET', 'POST'])
def api_pred_sms():
    if 'username' in session:
        form = SmsSpamForm()
        p = ""
        if form.validate_on_submit():
            print("Submitted")
            cv = CountVectorizer()
            model = pickle.load(open('model/modeldec.pkl', 'rb'))
            model2 = pickle.load(open('model/vec.pkl', 'rb'))
            ii = request.form['ip']
            f = [str(ii)]
            print(f)
            final = model2.transform(f).toarray()
            if(model.predict(final) == 0):
                p = "Not Spam"
            else:
                p = "Spam"
            smspred = mongo.db.smsprediction
            smspred.insert_one(
                {'username': session['username'], 'ipstring': ii, 'Prediction': p})
        return p
    else:
        return render_template('index.html')




@app.route('/spamemaildetect', methods=['GET', 'POST'])
def spamemaildetect():
    if 'username' in session:
        form = EmailSpamForm()
        p = ""
        if form.validate_on_submit():
            print("Submitted")
            cv = CountVectorizer()
            model = pickle.load(open('model/emmodeldec.pkl', 'rb'))
            model2 = pickle.load(open('model/emvec.pkl', 'rb'))
            ii = request.form['ipe']
            f = [str(ii)]
            print(f)
            final = model2.transform(f).toarray()
            if(model.predict(final) == 0):
                p = "Not Spam"
            else:
                p = "Spam"
            empred = mongo.db.emprediction
            empred.insert_one(
                {'username': session['username'], 'ipstring': ii, 'Prediction': p})
        return render_template('emailspam.html', form=form, p=p)
    else:
        return render_template('index.html')

@app.route('/api_pred_em', methods=['GET', 'POST'])
def api_pred_em():
    if 'username' in session:
        form = EmailSpamForm()
        p = ""
        if form.validate_on_submit():
            print("Submitted")
            cv = CountVectorizer()
            model = pickle.load(open('model/emmodeldec.pkl', 'rb'))
            model2 = pickle.load(open('model/emvec.pkl', 'rb'))
            ii = request.form['ipe']
            f = [str(ii)]
            print(f)
            final = model2.transform(f).toarray()
            if(model.predict(final) == 0):
                p = "Not Spam"
            else:
                p = "Spam"
            empred = mongo.db.emprediction
            empred.insert_one(
                {'username': session['username'], 'ipstring': ii, 'Prediction': p})
        return p
    else:
        return render_template('index.html')
@app.route('/aboutus')
def aboutus():
    if 'username' in session:
        return render_template('aboutus.html')
    else:
        return render_template('index.html')


if __name__ == '__main__':
    app.run()

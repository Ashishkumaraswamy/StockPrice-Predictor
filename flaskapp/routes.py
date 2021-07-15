from flask import render_template, url_for, flash, redirect, request
from flaskapp.models import User, Stocks
from flaskapp import app, db, bcrypt
from flaskapp.forms import RegistrationForm, LoginForm ,ForgetForm,EditProfileForm
from flask_login import login_user, current_user, logout_user, login_required


@app.route("/", methods=['GET', 'POST'])
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('mainpage'))
    form = LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user)
            next_page=request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('mainpage'))
        else:
            flash('Login Unsuccessfull.Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('login'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(username=form.username.data,
                    email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        # flash(f'Account Created for {form.username.data}!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/forgot", methods=['GET', 'POST'])
def forgot():
    form = ForgetForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user:
            hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            print(user.password)
            return redirect(url_for('login'))
        else:
            flash('No such email exits!! Please check email', 'danger')
    return render_template('forgot.html', title='Forgot', form=form)


@app.route("/mainpage", methods=['GET'])
def mainpage():
    return render_template('mainpage.html', title='Stock Analysis')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form=EditProfileForm()
    print(current_user.password)
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password,form.currentpassword.data):
            hashed_password = bcrypt.generate_password_hash(
            form.newpassword.data).decode('utf-8') 
            current_user.password=hashed_password
            current_user.username=form.username.data
            current_user.email=form.email.data
            db.session.commit()
            return redirect(url_for('account'))
        else:
            flash('Enter Correct Password', 'danger')
    elif request.method=='GET':
        form.username.data=current_user.username
        form.email.data=current_user.email
    return render_template('account.html', title='Account',form=form)
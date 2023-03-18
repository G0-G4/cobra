from flask import Flask, render_template, flash, redirect, url_for, request
from flask_sqlalchemy  import SQLAlchemy
from sqlalchemy import desc, exc
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length, InputRequired
import os


basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir,'db.sqlite')
app.config['SECRET_KEY'] = os.urandom(32)
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(20), unique = True)
    password_hash = db.Column(db.String(128))
    high_score = db.Column(db.Integer, default = 0)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User> {self.id}, {self.name}, {self.high_score}'

class Form(FlaskForm):
    name = StringField('name', validators = [InputRequired()], render_kw={"placeholder": "name"})
    password = PasswordField('password', validators = [InputRequired()], render_kw={"placeholder": "password"})
    submit = SubmitField()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = Form()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.name.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('invalid name or password')
    return render_template('login.html', form=form)

@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = Form()
    if form.validate_on_submit():
        user = User(
            name = form.name.data,
            password = form.password.data
            )
        db.session.add(user)
        try:
            db.session.commit()
        except exc.IntegrityError:
            flash('this name is already taken')
            return redirect(url_for('register'))
        flash('you are registered, now you can log in')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('you have been logout')
    return redirect(url_for('index'))

@app.route('/cobra', methods = ['GET', 'POST'])
@login_required
def cobra():
    return render_template('cobra.html')

@app.route('/save', methods = ['POST'])
@login_required
def save():
    score = int(request.form['score'])
    high_score = current_user.high_score
    if score > high_score:
        current_user.high_score = score
        db.session.commit()
    return redirect(url_for('scores', score=score))

@app.route('/scores/<score>', methods = ['GET'])
@login_required
def scores(score):
    users = User.query.order_by(desc(User.high_score)).limit(20).all()
    return render_template('scores.html', score=score, users=users)

@app.route('/', methods = ['GET'])
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug = True)
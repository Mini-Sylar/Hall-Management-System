from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login.utils import login_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import redirect
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, func
from flask_login import UserMixin, login_manager, login_user, LoginManager, login_required, logout_user
from datetime import datetime, date, timedelta
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message
import click
from flask.cli import with_appcontext

app = Flask(__name__)
app.config['SECRET_KEY'] = '1234'
# DATABASE_URL = os.environ['DATABASE']
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE')
# conn = psycopg2.connect(DATABASE_URL, sslmode='require')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hallmanagement.db'

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'resetpasswtaessa@gmail.com'
app.config['MAIL_PASSWORD'] = 'qgdjoydwcaxclyqi'
# 'taessa30reset12'
# qgdjoydwcaxclyqi
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@click.command(name='create_tables')
@with_appcontext
def create_tables():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    # print("login is", User.query.get(int(user_id)))
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def handle_needs_login():
    flash("You have to be logged in to access this page.", 'error')
    return redirect(url_for('login', next=request.endpoint))


class HallManage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(200), nullable=False)
    lastname = db.Column(db.String(200), nullable=False)
    student_name = db.Column(db.String(200), nullable=False)
    student_id = db.Column(db.Integer, unique=True, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    room_number = db.Column(db.String(20), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    course_name = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.id


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return '<User %r>' % self.id


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignee = db.Column(db.String(200), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    person_modified = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.id


# Landing Page
@app.route('/', methods=['POST', 'GET'])
def index():
    return render_template('LandingPage.html')

# About Page


@app.route('/About', methods=['POST', 'GET'])
def AboutUs():
    return render_template('AboutUs.html')

# Contact Page


@app.route('/Contact', methods=['POST', 'GET'])
def Contact():
    return render_template('Contact.html')


@app.route('/SignUp', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.form['password'] != request.form['confirmpassword']:
            flash("Passwords do not match check it", 'warning')
            return redirect("/SignUp")
        elif request.form['secretkey'] != "porter2021":
            flash(
                "Key provided is invalid, check with the head porter and try again", 'info')
            return redirect("/SignUp")
        else:
            user_info = User(
                fullname=request.form['fullname'].title(),
                email=request.form['email'],
                username=request.form['username'],
                password=generate_password_hash(
                    request.form['password'], method='sha256')

            )
            try:
                db.session.add(user_info)
                db.session.commit()  # Add new data to db
                return redirect("/login")
            except:
                # replace with nicer experience
                flash("Username already exists choose another one", 'error')
                return redirect("/SignUp")
    else:
        return render_template('RegisterStaff.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        session['user'] = username
        # print(session['user'])
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.', 'error')
        # if the user doesn't exist or password is wrong, reload the page
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('dashboard'))
    else:
        # take user somewhere
        return render_template("Login.html")


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route('/Dashboard', methods=['POST', 'GET'])
@login_required
def dashboard():
    male = HallManage.query.filter(HallManage.gender == "Male").count()
    female = HallManage.query.filter(HallManage.gender == "Female").count()
    activity = ActivityLog.query.filter(
        func.date(ActivityLog.date_created) == date.today()).all()

    # print("This is session", session['user'])
    return render_template("Dashboard.html", male=male, female=female, activity=activity)


@app.route('/Analytics', methods=['POST', 'GET'])
@login_required
def Analytics():
    male = HallManage.query.filter(HallManage.gender == "Male").count()
    female = HallManage.query.filter(HallManage.gender == "Female").count()
    total = male+female
    results = User.query.order_by(User.fullname).all()
    register_count = User.query.count()
    activity = ActivityLog.query.filter(
        func.date(ActivityLog.date_created)).all()

    mydays = []
    base = datetime.today()
    for x in range(0, 5):
        mydays.append(base + timedelta(days=x))

    day1 = ActivityLog.query.filter(
        func.date(ActivityLog.date_created) == date.today()).count()

    # print("This is analytics", session['user'])
    return render_template("Analytics.html", male=male, female=female, activity=activity,
                           total=total, results=results, day1=day1, register_count=register_count)


@app.route('/addstudent', methods=['POST', 'GET'])
@login_required
def addStudent():
    if request.method == 'POST':
        first_name = request.form['first_name'].title()
        last_name = request.form['last_name'].title()
        studentID = request.form['studentID'].capitalize()
        try:
            gender = request.form['gender']
        except:
            gender = "No Gender"
        roomnumber = request.form['roomnumber']
        phone = request.form['phone']
        course = request.form['course'].title()

        data = HallManage(
            firstname=first_name,
            lastname=last_name,
            student_name=first_name + " " + last_name,
            student_id=studentID,
            gender=gender,
            room_number=roomnumber,
            phone_number=phone,
            course_name=course
        )
        activity = ActivityLog(
            assignee=session['user'],
            action="Added a new student",
            person_modified=first_name + " " + last_name,
        )

        try:
            db.session.add(data)
            db.session.add(activity)
            db.session.commit()
            flash("Student successfully added")
            return redirect("/addstudent")
        except:
            return render_template('ErrorID.html')

    else:
        order = HallManage.query.order_by(HallManage.student_id).all()
        return render_template('Add_Student.html', tasks=order,)


@app.route('/SearchStudent', methods=['POST', 'GET'])
@login_required
def showUser():
    currentpage = request.url_rule
    # print("rule is", currentpage)
    session['rule'] = str(currentpage)
    if request.method == 'POST':
        searchQuery = request.form.get("searchQuery")
        # results = HallManage.query.filter_by(student_id=searchQuery).all()
        try:
            results = HallManage.query.filter(or_(HallManage.student_id == searchQuery,
                                                  HallManage.firstname.op('regexp')(
                                                      r'\b{}\b'.format(searchQuery.title())),
                                                  HallManage.lastname.op('regexp')(
                                                      r'\b{}\b'.format(searchQuery.title())),
                                                  HallManage.student_name.op('regexp')(
                                                      r'\b{}\b'.format(searchQuery.title()))
                                                  )).all()
            return render_template('SearchStudent.html', results=results)
        except:
            return "There was a problem with the querying code"
    else:
        return render_template('SearchStudent.html')


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    student_to_delete = HallManage.query.get_or_404(id)
    activity = ActivityLog(
        assignee=session['user'],
        action="Deleted a student",
        person_modified=student_to_delete.student_name,
    )
    try:
        db.session.add(activity)
        db.session.delete(student_to_delete)
        db.session.commit()
        return redirect(session['rule'])
    except:
        return "There was a problem deleting that student"


@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    updateStudent = HallManage.query.get_or_404(id)
    activity = ActivityLog(
        assignee=session['user'],
        action="Updated a student",
        person_modified=updateStudent.student_name,
    )
    if request.method == 'POST':
        # Update Here
        updateStudent.firstname = request.form['first_name'].title()
        updateStudent.lastname = request.form['last_name'].title()
        updateStudent.student_name = updateStudent.firstname + " " + updateStudent.lastname
        updateStudent.gender = request.form['gender']
        updateStudent.room_number = request.form['roomnumber']
        updateStudent.phone_number = request.form['phone']
        updateStudent.course_name = request.form['course'].title()

        try:
            db.session.add(activity)
            db.session.commit()  # Add new data to db
            return redirect(session['rule'])
        except:
            return "There was an issue updating"
    else:
        return render_template('Update_Student.html', updateStudent=updateStudent)


@app.route('/StudentsData', methods=['POST', 'GET'])
@login_required
def showAll():
    currentpage = request.url_rule
    # print("rule is", currentpage)
    session['rule'] = str(currentpage)
    results = HallManage.query.order_by(HallManage.firstname).all()
    return render_template("Data.html", results=results)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message(subject="Password Reset Request",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email],
                  body=f'''To reset your password, visit the following link:
{url_for('resetToken',token=token, _external=True)}
If you did not make this request then simply ignore this email
                    ''')
    mail.send(msg)


@app.route('/ResetAccount', methods=['POST', 'GET'])
def resetRequest():
    if request.method == "POST":
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Account does not exist')
            # if the user doesn't exist , reload the page
            return redirect(url_for('/SignUp'))
        else:
            send_reset_email(user)
            flash(
                'An email has been sent with instructions to reset your password Check your spam if you are unable to find the message in your inbox', 'info')
            return redirect(url_for('login'))
    else:
        # take user somewhere
        return render_template("ResetAccount.html")


@app.route('/ResetPassword/<token>', methods=['POST', 'GET'])
def resetToken(token):
    user = User.verify_reset_token(token)
    newpassword = request.form.get('newpass')
    confirmpassword = request.form.get('confirmpass')
    if request.method == 'POST':
        if user is None:
            flash("That is an invalid or expired Token. Resend Another Email", 'error')
            return redirect('/ResetAccount')
        else:
            if newpassword == confirmpassword:
                user.password = generate_password_hash(
                    newpassword, method='sha256')
                try:
                    db.session.commit()  # Add new data to db
                    flash(
                        "Password Successfully Reset, Login with the new password", 'success')
                    return redirect("/login")
                except:
                    # replace with nicer experience
                    flash(
                        "There was an issue resetting your password, create another account instead", 'error')
                    return redirect("/SignUp")
            else:
                flash("Passwords Do not Match, try again")
                return redirect(request.referrer)
    else:
        return render_template("ResetPassword.html")


if __name__ == "__main__":
    app.jinja_env.auto_reload = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(debug=True)

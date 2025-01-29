from flask import Flask, render_template,redirect,url_for,request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import check_password_hash,generate_password_hash


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SECRET_KEY"] = "your_secret_key"
db = SQLAlchemy(app)


login_manager_app = LoginManager(app)

class Todo(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key = True)
    title =db.Column(db.String(100))
    state = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key para relacionar con el user


class User(db.Model,UserMixin):
    id = db.Column(db.Integer, autoincrement=True, primary_key = True)
    username =db.Column(db.String(100))
    password =db.Column(db.String(100))
    fullname =db.Column(db.String(100))
    todos = db.relationship('Todo', backref='user', lazy=True)  # Relationship para ver todos

    def __init__(self, username, password, fullname="") -> None:
        self.username = username
        self.password = generate_password_hash(password)
        self.fullname = fullname

    @classmethod
    def check_password(self, hashed_password, password):
        return check_password_hash(hashed_password, password)

with app.app_context():
    db.create_all()
    admin_user = User.query.filter_by(username="admin@admin.com").first()
    if not admin_user:
        admin_user = User(username="admin@admin.com", password="admin2025", fullname="Administrator")
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created: username='admin@admin.com', password='admin2025'")


@login_manager_app.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
@login_required
def index():
    todos = Todo.query.filter_by(user_id=current_user.id).all()  # Get only the current user's todos
    return render_template('index.html', todos=todos, username= current_user)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username=(request.form['username'])
        password=(request.form['password'])
        user = User.query.filter_by(username=username).first()
        if user and User.check_password(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            return "Invalid username or password", 401
    return render_template('login.html')

@app.route("/logout")
def logout():
    logout_user()
    return render_template('logout.html')

# metodos crud de TODO
@app.route("/add", methods=['POST'])
@login_required
def add_todo():
    title = request.form['title']
    new_todo = Todo(title=title, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return redirect(url_for('index'))







# Controladore de Error 401
def status_401(error):
    print('401')
    return redirect(url_for('login'))

# Controladore de Error 404
def status_404(error):
    return render_template('error404.html')


if __name__== '__main__':
    app.register_error_handler(401, status_401)
    app.register_error_handler(404, status_404)
    app.run(debug=True,  port=5001)
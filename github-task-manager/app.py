from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)

# Secret key
app.secret_key = os.environ.get('SECRET_KEY', '123456789')

# Database — use DATABASE_URL env var on Vercel (Neon Postgres), fallback to SQLite locally
database_url = os.environ.get('DATABASE_URL', 'postgresql://neondb_owner:npg_PMvC2FQTKI5p@ep-dawn-violet-akujidvu-pooler.c-3.us-west-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# ── Models ────────────────────────────────────────────────────────────────────

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


with app.app_context():
    db.create_all()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            error = 'Username and password are required'
        else:
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['username'] = user.username
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid username or password'
        return render_template('login.html', error=error)
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            error = 'Username and password are required'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters long'
        elif User.query.filter_by(username=username).first():
            error = 'Username already exists'
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            return redirect(url_for('dashboard'))
        return render_template('register.html', error=error)
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    tasks = Task.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', tasks=tasks)


@app.route('/addtask', methods=['GET', 'POST'])
def addtask():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    error = None
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        if not title:
            error = 'Title is required'
        else:
            new_task = Task(title=title, description=description, user_id=session['user_id'])
            db.session.add(new_task)
            db.session.commit()
            return redirect(url_for('dashboard'))
        return render_template('addtask.html', error=error)
    return render_template('addtask.html')


@app.route('/task/<int:task_id>/complete', methods=['POST'])
def complete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    task = Task.query.get(task_id)
    if task and task.user_id == session['user_id']:
        task.completed = not task.completed
        db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/task/<int:task_id>/delete', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    task = Task.query.get(task_id)
    if task and task.user_id == session['user_id']:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)

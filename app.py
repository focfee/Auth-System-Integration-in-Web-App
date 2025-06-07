from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from datetime import datetime, timedelta, timezone
from models import db, User
from functools import wraps
import hashlib
import jwt
import logging
import os
from dotenv import load_dotenv

dotenv_path = '.env'

if not os.path.exists(dotenv_path):
    print("Ошибка не найден файл .env! Для корректной работы проекта создайте .env на основе .env.example и заполните все нужные параметры.")
    exit(1)

load_dotenv(dotenv_path)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            logger.debug("Token required: No token found")
            return redirect(url_for('login'))
        
        try:
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            current_user = User.query.filter_by(username=data['username']).first()
            if not current_user:
                logger.debug("Token required: User not found in DB")
                return redirect(url_for('login'))
            
            return f(current_user=current_user, *args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            logger.debug("Token expired")
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            logger.debug("Invalid token")
            return redirect(url_for('login'))
        except Exception as e:
            logger.debug(f"Token error: {str(e)}")
            return redirect(url_for('login'))
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(current_user, *args, **kwargs):
        if not current_user.admin:
            logger.debug("Admin required: Access denied")
            return "Доступ запрещён. Требуются права администратора.", 403
        return f(current_user=current_user, *args, **kwargs)
    return decorated_function

def create_default_users():
    admin_username = os.getenv('ADMIN_USERNAME')
    admin_password = os.getenv('ADMIN_PASSWORD')
    admin_is_admin = os.getenv('ADMIN_IS_ADMIN', 'true').lower() == 'true'
    
    admin = User.query.filter_by(username=admin_username).first()
    if not admin:
        password_hash = hashlib.sha256(admin_password.encode()).hexdigest()
        admin_user = User(username=admin_username, password=password_hash, admin=admin_is_admin)
        db.session.add(admin_user)
        logger.info(f"Создан администратор: {admin_username}")
    
    student_username = os.getenv('STUDENT_USERNAME')
    student_password = os.getenv('STUDENT_PASSWORD')
    student_is_admin = os.getenv('STUDENT_IS_ADMIN', 'false').lower() == 'true'
    
    student = User.query.filter_by(username=student_username).first()
    if not student:
        password_hash = hashlib.sha256(student_password.encode()).hexdigest()
        student_user = User(username=student_username, password=password_hash, admin=student_is_admin)
        db.session.add(student_user)
        logger.info(f"Создан студент: {student_username}")
    
    db.session.commit()

with app.app_context():
    db.create_all()
    create_default_users()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['login']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        user = User.query.filter_by(username=username, password=password).first()
        
        if user:
            token_data = {
                'username': username,
                'admin': user.admin,
                'exp': datetime.now(timezone.utc) + timedelta(hours=1)
            }
            token = jwt.encode(token_data, app.secret_key, algorithm="HS256")
            
            resp = make_response(redirect(url_for('index')))
            resp.set_cookie('token', token, httponly=True, secure=os.getenv('FLASK_ENV') == 'production')
            logger.info(f"User {username} logged in. Admin: {user.admin}")
            return resp
        
        error = "Неправильный логин или пароль"
        return render_template('login.html', error=error)
    
    return render_template('login.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form['login']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        if User.query.filter_by(username=username).first():
            error = "Пользователь уже существует"
            return render_template('register.html', error=error)
        new_user = User(username=username, password=password, admin=False)
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"Зарегистрирован новый пользователь: {username}")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/")
def start():
    return redirect(url_for('index'))

@app.route("/main")
@token_required
def index(current_user):
    return render_template('main.html', username=current_user.username, admin=current_user.admin)

@app.route("/account", methods=["GET", "POST"])
@token_required
def account(current_user):
    if request.method == "POST":
        try:
            new_login = request.form.get('login')
            new_password = request.form.get('password')
            if new_login:
                current_user.username = new_login
            if new_password:
                current_user.password = hashlib.sha256(new_password.encode()).hexdigest()
            db.session.commit()
            logger.info(f"Пользователь {current_user.username} обновил данные аккаунта")
        except Exception as e:
            logger.error(f"Ошибка при обновлении аккаунта: {str(e)}")
            return "Internal Server Error", 500
        return redirect(url_for('account'))
    return render_template('account.html', username=current_user.username, admin=current_user.admin)

@app.route("/delete_account")
@token_required
def delete_account(current_user):
    try:
        username = current_user.username
        db.session.delete(current_user)
        db.session.commit()
        resp = make_response(redirect(url_for('register')))
        resp.delete_cookie('token')
        logger.info(f"Пользователь {username} удалил аккаунт")
        return resp
    except Exception as e:
        logger.error(f"Ошибка при удалении аккаунта: {str(e)}")
        return "Internal Server Error", 500

@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('token')
    return resp

@app.route("/admin")
@token_required
@admin_required
def admin_panel(current_user):
    users = User.query.filter(User.username != current_user.username).order_by(User.id).all()
    return render_template("admin.html",
                         users=users,
                         current_user=current_user.username,
                         admin=current_user.admin,
                         username=current_user.username)

@app.route("/admin/delete_user/<int:user_id>", methods=["DELETE"])
@token_required
@admin_required
def delete_user(current_user, user_id):
    if current_user.id == user_id:
        return jsonify({"error": "Нельзя удалить самого себя"}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    
    db.session.delete(user)
    db.session.commit()
    logger.info(f"Администратор {current_user.username} удалил пользователя {user.username}")
    return jsonify({"message": "Пользователь удален"}), 200

if __name__ == "__main__":
    port = int(os.getenv('FLASK_PORT', 5000))
    app.run(host=os.getenv('FLASK_HOST', '0.0.0.0'),
           port=port,
           debug=os.getenv('FLASK_DEBUG', 'true').lower() == 'true')
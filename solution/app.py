import re
import secrets
import string
import os
import uuid

import psycopg2
import hashlib
from psycopg2 import Error
from flask import Flask, jsonify, request
from dotenv import load_dotenv
import jwt

from datetime import datetime, timedelta
app = Flask(__name__)
load_dotenv()
# Получение параметров подключения к PostgreSQL из переменных окружения
POSTGRES_CONN = os.getenv('POSTGRES_CONN')

# Установка подключения к базе данных
conn = psycopg2.connect(POSTGRES_CONN)
cursor = conn.cursor()

create_table_query = '''
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    login VARCHAR(30) UNIQUE NOT NULL,
    email VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    country_code VARCHAR(2) NOT NULL,
    is_public BOOLEAN NOT NULL,
    phone VARCHAR(15) UNIQUE,
    image VARCHAR(200)
);
CREATE TABLE IF NOT EXISTS tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS friends (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    friend_login VARCHAR(30) NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT unique_friend UNIQUE (user_id, friend_login)
);
CREATE TABLE IF NOT EXISTS posts (
    id VARCHAR(100) PRIMARY KEY,
    content VARCHAR(1000) NOT NULL,
    author INTEGER REFERENCES users(id) NOT NULL,
    tags VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    likes_count INTEGER DEFAULT 0,
    dislikes_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS post_reactions (
    post_id VARCHAR(100) REFERENCES posts(id) NOT NULL,
    user_id INTEGER REFERENCES users(id) NOT NULL,
    reaction_type VARCHAR(10) CHECK (reaction_type IN ('like', 'dislike')),
    PRIMARY KEY (post_id, user_id)
);
'''

# Выполнение SQL-запроса
cursor.execute(create_table_query)
conn.commit()
cursor.close()
conn.close()

# Обработчик эндпоинта /api/ping
@app.route('/api/ping')
def ping():
    return 'Pong'

# Обработчик эндпоинта /api/countries
@app.route('/api/countries', methods=['GET'])
def get_countries():
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()
    region = request.args.getlist('region')
    if region:
        placeholders = ','.join(['%s' for _ in region])
        query = f"SELECT name, alpha2, alpha3, region FROM countries WHERE region IN ({placeholders}) ORDER BY alpha2"
        cursor.execute(query, region)
    else:
        cursor.execute("SELECT name, alpha2, alpha3, region FROM countries ORDER BY alpha2")
    countries = cursor.fetchall()
    formatted_countries = [{'name': country[0], 'alpha2': country[1], 'alpha3': country[2], 'region': country[3]} for country in countries]
    cursor.close()
    conn.close()
    return jsonify(formatted_countries)

# Обработчик эндпоинта /countries/<alpha2>
@app.route('/api/countries/<alpha2>', methods=['GET'])
def get_country(alpha2):
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()
    cursor.execute("SELECT name, alpha2, alpha3, region FROM countries WHERE alpha2 = %s", (alpha2,))
    country = cursor.fetchone()
    if country:
        formatted_country = {'name': country[0], 'alpha2': country[1], 'alpha3': country[2], 'region': country[3]}
        cursor.close()
        conn.close()
        return jsonify(formatted_country)
    else:
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Country not found'}), 404


@app.route('/api/auth/register', methods=['POST'])
def register():
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()
    data = request.json

    # Проверка наличия всех необходимых данных
    required_fields = ['login', 'email', 'password', 'countryCode', 'isPublic']
    if not all(field in data for field in required_fields):
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Missing required fields'}), 400

    # Проверка уникальности email, login и phone
    cursor.execute("SELECT email FROM users WHERE email = %s", (data['email'],))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Email already exists'}), 409

    cursor.execute("SELECT login FROM users WHERE login = %s", (data['login'],))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Login already exists'}), 409

    if 'phone' in data:
        cursor.execute("SELECT phone FROM users WHERE phone = %s", (data['phone'],))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Phone number already exists'}), 409

    # Проверка пароля
    # if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{6,100}$", data['password']):
    #     cursor.close()
    #     conn.close()
    #     return jsonify({'reason': 'Password does not meet the requirements'}), 400
    if not (
            len(data['password']) >= 6
            and len(data['password']) <= 100
            and any(c.isupper() for c in data['password'])
            and any(c.islower() for c in data['password'])
            and any(c.isdigit() for c in data['password'])
    ):
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Password does not meet the requirements'}), 400
    # Проверка логина верно
    if not re.match(r"^[a-zA-Z0-9-]{1,30}$", data['login']):
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Invalid login format'}), 400

    # Проверка email
    if len(data['email']) > 50:
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Invalid email format'}), 400
    if len(data['email']) < 1:
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Invalid email format'}), 400
    # Проверка кода страны
    cursor.execute("SELECT name FROM countries WHERE alpha2 = %s", (data['countryCode'],))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Invalid country code'}), 400

    # Проверка номера телефона
    if len(data['phone']) > 20:
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Invalid phone number format'}), 400
    if len(data['phone']) < 1:
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Invalid phone number format'}), 400
    # Проверка длины ссылки на изображение
    if 'image' in data:
        if len(data['image']) > 200:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Image URL exceeds the maximum length'}), 400
        if len(data['image']) < 1:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Image URL is too short'}), 400

    # Хеширование пароля
    hashed_password = hashlib.sha256(data['password'].encode('utf-8')).hexdigest()
    # Вставка данных в базу
    try:
        cursor.execute("INSERT INTO users (login, email, password, country_code, is_public, phone, image) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                       (data['login'], data['email'], hashed_password, data['countryCode'], data['isPublic'], data.get('phone'), data.get('image')))
        conn.commit()
        user_id = cursor.fetchone()[0]
    except psycopg2.Error as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Database reason', 'details': str(e)}), 400

    # Формирование ответа
    profile_data = {
        'login': data['login'],
        'email': data['email'],
        'countryCode': data['countryCode'],
        'isPublic': data['isPublic']
    }
    if 'phone' in data:
        profile_data['phone'] = data['phone']
    if 'image' in data:
        profile_data['image'] = data['image']

    cursor.close()
    conn.close()
    return jsonify({'profile': profile_data}), 201



@app.route('/api/auth/sign-in', methods=['POST'])
def sign_in():
    try:
        conn = psycopg2.connect(POSTGRES_CONN)
        cursor = conn.cursor()
        data = request.json

        # Поиск пользователя по логину
        cursor.execute("SELECT id, password FROM users WHERE login = %s", (data['login'],))
        user = cursor.fetchone()

        if user:

            user_id, hashed_password_from_db = user

            entered_password_hash = hashlib.sha256(data['password'].encode('utf-8')).hexdigest()

            # Сравнение хешей паролей
            try:
                if entered_password_hash == hashed_password_from_db:

                    JWT_SECRET_LENGTH = 40
                    token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(JWT_SECRET_LENGTH))

                    # Сохранение токена в базе данных (если это требуется вашим приложением)

                    cursor.execute("INSERT INTO tokens (user_id, token) VALUES (%s, %s)", (user_id, token))
                    conn.commit()

                    cursor.close()
                    conn.close()
                    return jsonify({'token': token}), 200
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({'reason': 'Пользователь с указанным логином и паролем не найден'}), 401
            except:
                cursor.close()
                conn.close()
                return jsonify({'reason': 'Внутренняя ошибка сервера'}), 504


        else:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Пользователь с указанным логином и паролем не найден'}), 401
    except Error as e:
        # Логирование ошибок
        print("Ошибка базы данных:", e)

        return jsonify({'reason': 'Ошибка базы данных'}), 501
    except Exception as e:
        # Обработка других исключений
        print("Ошибка:", e)
        return jsonify({'reason': 'Внутренняя ошибка сервера'}), 502

@app.route('/api/me/profile', methods=['GET', 'PATCH'])
def me_profile():
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()
    if request.method == 'GET':
        # Получение профиля
        token = request.headers.get('Authorization')
        if token:
            token = token.split('Bearer ')[1]

            cursor.execute("SELECT user_id, created_at FROM tokens WHERE token = %s", (token,))
            user_data = cursor.fetchone()
            if user_data:
                user_id, created_at = user_data
                if is_token_valid(created_at):
                    cursor.execute("SELECT login, email, country_code, is_public, phone, image FROM users WHERE id = %s", (user_id,))
                    user_data = cursor.fetchone()

                    if user_data:
                        profile = {
                            'login': user_data[0],
                            'email': user_data[1],
                            'countryCode': user_data[2],
                            'isPublic': user_data[3],
                            'phone': user_data[4],
                            'image': user_data[5]
                        }
                        cursor.close()
                        conn.close()
                        return jsonify(profile), 200
                    else:
                        cursor.close()
                        conn.close()
                        return jsonify({'reason': 'User not found'}), 406
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({'reason': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                return jsonify({'reason': 'Invalid token'}), 401
        else:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Token is missing'}), 401
    elif request.method == 'PATCH':
        # Обновление профиля
        token = request.headers.get('Authorization')
        if token:
            token = token.split('Bearer ')[1]

            cursor.execute("SELECT user_id, created_at FROM tokens WHERE token = %s", (token,))
            user_data = cursor.fetchone()
            if user_data:
                user_id, created_at = user_data
                if is_token_valid(created_at):

                    data = request.json
                    # Проверяем, переданы ли данные для обновления
                    if data:
                        # Генерируем SET выражение
                        set_expr = ','.join([f"{field} = '{data[field]}'" for field in data])
                        query = f"UPDATE users SET {set_expr} WHERE id = %s RETURNING login, email, country_code, is_public, phone, image"
                        cursor.execute(query, (user_id,))
                        updated_user_data = cursor.fetchone()
                        if updated_user_data:
                            updated_profile = {
                                'login': updated_user_data[0],
                                'email': updated_user_data[1],
                                'countryCode': updated_user_data[2],
                                'isPublic': updated_user_data[3],
                                'phone': updated_user_data[4],
                                'image': updated_user_data[5],
                            }
                            conn.commit()

                            cursor.close()
                            conn.close()
                            return jsonify(updated_profile), 200
                        else:
                            cursor.close()
                            conn.close()
                            return jsonify({'reason': 'User not found'}), 405
                    else:
                        cursor.close()
                        conn.close()
                        return jsonify({'reason': 'No data provided'}), 400
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({'reason': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                return jsonify({'reason': 'Invalid token'}), 401
        else:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Token is missing'}), 401

@app.route('/api/profiles/<login>', methods=['GET'])
def get_profile(login):
    try:
        # Получение токена из заголовка Authorization
        token = request.headers.get('Authorization')

        if token:
            # Извлечение токена из строки "Bearer {token}"
            token = token.split('Bearer ')[1]

            # Подключение к базе данных
            conn = psycopg2.connect(POSTGRES_CONN)
            cursor = conn.cursor()

            # Получение идентификатора пользователя по токену
            cursor.execute("SELECT user_id, created_at FROM tokens WHERE token = %s", (token,))
            user_data = cursor.fetchone()
            if user_data:
                user_id, created_at = user_data
                if is_token_valid(created_at):




                    # Проверка наличия профиля пользователя
                    cursor.execute("SELECT login, email, country_code, is_public, phone, image, id FROM users WHERE login = %s",
                                   (login,))
                    user_data = cursor.fetchone()

                    cursor.execute(
                        "SELECT login, email, country_code, is_public, phone, image, id FROM users WHERE id = %s",
                        (user_id,))
                    user_data2 = cursor.fetchone()
                    if user_data:
                        profile = {
                            'login': user_data[0],
                            'email': user_data[1],
                            'countryCode': user_data[2],
                            'isPublic': user_data[3],
                            'phone': user_data[4],
                            'image': user_data[5]
                        }

                        # Проверка настройки приватности профиля
                        if user_data[3] or user_id == user_data[6]:  # Если профиль публичен
                            cursor.close()
                            conn.close()
                            return jsonify(profile), 200
                        else:
                            # Проверка доступа к закрытому профилю
                            cursor.execute("SELECT 1 FROM friends WHERE user_id = %s AND friend_login = %s",
                                           (user_data[6], user_data2[0]))
                            friend = cursor.fetchone()
                            if friend:
                                cursor.close()
                                conn.close()
                                return jsonify(profile), 200
                            else:
                                cursor.close()
                                conn.close()
                                return jsonify({'reason': 'Access denied. Profile is private.'}), 403
                    else:
                        cursor.close()
                        conn.close()
                        return jsonify({'reason': 'User not found'}), 404
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({'reason': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                # Некорректный токен
                return jsonify({'reason': 'Invalid token'}), 401
        else:
            # Токен отсутствует
            return jsonify({'reason': 'Token is missing'}), 401
    except psycopg2.Error as e:
        print("Database reason:", e)
        return jsonify({'reason': 'Database reason'}), 500
    except Exception as e:
        print("Error:", e)
        return jsonify({'reason': 'Internal server reason'}), 500

def get_user_login_by_id(user_id):
    # Подключение к базе данных
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()

    # Выполнение SQL-запроса для получения логина по заданному идентификатору пользователя
    cursor.execute("SELECT login FROM users WHERE id = %s", (user_id,))
    login = cursor.fetchone()

    # Закрытие курсора и соединения
    cursor.close()
    conn.close()

    # Возврат логина, если он найден, в противном случае возврат None
    return login[0] if login else None
def is_friend(user_id, friend_login):
    # Подключение к базе данных
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()

    # Выполнение SQL-запроса для проверки, является ли пользователь другом текущего пользователя
    cursor.execute("SELECT EXISTS(SELECT 1 FROM friends WHERE user_id = %s AND friend_login = %s)", (user_id, friend_login))

    is_friend = cursor.fetchone()[0]

    # Закрытие курсора и соединения
    cursor.close()
    conn.close()

    # Возврат результата проверки
    return is_friend

def is_user_exist(login):
    # Подключение к базе данных
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()

    # Выполнение SQL-запроса для проверки существования пользователя с заданным логином
    cursor.execute("SELECT EXISTS(SELECT 1 FROM users WHERE login = %s)", (login,))
    user_exists = cursor.fetchone()[0]

    # Закрытие курсора и соединения
    cursor.close()
    conn.close()

    # Возврат результата проверки
    return user_exists

@app.route('/api/friends/add', methods=['POST'])
def add_friend():
    try:
        conn = psycopg2.connect(POSTGRES_CONN)
        cursor = conn.cursor()

        # Получение логина текущего пользователя по токену
        token = request.headers.get('Authorization')
        if token:
            token = token.split('Bearer ')[1]
            cursor.execute("SELECT user_id, created_at FROM tokens WHERE token = %s", (token,))
            user_data = cursor.fetchone()
            if user_data:
                user_id, created_at = user_data
                if is_token_valid(created_at):

                    data = request.json
                    friend_login = data.get('login')

                    # Проверка, что пользователь не добавляет сам себя в друзья
                    if friend_login == get_user_login_by_id(user_id):
                        cursor.close()
                        conn.close()
                        return jsonify({'status': 'ok'}), 200

                    # Проверка, что пользователь с таким логином существует
                    if not is_user_exist(friend_login):
                        cursor.close()
                        conn.close()
                        return jsonify({'reason': 'User not found'}), 404

                    # Проверка, что пользователь уже не является другом
                    if is_friend(user_id, friend_login):
                        cursor.close()
                        conn.close()
                        return jsonify({'status': 'ok'}), 200

                    # Добавление друга
                    cursor.execute("INSERT INTO friends (user_id, friend_login, added_at) VALUES (%s, %s, NOW())", (user_id, friend_login))
                    conn.commit()

                    cursor.close()
                    conn.close()
                    return jsonify({'status': 'ok'}), 200
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({'reason': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                return jsonify({'reason': 'Invalid token'}), 401
        else:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Token is missing'}), 401
    except psycopg2.Error as e:
        print("Database reason:", e)
        return jsonify({'reason': 'Database reason'}), 500
    except Exception as e:
        print("Error:", e)
        return jsonify({'reason': 'Internal server reason'}), 500

# Эндпоинт для удаления пользователя из друзей
@app.route('/api/friends/remove', methods=['POST'])
def remove_friend():
    try:
        conn = psycopg2.connect(POSTGRES_CONN)
        cursor = conn.cursor()

        # Получение логина текущего пользователя по токену
        token = request.headers.get('Authorization')
        if token:
            token = token.split('Bearer ')[1]
            cursor.execute("SELECT user_id, created_at FROM tokens WHERE token = %s", (token,))
            user_data = cursor.fetchone()
            if user_data:
                user_id, created_at = user_data
                if is_token_valid(created_at):
                    data = request.json
                    friend_login = data.get('login')

                    # Удаление друга
                    cursor.execute("DELETE FROM friends WHERE user_id = %s AND friend_login = %s", (user_id, friend_login))
                    conn.commit()

                    cursor.close()
                    conn.close()
                    return jsonify({'status': 'ok'}), 200
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({'reason': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                return jsonify({'reason': 'Invalid token'}), 401
        else:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Token is missing'}), 401
    except psycopg2.Error as e:
        print("Database reason:", e)
        return jsonify({'reason': 'Database reason'}), 500
    except Exception as e:
        print("Error:", e)
        return jsonify({'reason': 'Internal server reason'}), 500

def is_token_valid(token_created_at):
    current_time = datetime.now()
    token_expiration_time = token_created_at + timedelta(hours=1)
    return current_time <= token_expiration_time
# Эндпоинт для получения списка друзей
@app.route('/api/friends', methods=['GET'])
def get_friends():
    try:
        conn = psycopg2.connect(POSTGRES_CONN)
        cursor = conn.cursor()

        # Получение логина текущего пользователя по токену
        token = request.headers.get('Authorization')
        if token:
            token = token.split('Bearer ')[1]
            cursor.execute("SELECT user_id, created_at FROM tokens WHERE token = %s", (token,))
            user_data = cursor.fetchone()
            if user_data:
                user_id, created_at = user_data
                if is_token_valid(created_at):


                    # Получение параметров пагинации
                    limit = request.args.get('limit', default=5, type=int)
                    if limit is not None:
                        if not 0 < limit <= 50:
                            return jsonify({'reason': 'Invalid limit value, must be between 1 and 50'}), 400

                    offset = request.args.get('offset', default=0, type=int)
                    if offset is not None:
                        if offset < 0:
                            return jsonify({'reason': 'Invalid offset value, must be non-negative'}), 400
                    # Получение списка друзей с учетом пагинации
                    cursor.execute("SELECT friend_login, added_at FROM friends WHERE user_id = %s ORDER BY added_at DESC LIMIT %s OFFSET %s", (user_id, limit, offset))
                    friends_data = cursor.fetchall()

                    friends_list = []
                    for friend_data in friends_data:
                        friend_login, added_at = friend_data
                        friends_list.append({'login': friend_login, 'addedAt': added_at.strftime('%Y-%m-%dT%H:%M:%SZ')})

                    cursor.close()
                    conn.close()
                    return jsonify(friends_list), 200
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({'reason': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                return jsonify({'reason': 'Invalid token'}), 401
        else:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Token is missing'}), 401
    except psycopg2.Error as e:
        print("Database reason:", e)
        return jsonify({'reason': 'Database reason'}), 500
    except Exception as e:
        print("Error:", e)
        return jsonify({'reason': 'Internal server reason'}), 500

def hash_password_sha256(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


@app.route('/api/me/updatePassword', methods=['POST'])
def update_password():
    try:
        # Получение токена из заголовка Authorization
        token = request.headers.get('Authorization')
        if token:
            token = token.split('Bearer ')[1]

            # Получение данных пользователя по токену
            conn = psycopg2.connect(POSTGRES_CONN)
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, created_at FROM tokens WHERE token = %s", (token,))
            user_data = cursor.fetchone()

            if user_data:
                user_id, created_at = user_data
                if is_token_valid(created_at):
                    # Получение пароля пользователя из таблицы users
                    cursor.execute("SELECT password FROM users WHERE id = %s", (user_id,))
                    password_hash = cursor.fetchone()[0]  # Получаем хэш пароля из результатов запроса

                    # Получение старого и нового паролей из тела запроса
                    data = request.json
                    old_password = data.get('oldPassword')
                    new_password = data.get('newPassword')

                    # Проверка соответствия старого пароля
                    if hash_password_sha256(old_password) == password_hash:
                        # Проверка нового пароля на соответствие требованиям
                        if (
                            len(new_password) >= 6
                            and len(new_password) <= 100
                            and any(c.isupper() for c in new_password)
                            and any(c.islower() for c in new_password)
                            and any(c.isdigit() for c in new_password)
                        ):
                            # Хеширование нового пароля
                            new_password_hash = hash_password_sha256(new_password)

                            # Обновление пароля в базе данных
                            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (new_password_hash, user_id))

                            # Отзыв всех ранее выпущенных токенов
                            cursor.execute("DELETE FROM tokens WHERE user_id = %s", (user_id,))

                            conn.commit()
                            cursor.close()
                            conn.close()

                            return jsonify({'status': 'ok'}), 200
                        else:
                            cursor.close()
                            conn.close()
                            return jsonify({'reason': 'New password does not meet the requirements'}), 400
                    else:
                        cursor.close()
                        conn.close()
                        return jsonify({'reason': 'Invalid old password'}), 403
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({'reason': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                return jsonify({'reason': 'Invalid token'}), 401
        else:
            return jsonify({'reason': 'Token is missing'}), 401
    except psycopg2.Error as e:
        print("Database reason:", e)
        return jsonify({'reason': 'Database reason'}), 500
    except Exception as e:
        print("Error:", e)
        return jsonify({'reason': 'Internal server reason'}), 500


# Функция для подключения к базе данных
def connect_to_database():
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()
    return conn, cursor

# Функция для выполнения запроса на вставку нового поста
def insert_post_to_database(post_id, content, author_id, tags):
    import datetime
    conn, cursor = connect_to_database()
    cursor.execute(
        "INSERT INTO posts (id, content, author, tags, created_at) VALUES (%s, %s, %s, %s, %s)",
        (post_id, content, author_id, tags, datetime.datetime.utcnow())
    )
    conn.commit()
    cursor.close()
    conn.close()

@app.route('/api/posts/new', methods=['POST'])
def submit_post():
    import datetime
    # Проверяем наличие заголовка Authorization
    if 'Authorization' not in request.headers:
        return jsonify({'reason': 'Missing Authorization header'}), 401

    # Получаем токен из заголовка Authorization
    auth_header = request.headers['Authorization']
    token = auth_header.split(' ')[1]  # Получаем только сам токен, убирая 'Bearer '

    # Подключаемся к базе данных
    conn, cursor = connect_to_database()
    cursor.execute("SELECT user_id, created_at FROM tokens WHERE token = %s", (token,))
    user_data = cursor.fetchone()

    if user_data:
        user_id, created_at = user_data
        if is_token_valid(created_at):

            # Получаем данные из тела запроса
            post_data = request.json
            content = post_data.get('content')
            tags = post_data.get('tags')

            # Генерируем уникальный идентификатор публикации
            post_id = str(uuid.uuid4())

            # Сохраняем пост в базу данных
            insert_post_to_database(post_id, content, user_id, tags)

            # Создаем объект публикации для возврата клиенту
            new_post = {
                'id': post_id,
                'content': content,
                'tags': tags,
                'created_at': datetime.datetime.utcnow().isoformat(),
                'likesCount': 0,
                'dislikesCount': 0
            }

            # Закрываем соединение с базой данных
            cursor.close()
            conn.close()

            # Возвращаем информацию о созданной публикации
            return jsonify(new_post), 200
        else:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Token expired'}), 401
    else:
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Invalid token'}), 401



# Функция для получения публикации по её идентификатору
@app.route('/api/posts/<post_id>', methods=['GET'])
def get_post_by_id(post_id):
    # Проверяем наличие заголовка Authorization
    if 'Authorization' not in request.headers:
        return jsonify({'reason': 'Missing Authorization header'}), 401

    # Получаем токен из заголовка Authorization
    auth_header = request.headers['Authorization']
    token = auth_header.split(' ')[1]  # Получаем только сам токен, убирая 'Bearer '

    # Подключаемся к базе данных
    conn, cursor = connect_to_database()
    cursor.execute("SELECT user_id, created_at FROM tokens WHERE token = %s", (token,))
    user_data = cursor.fetchone()


    if user_data:
        user_id, created_at = user_data
        if is_token_valid(created_at):



            # Запрос к базе данных для получения информации о посте по его ID
            cursor.execute(
                "SELECT id, content, author, tags, created_at, likes_count, dislikes_count FROM posts WHERE id = %s",
                (post_id,)
            )
            post_data = cursor.fetchone()


            cursor.execute("SELECT login, email, country_code, is_public, phone, image FROM users WHERE id = %s",
                           (user_id,))
            user_account2 = cursor.fetchone()
            if post_data:
                cursor.execute("SELECT login, email, country_code, is_public, phone, image FROM users WHERE id = %s",
                               (post_data[2],))
                user_account = cursor.fetchone()
                post = {
                    'id': post_data[0],
                    'content': post_data[1],
                    'author_id': post_data[2],
                    'tags': post_data[3],
                    'created_at': post_data[4].isoformat(),
                    'likesCount': post_data[5],
                    'dislikesCount': post_data[6]
                }
                if user_account[3] or user_id == post_data[2]:  # Если профиль публичен
                    cursor.close()
                    conn.close()
                    return jsonify(post), 200
                else:
                    # Проверка доступа к закрытому профилю

                    cursor.execute("SELECT 1 FROM friends WHERE user_id = %s AND friend_login = %s",
                                   (post_data[2], user_account2[0]))
                    friend = cursor.fetchone()
                    if friend:
                        cursor.close()
                        conn.close()
                        return jsonify(post), 200
                    else:
                        cursor.close()
                        conn.close()
                        return jsonify({'reason': 'Access denied. Post is private.'}), 403
            else:
                cursor.close()
                conn.close()
                return jsonify({'reason': 'Post not found'}), 404
        else:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Token expired'}), 401
    else:
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Invalid token'}), 401

def get_user_posts(user_id, limit, offset):
    conn, cursor = connect_to_database()
    cursor.execute(
        "SELECT id, content, tags, created_at, likes_count, dislikes_count FROM posts WHERE author = %s ORDER BY created_at DESC LIMIT %s OFFSET %s",
        (user_id, limit, offset)
    )
    posts = []
    for row in cursor.fetchall():
        post = {
            'id': row[0],
            'content': row[1],
            'tags': row[2].split(',') if row[2] else [],  # Преобразуем строку с тегами в список
            'created_at': row[3].isoformat(),  # Преобразуем дату в строку в формате ISO
            'likesCount': row[4],
            'dislikesCount': row[5]
        }
        posts.append(post)
    cursor.close()
    conn.close()
    return posts
@app.route('/api/posts/feed/my', methods=['GET'])
def get_my_feed():
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()
    # Проверяем наличие заголовка Authorization
    if 'Authorization' not in request.headers:
        return jsonify({'reason': 'Missing Authorization header'}), 401

    # Получаем токен из заголовка Authorization
    auth_header = request.headers['Authorization']
    token = auth_header.split(' ')[1]  # Получаем только сам токен, убирая 'Bearer '

    # Получаем данные пользователя из базы данных
    cursor.execute("SELECT user_id, created_at FROM tokens WHERE token = %s", (token,))
    user_data = cursor.fetchone()

    if user_data:
        user_id, created_at = user_data
        if is_token_valid(created_at):
            if not user_id:
                cursor.close()
                conn.close()
                return jsonify({'reason': 'Invalid token'}), 401

            # Получаем параметры пагинации
            limit = request.args.get('limit', default=5, type=int)
            if limit is not None:
                if not 0 < limit <= 50:
                    return jsonify({'reason': 'Invalid limit value, must be between 1 and 50'}), 400

            offset = request.args.get('offset', default=0, type=int)
            if offset is not None:
                if offset < 0:
                    return jsonify({'reason': 'Invalid offset value, must be non-negative'}), 400

            # Получаем посты пользователя с пагинацией
            posts = get_user_posts(user_id, limit, offset)
            cursor.close()
            conn.close()
            return jsonify(posts), 200
        else:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Token expired'}), 401
    else:
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Invalid token'}), 401

def get_user_id_from_token(token):
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()

    cursor.execute("SELECT user_id, created_at FROM tokens WHERE token = %s", (token,))
    user_data = cursor.fetchone()
    if user_data:
        user_id, created_at = user_data
        if is_token_valid(created_at):
            user_id = cursor.fetchone()
            cursor.close()
            conn.close()
            return user_id[0] if user_id else None
        else:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Token expired'}), 401
    else:
        cursor.close()
        conn.close()
        return jsonify({'reason': 'Invalid token'}), 401


def get_user_by_login(login):
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE login = %s", (login,))
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()
    return user_data

def can_access_user_posts(user_id, target_user):
    # Проверяем, является ли профиль пользователя открытым или пользователь - владелец постов
    if target_user[5]==True or user_id == target_user[0]:
        return True

    # Проверяем, есть ли пользователь в списке друзей у владельца постов
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()

    cursor.execute("SELECT login, email, country_code, is_public, phone, image FROM users WHERE id = %s",
                   (user_id,))
    user_account = cursor.fetchone()


    cursor.execute("SELECT 1 FROM friends WHERE user_id = %s AND friend_login = %s",
                   (target_user[0], user_account[0],))
    friend = cursor.fetchone()
    cursor.close()
    conn.close()

    return friend is not None

def get_user_posts(user_id, limit, offset):
    conn = psycopg2.connect(POSTGRES_CONN)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts WHERE author = %s ORDER BY created_at DESC LIMIT %s OFFSET %s", (user_id, limit, offset,))
    posts = cursor.fetchall()
    cursor.close()
    conn.close()
    return posts
@app.route('/api/posts/feed/<login>', methods=['GET'])
def get_user_feed(login):
    # Проверяем наличие заголовка Authorization
    if 'Authorization' not in request.headers:
        return jsonify({'reason': 'Missing Authorization header'}), 401

    # Получаем токен из заголовка Authorization
    auth_header = request.headers['Authorization']
    token = auth_header.split(' ')[1]  # Получаем только сам токен, убирая 'Bearer '

    # Получаем данные пользователя из базы данных
    user_id = get_user_id_from_token(token)
    if not user_id:
        return jsonify({'reason': 'Invalid token'}), 401

    # Получаем данные о пользователе, чьи посты запрашиваются
    target_user = get_user_by_login(login)
    if not target_user:
        return jsonify({'reason': 'User not found'}), 404

    # Проверяем доступ к постам запрашиваемого пользователя
    if not can_access_user_posts(user_id, target_user):
        return jsonify({'reason': 'Access denied'}), 403

    # Получаем параметры пагинации
    limit = request.args.get('limit', default=5, type=int)
    if limit is not None:
        if not 0 < limit <= 50:
            return jsonify({'reason': 'Invalid limit value, must be between 1 and 50'}), 400

    offset = request.args.get('offset', default=0, type=int)
    if offset is not None:
        if offset < 0:
            return jsonify({'reason': 'Invalid offset value, must be non-negative'}), 400

    # Получаем посты запрашиваемого пользователя с пагинацией
    posts = get_user_posts(target_user[0], limit, offset)

    return jsonify(posts), 200


@app.route('/api/posts/<postId>/like', methods=['POST'])
def like_post(postId):
    try:
        conn = psycopg2.connect(POSTGRES_CONN)
        cursor = conn.cursor()

        # Получение ID пользователя из токена
        user_id = get_user_id_from_token(request.headers.get('Authorization'))
        if not user_id:
            return jsonify({'reason': 'Invalid token'}), 401

        # Проверка существования поста и доступа к нему
        cursor.execute("SELECT * FROM posts WHERE id = %s", (postId,))
        post = cursor.fetchone()
        if not post:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Post not found'}), 404
        if post[2] == user_id:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Cannot react to own post'}), 403

        # Проверка, не ставил ли пользователь уже лайк к этому посту
        cursor.execute("SELECT * FROM post_reactions WHERE post_id = %s AND user_id = %s", (postId, user_id))
        existing_reaction = cursor.fetchone()
        if existing_reaction:
            if existing_reaction[2] == 'like':
                # Если пользователь уже поставил лайк, то ничего не меняем
                cursor.close()
                conn.close()
                return jsonify({'reason': 'Already liked'}), 200
            else:
                # Если пользователь поставил дизлайк, то заменяем его на лайк
                cursor.execute("UPDATE post_reactions SET reaction_type = 'like' WHERE post_id = %s AND user_id = %s", (postId, user_id))
                cursor.execute("UPDATE posts SET likes_count = likes_count + 1, dislikes_count = dislikes_count - 1 WHERE id = %s", (postId,))
        else:
            # Если пользователь еще не реагировал на пост, то добавляем его лайк
            cursor.execute("INSERT INTO post_reactions (post_id, user_id, reaction_type) VALUES (%s, %s, 'like')", (postId, user_id))
            cursor.execute("UPDATE posts SET likes_count = likes_count + 1 WHERE id = %s", (postId,))

        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True}), 200

    except psycopg2.Error as e:
        print("Database error:", e)
        return jsonify({'reason': 'Database error'}), 500
    except Exception as e:
        print("Error:", e)
        return jsonify({'reason': 'Internal server error'}), 500


# Функция для обработки дизлайка поста
@app.route('/api/posts/<postId>/dislike', methods=['POST'])
def dislike_post(postId):
    try:
        conn = psycopg2.connect(POSTGRES_CONN)
        cursor = conn.cursor()

        # Получение ID пользователя из токена
        user_id = get_user_id_from_token(request.headers.get('Authorization'))
        if not user_id:
            return jsonify({'reason': 'Invalid token'}), 401

        # Проверка существования поста и доступа к нему
        cursor.execute("SELECT * FROM posts WHERE id = %s", (postId,))
        post = cursor.fetchone()
        if not post:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Post not found'}), 404
        if post[2] == user_id:
            cursor.close()
            conn.close()
            return jsonify({'reason': 'Cannot react to own post'}), 403

        # Проверка, не ставил ли пользователь уже дизлайк к этому посту
        cursor.execute("SELECT * FROM post_reactions WHERE post_id = %s AND user_id = %s", (postId, user_id))
        existing_reaction = cursor.fetchone()
        if existing_reaction:
            if existing_reaction[2] == 'dislike':
                # Если пользователь уже поставил дизлайк, то ничего не меняем
                cursor.close()
                conn.close()
                return jsonify({'reason': 'Already disliked'}), 200
            else:
                # Если пользователь поставил лайк, то заменяем его на дизлайк
                cursor.execute("UPDATE post_reactions SET reaction_type = 'dislike' WHERE post_id = %s AND user_id = %s", (postId, user_id))
                cursor.execute("UPDATE posts SET dislikes_count = dislikes_count + 1, likes_count = likes_count - 1 WHERE id = %s", (postId,))
        else:
            # Если пользователь еще не реагировал на пост, то добавляем его дизлайк
            cursor.execute("INSERT INTO post_reactions (post_id, user_id, reaction_type) VALUES (%s, %s, 'dislike')", (postId, user_id))
            cursor.execute("UPDATE posts SET dislikes_count = dislikes_count + 1 WHERE id = %s", (postId,))

        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True}), 200

    except psycopg2.Error as e:
        print("Database error:", e)
        return jsonify({'reason': 'Database error'}), 500
    except Exception as e:
        print("Error:", e)
        return jsonify({'reason': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True)

import secrets
import string
import os
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
        return jsonify({'error': 'Country not found'}), 404


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
        return jsonify({'error': 'Missing required fields'}), 400

    # Проверка уникальности email, login и phone
    cursor.execute("SELECT email FROM users WHERE email = %s", (data['email'],))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({'error': 'Email already exists'}), 409

    cursor.execute("SELECT login FROM users WHERE login = %s", (data['login'],))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({'error': 'Login already exists'}), 409

    if 'phone' in data:
        cursor.execute("SELECT phone FROM users WHERE phone = %s", (data['phone'],))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Phone number already exists'}), 409

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
        return jsonify({'error': 'Database error', 'details': str(e)}), 400

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
                    return jsonify({'error': 'Пользователь с указанным логином и паролем не найден'}), 401
            except:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Внутренняя ошибка сервера'}), 504


        else:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Пользователь с указанным логином и паролем не найден'}), 401
    except Error as e:
        # Логирование ошибок
        print("Ошибка базы данных:", e)

        return jsonify({'error': 'Ошибка базы данных'}), 501
    except Exception as e:
        # Обработка других исключений
        print("Ошибка:", e)
        return jsonify({'error': 'Внутренняя ошибка сервера'}), 502

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
                        return jsonify({'error': 'User not found'}), 406
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({'error': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Invalid token'}), 401
        else:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Token is missing'}), 401
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
                            return jsonify({'error': 'User not found'}), 405
                    else:
                        cursor.close()
                        conn.close()
                        return jsonify({'error': 'No data provided'}), 400
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({'error': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Invalid token'}), 401
        else:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Token is missing'}), 401

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
                    cursor.execute("SELECT login, email, country_code, is_public, phone, image FROM users WHERE login = %s",
                                   (login,))
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

                        # Проверка настройки приватности профиля
                        if user_data[3]:  # Если профиль публичен
                            cursor.close()
                            conn.close()
                            return jsonify(profile), 200
                        else:
                            # Проверка доступа к закрытому профилю
                            cursor.execute("SELECT 1 FROM friends WHERE user_id = %s AND friend_login = %s",
                                           (user_id, user_data[0]))
                            friend = cursor.fetchone()
                            if friend:
                                cursor.close()
                                conn.close()
                                return jsonify(profile), 200
                            else:
                                cursor.close()
                                conn.close()
                                return jsonify({'error': 'Access denied. Profile is private.'}), 403
                    else:
                        cursor.close()
                        conn.close()
                        return jsonify({'error': 'User not found'}), 404
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({'error': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                # Некорректный токен
                return jsonify({'error': 'Invalid token'}), 401
        else:
            # Токен отсутствует
            return jsonify({'error': 'Token is missing'}), 401
    except psycopg2.Error as e:
        print("Database error:", e)
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        print("Error:", e)
        return jsonify({'error': 'Internal server error'}), 500

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
                        return jsonify({'error': 'User not found'}), 404

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
                    return jsonify({'error': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Invalid token'}), 401
        else:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Token is missing'}), 401
    except psycopg2.Error as e:
        print("Database error:", e)
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        print("Error:", e)
        return jsonify({'error': 'Internal server error'}), 500

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
                    return jsonify({'error': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Invalid token'}), 401
        else:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Token is missing'}), 401
    except psycopg2.Error as e:
        print("Database error:", e)
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        print("Error:", e)
        return jsonify({'error': 'Internal server error'}), 500

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
                    limit = request.args.get('limit', default=10, type=int)
                    offset = request.args.get('offset', default=0, type=int)

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
                    return jsonify({'error': 'Token expired'}), 401
            else:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Invalid token'}), 401
        else:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Token is missing'}), 401
    except psycopg2.Error as e:
        print("Database error:", e)
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        print("Error:", e)
        return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True)

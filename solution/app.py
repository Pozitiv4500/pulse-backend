import base64
import os
import psycopg2
import hashlib
from bcrypt import checkpw
from bcrypt import hashpw, gensalt
from flask import Flask, jsonify, request
from dotenv import load_dotenv
import jwt
from datetime import datetime, timedelta
app = Flask(__name__)
load_dotenv()
# Получение параметров подключения к PostgreSQL из переменных окружения
POSTGRES_CONN = os.getenv('POSTGRES_CONN')
JWT_SECRET = os.getenv('JWT_SECRET')
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
        if entered_password_hash == hashed_password_from_db:
            JWT_ALGORITHM = 'HS256'
            JWT_EXPIRATION_DELTA = timedelta(hours=1)


            # Подготовка данных для токена
            payload = {
                'sub': user_id,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + JWT_EXPIRATION_DELTA
            }

            # Генерация токена
            token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

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
    else:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Пользователь с указанным логином и паролем не найден'}), 401

if __name__ == '__main__':
    app.run(debug=True)

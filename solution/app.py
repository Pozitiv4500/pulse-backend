import os
import psycopg2
from bcrypt import hashpw, gensalt
from flask import Flask, jsonify, request
from dotenv import load_dotenv
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
'''

# Выполнение SQL-запроса
cursor.execute(create_table_query)
conn.commit()
# Обработчик эндпоинта /api/ping
@app.route('/api/ping')
def ping():
    return 'Pong'

# Обработчик эндпоинта /api/countries
@app.route('/api/countries', methods=['GET'])
def get_countries():
    region = request.args.getlist('region')
    if region:
        placeholders = ','.join(['%s' for _ in region])
        query = f"SELECT name, alpha2, alpha3, region FROM countries WHERE region IN ({placeholders}) ORDER BY alpha2"
        cursor.execute(query, region)
    else:
        cursor.execute("SELECT name, alpha2, alpha3, region FROM countries")
    countries = cursor.fetchall()
    formatted_countries = [{'name': country[0], 'alpha2': country[1], 'alpha3': country[2], 'region': country[3]} for country in countries]
    return jsonify(formatted_countries)

# Обработчик эндпоинта /countries/<alpha2>
@app.route('/api/countries/<alpha2>', methods=['GET'])
def get_country(alpha2):
    cursor.execute("SELECT name, alpha2, alpha3, region FROM countries WHERE alpha2 = %s", (alpha2,))
    country = cursor.fetchone()
    if country:
        formatted_country = {'name': country[0], 'alpha2': country[1], 'alpha3': country[2], 'region': country[3]}
        return jsonify(formatted_country)
    else:
        return jsonify({'error': 'Country not found'}), 404


@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json

    # Проверка наличия всех необходимых данных
    required_fields = ['login', 'email', 'password', 'countryCode', 'isPublic']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Проверка уникальности email, login и phone
    cursor.execute("SELECT email FROM users WHERE email = %s", (data['email'],))
    if cursor.fetchone():
        return jsonify({'error': 'Email already exists'}), 409

    cursor.execute("SELECT login FROM users WHERE login = %s", (data['login'],))
    if cursor.fetchone():
        return jsonify({'error': 'Login already exists'}), 409

    if 'phone' in data:
        cursor.execute("SELECT phone FROM users WHERE phone = %s", (data['phone'],))
        if cursor.fetchone():
            return jsonify({'error': 'Phone number already exists'}), 409

    # Хеширование пароля
    hashed_password = hashpw(data['password'].encode('utf-8'), gensalt())

    # Вставка данных в базу
    try:
        cursor.execute("INSERT INTO users (login, email, password, country_code, is_public, phone, image) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                       (data['login'], data['email'], hashed_password, data['countryCode'], data['isPublic'], data.get('phone'), data.get('image')))
        conn.commit()
        user_id = cursor.fetchone()[0]
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify({'error': 'Database error', 'details': str(e)}), 400

    return jsonify({'profile': {'id': user_id, 'login': data['login'], 'email': data['email'], 'countryCode': data['countryCode'], 'isPublic': data['isPublic']}}), 201

if __name__ == '__main__':
    app.run(debug=True)

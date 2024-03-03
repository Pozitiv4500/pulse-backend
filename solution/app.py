import os
import psycopg2
from flask import Flask, jsonify, request
from dotenv import load_dotenv
app = Flask(__name__)
load_dotenv()
# Получение параметров подключения к PostgreSQL из переменных окружения
POSTGRES_CONN = os.getenv('POSTGRES_CONN')

# Установка подключения к базе данных
conn = psycopg2.connect(POSTGRES_CONN)
cursor = conn.cursor()

# Обработчик эндпоинта /api/ping
@app.route('/api/ping')
def ping():
    return 'Pong'

# Обработчик эндпоинта /api/countries
@app.route('/api/countries')
def get_countries():
    region = request.args.getlist('region')  # Получаем список регионов из запроса
    filtered_countries = []
    if region:
        # Генерируем строку с плейсхолдерами для каждого региона
        placeholders = ','.join(['%s' for _ in region])
        # Формируем запрос с фильтрацией по региону
        query = f"SELECT * FROM countries WHERE region IN ({placeholders})"
        cursor.execute(query, region)
    else:
        # Получаем все страны
        cursor.execute("SELECT * FROM countries")
    countries = cursor.fetchall()
    return jsonify(countries)

# Обработчик эндпоинта /api/countries/<alpha2>
@app.route('/api/countries/<alpha2>')
def get_country(alpha2):
    # Получаем страну по её уникальному двухбуквенному коду
    cursor.execute("SELECT * FROM countries WHERE alpha2 = %s", (alpha2,))
    country = cursor.fetchone()
    if country:
        return jsonify(country)
    else:
        return jsonify({'error': 'Country not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)

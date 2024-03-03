import psycopg2
from flask import Flask

app = Flask(__name__)

# Connect to PostgreSQL
conn = psycopg2.connect(
    dbname="postgres",
    user="postgres",
    password="admin11311",
    host="localhost",
    port="5432"
)

@app.route('/api/ping')
def ping():
    return 'ok'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
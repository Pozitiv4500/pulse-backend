FROM python:3.12.1-alpine3.19

# Устанавливаем переменную окружения PYTHONUNBUFFERED=1 для предотвращения вывода буферизации
ENV PYTHONUNBUFFERED=1

# Устанавливаем директорию приложения в контейнере
WORKDIR /app

# Устанавливаем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем наше приложение в контейнер
COPY . .

# Команда для запуска приложения
CMD ["python", "app.py"]
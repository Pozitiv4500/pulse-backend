FROM python:3.12.1-alpine3.19

RUN apk add --no-cache gcc musl-dev postgresql-dev

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

ENV SERVER_PORT=8080
ENV POSTGRES_CONN="postgres://postgres:postgres@localhost:5432"

CMD ["sh", "-c", "exec python3 -m flask run --host=0.0.0.0 --port=$SERVER_PORT"]

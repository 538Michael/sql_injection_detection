FROM tiangolo/uvicorn-gunicorn:python3.11
WORKDIR /app
COPY main.py .
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY . .

EXPOSE 8000
FROM python:3.11.2
WORKDIR code
COPY main.py .
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

EXPOSE 8000

CMD ["uvicorn", "main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"]

# syntax=docker/dockerfile:1.4
FROM python:3

WORKDIR /code
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python","code/server.py"]

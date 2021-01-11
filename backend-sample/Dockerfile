FROM python:3.7
WORKDIR /app
COPY app.py .
COPY requirements.txt .
RUN pip3 install -r requirements.txt
CMD python3 app.py

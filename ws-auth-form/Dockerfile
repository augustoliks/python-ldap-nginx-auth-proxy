FROM python:3.7
ENV FLASK_ENV production
WORKDIR /app
COPY src /app
RUN pip3 install -r requirements.txt
CMD gunicorn --bind 0.0.0.0:5000
FROM python:3.7
WORKDIR /app
COPY src .
RUN apt-get update -y
RUN apt-get install -y libsasl2-dev python-dev libldap2-dev libssl-dev
RUN pip3 install -r requirements.txt
CMD gunicorn --bind 0.0.0.0:5000

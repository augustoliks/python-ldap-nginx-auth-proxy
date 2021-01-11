build:
	virtualenv venv
	venv/bin/pip3 install docker-compose

up:
	venv/bin/docker-compose up --build -d

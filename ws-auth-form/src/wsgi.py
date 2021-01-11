from flask import Flask
import routes


def create_app():
    app = Flask(__name__)
    routes.configure_routes(app)

    return app


app = create_app()

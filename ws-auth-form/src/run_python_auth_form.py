from flask import Flask
import routes


def create_app():
    app = Flask(__name__)
    routes.configure_routes(app)

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5001)

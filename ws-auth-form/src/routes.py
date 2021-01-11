import security
import base64
from flask import (
    render_template,
    Flask,
    request,
    redirect
)


def configure_routes(app: Flask):
    @app.route("/login", methods=["GET"])
    def login_get():
        header_target = request.headers.get('X-Target')

        if not header_target:
            raise RuntimeError('target url is not passed')

        return render_template(
            'form.htm.j2',
            target=header_target
        )

    @app.route("/login", methods=["POST"])
    def login_post():
        username = request.form['username']
        password = request.form['password']
        target = request.form['target']

        seal_b64 = security.seal_auth_b64(username, password)
        seal_encrypted = security.encrypt(seal_b64)
        seal_encrypted_b64 = base64.b64encode(seal_encrypted.encode('utf-8'))

        redirect_response = redirect(target, code=302)
        redirect_response.set_cookie("nginxauth", seal_encrypted_b64, httponly=True)

        return redirect_response

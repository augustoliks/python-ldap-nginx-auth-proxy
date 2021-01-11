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

        auth_seal_b64 = base64.b64encode(f'{username}:{password}'.encode())

        redirect_response = redirect(target, code=302)
        redirect_response.set_cookie("nginxauth", auth_seal_b64, httponly=True)

        return redirect_response

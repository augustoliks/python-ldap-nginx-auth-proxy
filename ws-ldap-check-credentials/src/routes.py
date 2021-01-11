import ldapauth
import json
from flask import (
    make_response,
    request,
    Flask
)


def configure_routes(app: Flask):
    @app.errorhandler(Exception)
    def error_handler(e: Exception):
        """Return JSON instead of HTML for HTTP errors."""
        realm = request.headers.get('realm')
        response = make_response()
        response.set_cookie('WWW-Authenticate', f'Basic realm="{realm}"')
        response.set_cookie('Cache-Control', 'no-cache')
        response.content_type = "application/json"
        response.status_code = 401
        response.data = json.dumps({
            'exception': str(e)
        })
        return response

    @app.route("/", methods=["GET"])
    def auth_ldap():
        ldap_params = ldapauth.LDAPParameters(
            url=request.headers['X-Ldap-URL'],
            bind_dn=request.headers['X-Ldap-BindDN'],
            bind_passwd=request.headers['X-Ldap-BindPass'],
            base_dn=request.headers['X-Ldap-BaseDN'],
            search_filter=request.headers['X-Ldap-SearchFilter'],
            disable_referrals=request.headers['X-Ldap-DisableReferrals'],
            starttls=request.headers['X-Ldap-Starttls'],
            realm=request.headers['X-Ldap-Realm']
        )
        auth_cookie_name = request.headers['X-AuthCookieName']
        auth_cookie = request.cookies[auth_cookie_name]

        if not auth_cookie:
            raise RuntimeError('user not is authenticated')

        user, password = ldapauth.retrieve_auth_b64_seal(
            auth_b64_seal=auth_cookie
        )

        auth_handler = ldapauth.LDAPAuthHandler(ldap_params)
        auth_handler.check_credentials(user, password)

        response = make_response()
        response.status_code = 200

        return response

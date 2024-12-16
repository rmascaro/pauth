from flask import Flask, redirect, url_for, session, request
from msal import ConfidentialClientApplication
import jwt
import json
import os
import uuid

app = Flask(__name__)
app.secret_key = os.getenv('PYTHON_SECRET_KEY', 'YOUR_DEFAULT_SECRET_KEY')

CLIENT_ID = os.getenv('PYTHON_CLIENT_ID')
CLIENT_SECRET = os.getenv('PYTHON_CLIENT_SECRET')
AUTHORITY = os.getenv('PYTHON_AUTHORITY')
REDIRECT_PATH = '/getAToken'
SCOPE = ['User.Read']

app_config = {
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'authority': AUTHORITY,
    'scope': SCOPE,
    'redirect_uri': os.getenv('PYTHON_REDIRECT_URI')
}

@app.route('/')
def index():
    if not session.get('user'):
        return redirect(url_for('login'))
    return redirect(url_for('display_token'))

@app.route('/login')
def login():
    session['state'] = str(uuid.uuid4())
    auth_url = _build_auth_url(state=session['state'])
    return redirect(auth_url)

@app.route(REDIRECT_PATH)
def authorized():
    if request.args.get('state') != session.get('state'):
        return redirect(url_for('index'))
    if 'error' in request.args:
        return "Error: " + request.args['error_description']
    if 'code' in request.args:
        result = _build_msal_app().acquire_token_by_authorization_code(
            request.args['code'],
            scopes=SCOPE,
            redirect_uri=app_config['redirect_uri'])
        session['user'] = result.get('id_token_claims')
        session['token'] = result.get('id_token')
    return redirect(url_for('index'))

@app.route('/display_token')
def display_token():
    if 'token' not in session:
        return redirect(url_for('login'))
    decoded_token = jwt.decode(session['token'], options={"verify_signature": False})
    return f"<pre>{json.dumps(decoded_token, indent=4)}</pre>"

@app.route('/logout')
def logout():
    session.clear()
    return redirect('https://login.microsoftonline.com/common/oauth2/v2.0/logout' +
                    '?post_logout_redirect_uri=' + url_for('index', _external=True))

def _build_msal_app():
    return ConfidentialClientApplication(
        app_config['client_id'],
        authority=app_config['authority'],
        client_credential=app_config['client_secret'])

def _build_auth_url(state=None):
    return __build_msal_app().get_authorization_request_url(
        app_config['scope'],
        state=state,
        redirect_uri=app_config['redirect_uri'])

if __name__ == '__main__':
    app.run(debug=True)

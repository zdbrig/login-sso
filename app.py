from flask import Flask, render_template, redirect, request, session, url_for
from flask_cors import CORS
import requests
import json
from functools import wraps
import os

app = Flask(__name__)
CORS(app)
app.secret_key = os.urandom(24)

KEYCLOAK_URL = "https://sso.block-gpt.io/"
REALM = "bacem"
CLIENT_ID = "bacemapp"
REDIRECT_URI = "http://localhost:5000/callback"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=session['user'])

@app.route('/login')
def login():
    if 'user' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/auth')
def auth():
    auth_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth"
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid',
        'redirect_uri': REDIRECT_URI
    }
    return redirect(requests.Request('GET', auth_url, params=params).prepare().url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return redirect(url_for('login'))

    token_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI
    }
    
    response = requests.post(token_url, data=data)
    if response.status_code != 200:
        return redirect(url_for('login'))

    tokens = response.json()
    userinfo_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/userinfo"
    headers = {'Authorization': f"Bearer {tokens['access_token']}"}
    userinfo = requests.get(userinfo_url, headers=headers).json()
    
    session['user'] = userinfo
    session['access_token'] = tokens['access_token']
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    logout_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout"
    params = {
        'redirect_uri': url_for('login', _external=True)
    }
    return redirect(requests.Request('GET', logout_url, params=params).prepare().url)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

from flask import Flask, request, redirect, url_for, render_template, session, abort

app = Flask(__name__)
app.secret_key = 'your_secret_key'

users = {'admin': 'password'}  # Dummy user database

@app.route('/')
def index():
    if 'username' in session:
        return 'Logged in as ' + session['username'] + '<br><a href="/logout">logout</a>', 200
    return redirect(url_for('login'), 302)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('index'), 302)
        else:
            return 'Invalid username/password', 401
    return render_template('login.html'), 200

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'), 302)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)

from flask import Flask, render_template, request, redirect, session, flash
from passlib.hash import sha256_crypt
import re
import mysql.connector as mariadb

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'




mariadb_connection = mariadb.connect(user='chooseAUserName', password='chooseAPassword', database='Login')

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def do_admin_login():
    login = request.form
    userName = login['username']
    password = login['password']

    cur = mariadb_connection.cursor(buffered=True)
    cur.execute('SELECT * FROM Login WHERE username=%s', (userName,))
    data = cur.fetchone()

    if data:
        if sha256_crypt.verify(password, data[2]):
            session['logged_in'] = True
            return redirect('/dashboard')
        else:
            flash('Wrong password!')
            return redirect('/')
    else:
        flash('User does not exist!')
        return redirect('/')

@app.route('/dashboard')
def dashboard():
    if session.get('logged_in'):
        return render_template('dashboard.html')
    else:
        return redirect('/')

def validate_password(password):
    # Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character
    if re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
        return True
    else:
        return False

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check for duplicate username in the database
        cur = mariadb_connection.cursor(buffered=True)
        cur.execute('SELECT * FROM Login WHERE username=%s', (username,))
        existing_user = cur.fetchone()
        if existing_user:
            flash('Username already exists!')
            return redirect('/register')
        
        # Validate password format
        if not validate_password(password):
            flash('Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character, and be at least 8 characters long.')
            return redirect('/register')

        # Encrypt the password
        hashed_password = sha256_crypt.encrypt(password)

        # Insert new user into the database
        cur.execute('INSERT INTO Login (username, password, email) VALUES (%s, %s, %s)', (username, hashed_password, email))
        cur.execute('INSERT INTO balance (username, balance) VALUES (%s, %s, %s)', (username, 10))
        mariadb_connection.commit()
        cur.close()

        flash('Registration successful! Please log in.')
        return redirect('/')

    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port='5000')


import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error= "Please provide a username!"
        elif not password:
            error= "Please provide a password!"
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            error= 'Nice one, but {} is already taken.'.format(username)

        if error is None:
            db.execute(
                'INSERT INTO user (username, password) VALUES (?,?)',(username, generate_password_hash(password))
            )
            db.commit()
            return redirect(url_for('auth.login'))

        flash(error)
    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username= ?', (username,)
        ).fetchone()

        if user is None:
            error = 'That username doesn\'t seem to exist.'
        elif not check_password_hash(user['password'], password):
            error = 'That password wasn\'t right.'

        if error is None:
            session.clear()
            session['user_id']= user['id']
            return redirect(user_for('index'))

        flash(error)

    return render_template('auth/login.html')

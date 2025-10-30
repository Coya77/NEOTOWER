# blueprints/auth.py (básico – expande después)
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from utils.database import get_db_connection  # Asume login con DB

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Lógica simple (ajusta con tu DB)
        email = request.form['email']
        password = request.form['password']
        if email == 'admin@test.com' and password == 'admin':  # Test
            session['user_id'] = 1
            session['user_rol'] = 'administrador'
            flash('Login exitoso', 'success')
            return redirect(url_for('dashboard.dashboard'))  # Ajusta
        flash('Credenciales inválidas', 'danger')
    return render_template('login.html')  # Crea template

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Logout exitoso', 'info')
    return redirect(url_for('auth.login'))
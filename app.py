# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
import psycopg2
import psycopg2.extras
import os

from io import BytesIO
from flask import send_file
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime, timedelta
from psycopg2.extras import RealDictCursor  
from functools import wraps


from datetime import datetime, timedelta
from psycopg2.extras import RealDictCursor
from werkzeug.utils import secure_filename
from io import BytesIO
import qrcode, os, uuid
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import send_file, flash, redirect, url_for, render_template, request, session
from functools import wraps

# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import psycopg2
import psycopg2.extras
from psycopg2.extras import RealDictCursor
from functools import wraps
from datetime import datetime, timedelta, date
import os
import re
import io
import pandas as pd
import requests
from itsdangerous import URLSafeTimedSerializer
import threading
from collections import defaultdict
import atexit
import schedule
import time


from functools import wraps
from flask import session, flash, redirect, url_for

def login_required_role(rol):
    """Decorador para restringir el acceso a usuarios con un rol específico."""
    def decorator(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("⚠️ Debes iniciar sesión para acceder a esta página.", "warning")
                return redirect(url_for('auth.login'))
            if session.get('user_rol') != rol:
                flash("🚫 No tienes permisos para acceder a esta sección.", "danger")
                # Si es admin, lo mandamos a su dashboard
                if session.get('user_rol') == 'administrador':
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrapped_function
    return decorator


# Blueprints
from blueprints.anuncios import anuncios_bp
from blueprints.buzon import buzon_bp
from blueprints.chat import chat_bp
from blueprints.votaciones import votaciones_bp
from blueprints.auth import auth_bp
from blueprints.notificaciones import notificaciones_bp
from blueprints.correos import correos_bp   


# Utilidades
from utils.database import DB_CONFIG, get_db_connection


from datetime import date
import re


app = Flask(__name__)
app.secret_key = os.urandom(24)

# --------------------------
# Configuración de subida de archivos
# --------------------------
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploads', 'incidentes')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# Registro de blueprints
app.register_blueprint(anuncios_bp)
app.register_blueprint(buzon_bp)
app.register_blueprint(chat_bp)            # 👈 Este es el importante
app.register_blueprint(votaciones_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(notificaciones_bp)
app.register_blueprint(correos_bp)

# --------------------------
# Configuración DB
# --------------------------
DB_CONFIG = {
    'host': 'localhost',
    'database': 'NEOTOWER',
    'user': 'postgres',
    'password': '12345'
}


bcrypt = Bcrypt(app)

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)

# ================= CONFIG MAIL =================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'neotower3@gmail.com'  # Direccion del correo remitente
app.config['MAIL_PASSWORD'] = 'dqqn nwcz xlmd wjfw'  # Esta es la contraseña empresarial, desde la que se envia el correo
app.config['MAIL_DEFAULT_SENDER'] = 'neotower3@gmail.com'
app.config['MAIL_MAX_EMAILS'] = None 
app.config['MAIL_SUPPRESS_SEND'] = False    # Contraseña de app si Gmail
mail = Mail(app)


# =========================
# CORREO DE BIENVENIDA
# =========================
def enviar_correo_bienvenida(email, nombre, rol):
    """Envía correo de bienvenida al crear cuenta nueva"""
    try:
        msg = Message(
            subject=f"Bienvenido a NEOTOWER 🏙️ - Tu cuenta ha sido creada",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )

        msg.body = f"""
        ¡Hola {nombre}! 👋

        Te damos la bienvenida a NEOTOWER.

        Tu cuenta ha sido creada exitosamente con los siguientes datos:

        🧑 Usuario: {nombre}
        📧 Correo: {email}
        🔑 Contraseña: {password}
        🎯 Rol asignado: {rol.capitalize()}

        

        Si no reconoces este registro, ignora este mensaje.

        — Equipo NEOTOWER 🏙️
        """

        mail.send(msg)
        print(f"📨 Correo de bienvenida enviado correctamente a {email}")
    except Exception as e:
        print(f"⚠️ Error enviando correo a {email}: {e}")


# ================= TOKEN =================
s = URLSafeTimedSerializer(app.secret_key)

# ================= CLAVES RECAPTCHA =================
RECAPTCHA_SITE_KEY = '6LcRy_wrAAAAAEl_fkuGIIhkabNF8FicCmISkBoN'
RECAPTCHA_SECRET_KEY = '6LcRy_wrAAAAAGZPriLu7KOzxs8jOC81-MS_mZN7'


# --------------------------
# Decoradores
# --------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_rol' not in session or session['user_rol'] not in roles:
                flash('No tienes permisos para acceder a esta página', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --------------------------
# CONFIGURACIÓN DE SEGURIDAD
# --------------------------
# Estructuras en memoria para evitar problemas de BD
seguridad_cache = defaultdict(dict)
seguridad_lock = threading.Lock()

MAX_INTENTOS = 5
TIEMPO_BLOQUEO = 15  # Minutos
TIEMPO_VENTANA = 30  # Minutos

def seguridad_registrar_intento_simple(ip, username=None):
    """Registrar intento fallido usando cache en memoria"""
    with seguridad_lock:
        ahora = datetime.now()
        
        # Obtener o crear registro para esta IP
        if ip not in seguridad_cache:
            seguridad_cache[ip] = {
                'intentos': 0,
                'primer_intento': ahora,
                'ultimo_intento': ahora,
                'bloqueado': False,
                'fecha_desbloqueo': None
            }
        
        registro = seguridad_cache[ip]
        
        # Limpiar si la ventana de tiempo expiró
        if ahora - registro['primer_intento'] > timedelta(minutes=TIEMPO_VENTANA):
            registro['intentos'] = 0
            registro['primer_intento'] = ahora
            registro['bloqueado'] = False
            registro['fecha_desbloqueo'] = None
        
        # Si está bloqueado, verificar si ya pasó el tiempo
        if registro['bloqueado'] and registro['fecha_desbloqueo']:
            if ahora > registro['fecha_desbloqueo']:
                registro['bloqueado'] = False
                registro['intentos'] = 0
                registro['fecha_desbloqueo'] = None
            else:
                registro['ultimo_intento'] = ahora
                return True  # Sigue bloqueado
        
        # Incrementar intentos
        registro['intentos'] += 1
        registro['ultimo_intento'] = ahora
        
        print(f"🔐 Intento {registro['intentos']}/{MAX_INTENTOS} para IP: {ip}")
        
        # Verificar si debe bloquearse
        if registro['intentos'] >= MAX_INTENTOS:
            registro['bloqueado'] = True
            registro['fecha_desbloqueo'] = ahora + timedelta(minutes=TIEMPO_BLOQUEO)
            print(f"🚫 IP {ip} BLOQUEADA por {TIEMPO_BLOQUEO} minutos")
            return True  # Bloqueado
        
        return False  # No bloqueado

def seguridad_verificar_bloqueo_simple(ip):
    """Verificar bloqueo usando cache en memoria"""
    with seguridad_lock:
        ahora = datetime.now()
        
        if ip not in seguridad_cache:
            return False, 0  # No bloqueado, 0 intentos
        
        registro = seguridad_cache[ip]
        
        # Limpiar si la ventana de tiempo expiró
        if ahora - registro['primer_intento'] > timedelta(minutes=TIEMPO_VENTANA):
            registro['intentos'] = 0
            registro['primer_intento'] = ahora
            registro['bloqueado'] = False
            registro['fecha_desbloqueo'] = None
            return False, 0
        
        # Verificar bloqueo
        if registro['bloqueado'] and registro['fecha_desbloqueo']:
            if ahora > registro['fecha_desbloqueo']:
                # Auto-desbloquear
                registro['bloqueado'] = False
                registro['intentos'] = 0
                registro['fecha_desbloqueo'] = None
                return False, 0
            else:
                tiempo_restante = (registro['fecha_desbloqueo'] - ahora).total_seconds() / 60
                return True, tiempo_restante  # Bloqueado
        
        return False, registro['intentos']  # No bloqueado, X intentos

def seguridad_limpiar_cache():
    """Limpiar cache antiguo"""
    with seguridad_lock:
        ahora = datetime.now()
        ips_a_eliminar = []
        
        for ip, registro in seguridad_cache.items():
            if ahora - registro['ultimo_intento'] > timedelta(hours=24):
                ips_a_eliminar.append(ip)
        
        for ip in ips_a_eliminar:
            del seguridad_cache[ip]
        
        if ips_a_eliminar:
            print(f"🧹 Limpiadas {len(ips_a_eliminar)} IPs antiguas del cache")

def seguridad_estado_actual():
    """Obtener estado actual del sistema de seguridad"""
    with seguridad_lock:
        return {
            'total_ips': len(seguridad_cache),
            'ips_bloqueadas': sum(1 for r in seguridad_cache.values() if r['bloqueado']),
            'cache': dict(seguridad_cache)
        }
def inicializar_seguridad():
    """Inicializar sistema de seguridad"""
    print("🛡️  Inicializando sistema de seguridad en memoria...")
    
    # Limpiar cache al iniciar
    seguridad_limpiar_cache()
    
    # Programar limpieza periódica (cada hora)
    def tarea_limpieza():
        seguridad_limpiar_cache()
        print("🛡️  Limpieza automática de seguridad ejecutada")
    
    # Ejecutar limpieza al salir
    atexit.register(seguridad_limpiar_cache)
inicializar_seguridad()

def obtener_ip_cliente():
    """Obtener la IP real del cliente considerando proxies"""
    if request.headers.get('X-Forwarded-For'):
        # Si está detrás de un proxy
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    
    # Limpiar y validar IP
    if ip and ip != '127.0.0.1' and ip != 'localhost':
        return ip
    else:
        # Para desarrollo local, usar una IP de prueba
        return '127.0.0.1'


# --------------------------
# Rutas básicas
# --------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))



# --------------------------
# LOGIN
# --------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Obtener IP del cliente
    ip_cliente = obtener_ip_cliente()
    print(f"\n" + "="*50)
    print(f"🔐 LOGIN - IP: {ip_cliente}")
    
    # Verificar bloqueo
    bloqueado, info = seguridad_verificar_bloqueo_simple(ip_cliente)
    
    if bloqueado:
        print(f"🚫 BLOQUEADO - Tiempo restante: {info:.1f} min")
        flash(f'⛔ Demasiados intentos fallidos. Intenta nuevamente en {int(info)} minutos', 'danger')
        return render_template('login.html', 
                             site_key=RECAPTCHA_SITE_KEY, 
                             bloqueado=True,
                             max_intentos=MAX_INTENTOS,
                             tiempo_bloqueo=TIEMPO_BLOQUEO)
    
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        
        print(f"📧 Usuario: {email}")

        # Validar captcha
        captcha_response = request.form.get('g-recaptcha-response')
        if not captcha_response:
            flash('Por favor, verifica el captcha', 'danger')
            return render_template('login.html', site_key=RECAPTCHA_SITE_KEY)
        
        captcha_verify = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={'secret': RECAPTCHA_SECRET_KEY, 'response': captcha_response}
        )
        captcha_result = captcha_verify.json()
        if not captcha_result.get('success'):
            flash('Captcha incorrecto, intenta nuevamente', 'danger')
            return render_template('login.html', site_key=RECAPTCHA_SITE_KEY)

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT id_usuario, password, rol, nombre, apellido FROM usuario WHERE email = %s",
                (email,)
            )
            user = cur.fetchone()

            if user and bcrypt.check_password_hash(user['password'], password):
                # ✅ Login exitoso
                print(f"🎉 LOGIN EXITOSO")
                
                # Actualizar último acceso
                cur.execute(
                    "UPDATE usuario SET ultimo_acceso = %s WHERE id_usuario = %s",
                    (datetime.now(), user['id_usuario'])
                )
                conn.commit()

                # Configurar sesión
                session['user_id'] = user['id_usuario']
                session['user_rol'] = user['rol']
                session['user_nombre'] = f"{user['nombre']} {user['apellido']}"

                # Limpiar intentos fallidos para esta IP
                with seguridad_lock:
                    if ip_cliente in seguridad_cache:
                        del seguridad_cache[ip_cliente]
                
                flash('Inicio de sesión exitoso ✅', 'success')

                if user['rol'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('dashboard'))
            else:
                # ❌ Login fallido
                print(f"❌ LOGIN FALLIDO")
                bloqueado_ahora = seguridad_registrar_intento_simple(ip_cliente, email)
                
                # Obtener estado actual
                _, intentos_actuales = seguridad_verificar_bloqueo_simple(ip_cliente)
                intentos_restantes = MAX_INTENTOS - intentos_actuales
                
                if bloqueado_ahora:
                    flash(f'⛔ Demasiados intentos fallidos. IP bloqueada por {TIEMPO_BLOQUEO} minutos', 'danger')
                    print(f"🔐 BLOQUEO ACTIVADO después de {MAX_INTENTOS} intentos")
                else:
                    if intentos_restantes <= 2:
                        flash(f'⚠️ Email o contraseña incorrectos. Te quedan {intentos_restantes} intentos', 'warning')
                    else:
                        flash('Email o contraseña incorrectos ❌', 'danger')
                    
                    print(f"📊 Estado: {intentos_actuales}/{MAX_INTENTOS} intentos fallidos")

        except Exception as e:
            print(f"💥 ERROR: {str(e)}")
            flash('Error al iniciar sesión: ' + str(e), 'danger')
        finally:
            cur.close()
            conn.close()

    # Obtener estado para el template
    _, intentos_actuales = seguridad_verificar_bloqueo_simple(ip_cliente)
    intentos_restantes = MAX_INTENTOS - intentos_actuales
    
    print(f"📈 Estado: {intentos_actuales} intentos, {intentos_restantes} restantes")
    print("="*50)
    
    return render_template('login.html', 
                         site_key=RECAPTCHA_SITE_KEY, 
                         bloqueado=False,
                         intentos_restantes=intentos_restantes,
                         max_intentos=MAX_INTENTOS)



@app.route('/admin/seguridad')
@login_required
@role_required(['administrador'])
def admin_seguridad():
    """Panel de monitoreo de seguridad"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Estadísticas de seguridad
        cur.execute("""
            SELECT 
                COUNT(*) as total_intentos,
                COUNT(CASE WHEN bloqueado THEN 1 END) as ips_bloqueadas,
                COUNT(CASE WHEN intentos_fallidos >= 3 THEN 1 END) as ips_sospechosas,
                MAX(ultimo_intento) as ultimo_intento
            FROM intentos_login 
            WHERE primer_intento > NOW() - INTERVAL '24 hours'
        """)
        stats = cur.fetchone()
        
        # IPs bloqueadas actualmente
        cur.execute("""
            SELECT ip_address, username, intentos_fallidos, 
                   fecha_desbloqueo, ultimo_intento
            FROM intentos_login 
            WHERE bloqueado = TRUE
            ORDER BY ultimo_intento DESC
            LIMIT 50
        """)
        ips_bloqueadas = cur.fetchall()
        
        # Últimos eventos de seguridad
        cur.execute("""
            SELECT ip_address, usuario, evento, descripcion, fecha_evento, nivel_severidad
            FROM logs_seguridad 
            ORDER BY fecha_evento DESC
            LIMIT 100
        """)
        logs = cur.fetchall()
        
    except Exception as e:
        flash(f"Error cargando datos de seguridad: {e}", "danger")
        stats, ips_bloqueadas, logs = {}, [], []
    finally:
        cur.close()
        conn.close()
    
    return render_template('administrador/seguridad.html',
                         stats=stats,
                         ips_bloqueadas=ips_bloqueadas,
                         logs=logs,
                         max_intentos=MAX_INTENTOS,
                         tiempo_bloqueo=TIEMPO_BLOQUEO)

def registrar_log_seguridad(ip, usuario, evento, descripcion, nivel_severidad='bajo'):
    """Registrar evento de seguridad en la base de datos"""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO logs_seguridad (ip_address, usuario, evento, descripcion, nivel_severidad)
            VALUES (%s, %s, %s, %s, %s)
        """, (ip, usuario, evento, descripcion, nivel_severidad))
        conn.commit()
    except Exception as e:
        print(f"Error registrando log de seguridad: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

def send_file(file_path, as_attachment=False, download_name=None):
    """Función simplificada para enviar archivos (para exportación)"""
    from flask import send_from_directory
    import os
    directory = os.path.dirname(file_path)
    filename = os.path.basename(file_path)
    return send_from_directory(directory, filename, as_attachment=as_attachment, download_name=download_name)


@app.route('/admin/seguridad/desbloquear-ip/<ip>')
@login_required
@role_required(['administrador'])
def desbloquear_ip(ip):
    """Desbloquear una IP manualmente"""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE intentos_login 
            SET bloqueado = FALSE, intentos_fallidos = 0, fecha_desbloqueo = NULL
            WHERE ip_address = %s
        """, (ip,))
        conn.commit()
        
        registrar_log_seguridad(ip, session['user_nombre'], 'ip_desbloqueada',
                              f'IP desbloqueada manualmente por administrador', 'medio')
        
        flash(f"✅ IP {ip} desbloqueada correctamente", "success")
    except Exception as e:
        flash(f"❌ Error desbloqueando IP: {e}", "danger")
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for('admin_seguridad'))


# --------------------------
# OLVIDÉ CONTRASEÑA
# --------------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id_usuario FROM usuario WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)
            
            msg = Message('Recuperar contraseña - NEOTOWER',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            msg.body = f'Hola, para restablecer tu contraseña haz click en el siguiente enlace: {reset_link}\n\nSi no solicitaste esto, ignora este mensaje.'
            mail.send(msg)

            flash('Se ha enviado un correo con instrucciones para restablecer tu contraseña', 'info')
        else:
            flash('El correo no está registrado', 'danger')

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('El enlace es inválido o ha expirado', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("UPDATE usuario SET password = %s WHERE email = %s", (hashed_password, email))
            conn.commit()
            cur.close()
            conn.close()
            flash('Contraseña restablecida correctamente. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# --------------------------
# LOGOUT
# --------------------------
@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada correctamente 👋', 'info')
    return redirect(url_for('login'))



# --------------------------
# REGISTRO
# --------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nombre = request.form['nombre'].strip()
        apellido = request.form['apellido'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        telefono = request.form.get('telefono', '').strip()
        tipo_residente = 'residente'

        errors = []
        if password != confirm_password:
            errors.append('Las contraseñas no coinciden')
        if len(password) < 6:
            errors.append('La contraseña debe tener al menos 6 caracteres')
        if not re.search(r'[A-Z]', password):
            errors.append('Debe contener al menos una mayúscula')
        if not re.search(r'[0-9]', password):
            errors.append('Debe contener al menos un número')
        if not re.match(r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$', email):
            errors.append('Formato de email inválido')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('register.html')

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT id_usuario FROM usuario WHERE email = %s", (email,))
            if cur.fetchone():
                flash('El email ya está registrado', 'danger')
                return render_template('register.html')

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            cur.execute("""
                INSERT INTO usuario (rol, nombre, apellido, email, password)
                VALUES (%s, %s, %s, %s, %s) RETURNING id_usuario
            """, (tipo_residente, nombre, apellido, email, hashed_password))
            user_id = cur.fetchone()['id_usuario']

            cur.execute("""
                INSERT INTO residente (id_usuario, nombre, apellido, email, telefono, fecha_registro)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, nombre, apellido, email, telefono, datetime.now().date()))

            conn.commit()
            # Si no viene del formulario, asigna "residente" por defecto
            rol = request.form.get('rol', 'residente')

            enviar_correo_bienvenida(email, f"{nombre} {apellido}", rol)
            flash('Registro exitoso 🎉. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            conn.rollback()
            flash('Error al registrar: ' + str(e), 'danger')
        finally:
            cur.close()
            conn.close()

    return render_template('register.html')

# --------------------------
# DASHBOARDS
# --------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    # Detectar el rol: si no está en la sesión, asumir residente
    rol = session.get('user_rol', 'residente')
    # Unificar roles de administrador: admite 'administrador' y 'admin'
    if rol in ('administrador', 'admin'):
        return redirect(url_for('admin_dashboard'))
    # Para residentes u otros roles, mostrar el dashboard estándar
    return render_template('dashboard.html')

@app.route('/admin/dashboard')
@login_required
@role_required(['administrador', 'admin'])  # Permitir ambos nombres de rol
def admin_dashboard():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    stats, resumen, labels, saldos = {}, {}, [], []

    try:
        # Estadísticas básicas
        cur.execute("SELECT COUNT(*) AS total FROM usuario;")
        stats['total_usuarios'] = cur.fetchone()['total']

        cur.execute("SELECT COUNT(*) AS total FROM departamento;")
        stats['total_departamentos'] = cur.fetchone()['total']

        cur.execute("SELECT COUNT(*) AS total FROM incidente WHERE estado = 'pendiente';")
        stats['incidentes_activos'] = cur.fetchone()['total']

        cur.execute("SELECT COUNT(*) AS total FROM pago WHERE estado = 'pendiente';")
        stats['pagos_pendientes'] = cur.fetchone()['total']

        # Resumen financiero del mes actual
        cur.execute("""
            SELECT COALESCE(SUM(monto), 0) AS total
            FROM pago
            WHERE estado = 'pagado'
            AND DATE_TRUNC('month', fecha) = DATE_TRUNC('month', CURRENT_DATE);
        """)
        ingresos_mes = float(cur.fetchone()['total'])

        cur.execute("""
            SELECT COALESCE(SUM(monto), 0) AS total
            FROM pago_personal
            WHERE DATE_TRUNC('month', fecha) = DATE_TRUNC('month', CURRENT_DATE);
        """)
        egresos_mes = float(cur.fetchone()['total'])

        resumen['ingresos_mes'] = ingresos_mes
        resumen['egresos_mes'] = egresos_mes
        resumen['saldo_mes'] = ingresos_mes - egresos_mes

        # Evolución mensual (últimos 6 meses)
        cur.execute("""
            SELECT TO_CHAR(DATE_TRUNC('month', fecha), 'YYYY-MM') AS mes, SUM(monto) AS total
            FROM pago
            WHERE estado = 'pagado'
            GROUP BY mes
            ORDER BY mes ASC
            LIMIT 6;
        """)
        ingresos = cur.fetchall()

        cur.execute("""
            SELECT TO_CHAR(DATE_TRUNC('month', fecha), 'YYYY-MM') AS mes, SUM(monto) AS total
            FROM pago_personal
            GROUP BY mes
            ORDER BY mes ASC
            LIMIT 6;
        """)
        egresos = cur.fetchall()

        # Combinar ingresos y egresos por mes para calcular el saldo mensual
        data_combinado = {}
        for r in ingresos:
            data_combinado[r['mes']] = {'ingreso': float(r['total']), 'egreso': 0.0}
        for r in egresos:
            if r['mes'] in data_combinado:
                data_combinado[r['mes']]['egreso'] = float(r['total'])
            else:
                data_combinado[r['mes']] = {'ingreso': 0.0, 'egreso': float(r['total'])}

        saldos = []
        for mes in sorted(data_combinado.keys()):
            ingreso = data_combinado[mes]['ingreso']
            egreso = data_combinado[mes]['egreso']
            saldo = ingreso - egreso
            saldos.append({'mes': mes, 'ingreso': ingreso, 'egreso': egreso, 'saldo': saldo})

        labels = [d['mes'] for d in saldos]

    except Exception as e:
        print(f"❌ Error al cargar dashboard financiero: {e}")
        flash("Error al cargar los datos financieros.", "danger")
    finally:
        cur.close()
        conn.close()

    return render_template(
        'admin_dashboard.html',
        stats=stats,
        resumen=resumen,
        labels=labels,
        saldos=saldos
    )

# --------------------------
# PERFIL DE USUARIO
# --------------------------
@app.route('/usuario/perfil')
@login_required
def usuario_perfil():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id_usuario, nombre, apellido, email, rol, ultimo_acceso
            FROM usuario
            WHERE id_usuario = %s
        """, (session['user_id'],))
        usuario = cur.fetchone()
    except Exception as e:
        flash("Error cargando el perfil: " + str(e), "danger")
        usuario = None
    finally:
        cur.close()
        conn.close()
    return render_template('usuario/perfil.html', usuario=usuario)



# --------------------------
# PAGOS - USUARIO
# --------------------------

@app.route('/usuario/pagos')
@login_required
def mis_pagos():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # 🔹 Obtener datos desde la vista consolidada
        cur.execute("""
            SELECT 
                id_pago,
                fecha_pago AS fecha,
                monto,
                estado,
                situacion,
                dias_retraso
            FROM vista_estado_cuenta
            WHERE id_usuario = %s
            ORDER BY fecha_pago DESC;
        """, (session['user_id'],))
        pagos = cur.fetchall()

        # 🔹 Calcular resumenes
        total_pagado = sum(p['monto'] for p in pagos if p['estado'].lower() == 'pagado')
        total_pendiente = sum(p['monto'] for p in pagos if p['estado'].lower() == 'pendiente')
        total_moroso = sum(p['monto'] for p in pagos if p['situacion'].lower() == 'moroso')

    except Exception as e:
        flash(f"Error cargando pagos: {e}", "danger")
        pagos, total_pagado, total_pendiente, total_moroso = [], 0, 0, 0
    finally:
        cur.close()
        conn.close()

    return render_template(
        "usuario/mis_pagos.html",
        pagos=pagos,
        total_pagado=total_pagado,
        total_pendiente=total_pendiente,
        total_moroso=total_moroso
    )



from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import mm
import qrcode
import os
@app.route('/usuario/pagar_servicio', methods=['POST'])
@login_required
def pagar_servicio():
    id_pago = request.form.get('id_pago')
    metodo = request.form.get('metodo')
    codigo = request.form.get('codigo', f"QR-{int(datetime.now().timestamp())}")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # 🔹 Actualizar estado del pago
        cur.execute("UPDATE pago SET estado = 'pagado' WHERE id_pago = %s", (id_pago,))

        # 🔹 Obtener información del residente y pago
        cur.execute("""
            SELECT 
                COALESCE(u.nombre, '') AS nombre,
                COALESCE(u.apellido, '') AS apellido,
                COALESCE(u.email, '') AS email,
                COALESCE(p.monto, 0) AS monto,
                COALESCE(p.fecha, CURRENT_DATE) AS fecha
            FROM pago p
            JOIN relacion_usuario_pago rup ON rup.id_pago = p.id_pago
            JOIN usuario u ON u.id_usuario = rup.id_usuario
            WHERE p.id_pago = %s
            LIMIT 1;
        """, (id_pago,))
        datos = cur.fetchone()

        if not datos:
            flash("⚠️ No se encontraron datos del usuario o pago.", "warning")
            return redirect(url_for('mis_pagos'))

        # ✅ Extraer datos
        nombre = datos.get('nombre', '')
        apellido = datos.get('apellido', '')
        email = datos.get('email', '')
        nombre_residente = f"{nombre} {apellido}".strip()

        try:
            monto = float(datos['monto'])
        except (ValueError, TypeError):
            monto = 0.0

        fecha = datos['fecha']
        fecha_str = fecha.strftime("%d/%m/%Y") if hasattr(fecha, "strftime") else str(fecha)

        # 🔹 Buscar el periodo desde la factura asociada
        cur.execute("""
            SELECT descripcion
            FROM factura
            WHERE id_pago = %s
            LIMIT 1;
        """, (id_pago,))
        factura = cur.fetchone()
        periodo = "No especificado"
        if factura and factura["descripcion"]:
            import re
            # busca dentro de corchetes [Octubre 2025] o después de "Periodo:"
            match = re.search(r"\[(.*?)\]", factura["descripcion"])
            if match:
                periodo = match.group(1)
            else:
                match_alt = re.search(r"Periodo[:\s]+(.+)", factura["descripcion"])
                if match_alt:
                    periodo = match_alt.group(1).strip()

        # -------------------------------
        # Crear carpeta de comprobantes
        # -------------------------------
        carpeta = os.path.join("static", "comprobantes")
        os.makedirs(carpeta, exist_ok=True)
        ruta_pdf = os.path.join(carpeta, f"comprobante_{id_pago}.pdf")

        # -------------------------------
        # Generar QR
        # -------------------------------
        qr_data = f"Comprobante NEOTOWER #{id_pago} - {nombre_residente} - {monto:.2f} Bs"
        qr_img = qrcode.make(qr_data)
        qr_path = os.path.join(carpeta, f"qr_{id_pago}.png")
        qr_img.save(qr_path)

        # -------------------------------
        # Crear PDF
        # -------------------------------
        c = canvas.Canvas(ruta_pdf, pagesize=letter)
        ancho, alto = letter

        # Fondo
        c.setFillColorRGB(0.95, 0.97, 1)
        c.rect(0, 0, ancho, alto, stroke=0, fill=1)

        # Borde
        c.setStrokeColor(colors.lightgrey)
        c.rect(25, 25, ancho - 50, alto - 50, stroke=1, fill=0)

        # Logo
        logo_path = os.path.join("static", "images", "img1.jpeg")
        if os.path.exists(logo_path):
            c.drawImage(logo_path, 50, alto - 100, width=120, height=60, mask='auto')

        # Título
        c.setFont("Helvetica-Bold", 18)
        c.setFillColor(colors.darkblue)
        c.drawString(200, alto - 70, "COMPROBANTE DE PAGO")
        c.setFont("Helvetica", 11)
        c.setFillColor(colors.black)
        c.drawString(200, alto - 90, "Sistema de Gestión NEOTOWER")
        c.line(40, alto - 100, ancho - 40, alto - 100)

        # -------------------------
        # DATOS DEL PAGO
        # -------------------------
        c.setFont("Helvetica", 11)
        y = alto - 150
        c.drawString(50, y, f"Residente: {nombre_residente}")
        y -= 20
        c.drawString(50, y, f"Email: {email}")
        y -= 20
        c.drawString(50, y, f"Periodo: {periodo}")  # 🔹 NUEVO CAMPO FUNCIONAL
        y -= 20
        c.drawString(50, y, f"Fecha del pago: {fecha_str}")
        y -= 20
        c.drawString(50, y, f"Método utilizado: {metodo.upper()}")
        y -= 20
        c.drawString(50, y, f"Código de confirmación: {codigo}")

        # -------------------------
        # CUADRO DE MONTO
        # -------------------------
        y -= 35
        c.setFillColorRGB(0.9, 0.95, 1)
        c.rect(45, y - 5, 180, 30, stroke=1, fill=1)
        c.setFont("Helvetica-Bold", 13)
        c.setFillColor(colors.darkblue)
        c.drawString(55, y + 5, f"MONTO: {monto:.2f} Bs")

        # -------------------------
        # QR
        # -------------------------
        c.drawImage(qr_path, ancho - 180, alto - 250, width=120, height=120)
        c.setFont("Helvetica-Oblique", 9)
        c.setFillColor(colors.gray)
        c.drawString(ancho - 180, alto - 260, "Escanea para verificar")

        # -------------------------
        # Monto total decorativo
        # -------------------------
        c.setFont("Helvetica-Bold", 14)
        c.setFillColor(colors.darkblue)
        c.drawCentredString(ancho / 2, 180, f"MONTO TOTAL: {monto:.2f} Bs")

        # -------------------------
        # Pie de página
        # -------------------------
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.gray)
        c.drawCentredString(ancho / 2, 50, "NEOTOWER • Administración del Edificio Inteligente")
        c.setFillColor(colors.black)

        c.save()

        conn.commit()
        flash("✅ Pago realizado correctamente y comprobante con periodo generado.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al procesar pago: {type(e).__name__} → {e}", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('mis_pagos'))




@app.route('/administrador/pagar_personal', methods=['POST'])
@login_required
@role_required(['administrador'])
def pagar_personal():
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    import qrcode
    import os

    id_personal = request.form.get('id_personal')
    monto = request.form.get('monto')
    id_admin = session.get('user_id')  # ID del administrador logueado

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # 🔹 Obtener datos del personal
        cur.execute("""
            SELECT nombre, cargo, salario
            FROM personal
            WHERE id_personal = %s
        """, (id_personal,))
        datos = cur.fetchone()

        if not datos:
            flash("⚠️ No se encontró el personal seleccionado.", "warning")
            return redirect(url_for('gestion_personal'))

        nombre = datos['nombre']
        cargo = datos['cargo']
        try:
            salario = float(datos['salario'])
        except (ValueError, TypeError):
            salario = 0.0

        # 🔹 Registrar el pago
        cur.execute("""
            INSERT INTO pago_personal (id_personal, fecha, monto)
            VALUES (%s, CURRENT_DATE, %s)
        """, (id_personal, monto))
        conn.commit()
        

        # 🔹 Crear carpeta para comprobantes si no existe
        carpeta = os.path.join("static", "comprobantes_personal")
        os.makedirs(carpeta, exist_ok=True)

        # 🔹 Nombre del archivo PDF (usa la fecha para hacerlo único)
        fecha_actual = datetime.now().strftime("%d-%m-%Y")
        ruta_pdf = os.path.join(carpeta, f"recibo_{id_personal}_{fecha_actual}.pdf")

        # 🔹 Crear QR con datos básicos del pago
        qr_data = f"Pago de sueldo {nombre} - {cargo} - {monto} Bs - {fecha_actual}"
        qr_img = qrcode.make(qr_data)
        qr_path = os.path.join(carpeta, f"qr_personal_{id_personal}.png")
        qr_img.save(qr_path)

        # -------------------------------
        # CREAR COMPROBANTE PDF
        # -------------------------------
        c = canvas.Canvas(ruta_pdf, pagesize=letter)
        ancho, alto = letter

        # Fondo azul claro
        c.setFillColorRGB(0.95, 0.97, 1)
        c.rect(0, 0, ancho, alto, stroke=0, fill=1)

        # Borde gris claro
        c.setStrokeColor(colors.lightgrey)
        c.rect(25, 25, ancho - 50, alto - 50, stroke=1, fill=0)

        # Logo NEOTOWER
        logo_path = os.path.join("static", "images", "img1.jpeg")
        if os.path.exists(logo_path):
            c.drawImage(logo_path, 50, alto - 100, width=120, height=60, mask='auto')

        # Título
        c.setFont("Helvetica-Bold", 18)
        c.setFillColor(colors.darkblue)
        c.drawString(200, alto - 70, "RECIBO DE SUELDO")
        c.setFont("Helvetica", 11)
        c.setFillColor(colors.black)
        c.drawString(200, alto - 90, "Sistema de Gestión NEOTOWER")
        c.line(40, alto - 100, ancho - 40, alto - 100)

        # Datos del empleado
        y = alto - 150
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Empleado: {nombre}")
        y -= 20
        c.drawString(50, y, f"Cargo: {cargo}")
        y -= 20
        c.drawString(50, y, f"Fecha de pago: {fecha_actual}")
        y -= 20
        c.drawString(50, y, f"Registrado por Administracion: {id_admin}")

        # Cuadro del monto
        y -= 35
        c.setFillColorRGB(0.9, 0.95, 1)
        c.rect(45, y - 5, 180, 30, stroke=1, fill=1)
        c.setFont("Helvetica-Bold", 13)
        c.setFillColor(colors.darkblue)
        c.drawString(55, y + 5, f"MONTO: {float(monto):.2f} Bs")

        # QR a la derecha
        c.drawImage(qr_path, ancho - 180, alto - 250, width=120, height=120)
        c.setFont("Helvetica-Oblique", 9)
        c.setFillColor(colors.gray)
        c.drawString(ancho - 180, alto - 260, "Escanea para verificar")

        # Monto total centrado (opcional)
        c.setFont("Helvetica-Bold", 14)
        c.setFillColor(colors.darkblue)
        c.drawCentredString(ancho / 2, 180, f"SUELDO PAGADO: {float(monto):.2f} Bs")

        # Pie de página
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.gray)
        c.drawCentredString(ancho / 2, 50, "NEOTOWER • Administración del Edificio Inteligente")
        c.setFillColor(colors.black)

        c.save()

        flash(f"✅ Pago de {monto} Bs registrado correctamente y comprobante generado.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al registrar pago: {type(e).__name__} → {e}", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('gestion_personal'))


@app.route('/admin/historial_pagos')
@login_required
@role_required(['administrador'])
def historial_pagos():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Consulta ajustada con relacion_usuario_pago
        cur.execute("""
            SELECT 
                u.nombre || ' ' || u.apellido AS residente,
                p.id_pago,
                p.monto,
                p.estado,
                p.fecha AS fecha_pago
            FROM relacion_usuario_pago rup
            JOIN usuario u ON u.id_usuario = rup.id_usuario
            JOIN pago p ON p.id_pago = rup.id_pago
            ORDER BY p.fecha DESC;
        """)
        historial = cur.fetchall()
    except Exception as e:
        flash(f"❌ Error al cargar historial: {type(e).__name__} → {e}", "danger")
        historial = []
    finally:
        cur.close()
        conn.close()

    return render_template('administrador/historial_pagos.html', historial=historial)




@app.route('/asignar_pago', methods=['POST'])
@login_required
@role_required(['administrador'])
def asignar_pago():
    id_usuario = request.form['id_usuario']
    electricidad = float(request.form['electricidad'])
    agua = float(request.form['agua'])
    gas = float(request.form['gas'])
    mantenimiento = float(request.form['mantenimiento'])
    periodo = request.form.get('periodo', 'Sin periodo')

    total = electricidad + agua + gas + mantenimiento

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        # 🔹 Insertar pago
        cur.execute("""
            INSERT INTO pago (fecha, monto, tipo, estado)
            VALUES (CURRENT_DATE, %s, %s, 'pendiente')
            RETURNING id_pago;
        """, (total, 'servicios'))
        id_pago = cur.fetchone()['id_pago']

        # 🔹 Relacionar con usuario
        cur.execute("""
            INSERT INTO relacion_usuario_pago (id_usuario, id_pago)
            VALUES (%s, %s);
        """, (id_usuario, id_pago))

        # 🔹 Crear factura con fecha
        descripcion = (
            f"[{periodo}] "
            f"Electricidad: {electricidad:.2f} Bs | "
            f"Agua: {agua:.2f} Bs | "
            f"Gas: {gas:.2f} Bs | "
            f"Mantenimiento: {mantenimiento:.2f} Bs"
        )

        cur.execute("""
            INSERT INTO factura (id_pago, fecha, descripcion, formato, monto)
            VALUES (%s, CURRENT_DATE, %s, 'pdf', %s);
        """, (id_pago, descripcion, total))

        conn.commit()
        flash('✅ Pago asignado correctamente.', 'success')

    except Exception as e:
        conn.rollback()
        flash(f'❌ Error al asignar pago: {type(e).__name__} → {e}', 'danger')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('gestion_pagos'))



@app.route('/pagos')
def pagos():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            u.id_usuario,
            CONCAT(u.nombre, ' ', u.apellido) AS nombre_completo,
            COALESCE(d.numero, 'N/A') AS departamento,
            COALESCE(TO_CHAR(MAX(p.fecha), 'DD/MM/YYYY'), 'Sin pagos') AS ultimo_pago,
            CASE
                WHEN COUNT(p.id_pago) = 0 THEN 'Sin pagos'
                WHEN BOOL_OR(p.estado = 'pendiente') THEN 'Pendiente'
                ELSE 'Pagado'
            END AS estado
        FROM usuario u
        JOIN residente r ON r.id_usuario = u.id_usuario
        LEFT JOIN departamento d ON d.id_residente = r.id_residente
        LEFT JOIN relacion_usuario_pago rup ON rup.id_usuario = u.id_usuario
        LEFT JOIN pago p ON p.id_pago = rup.id_pago
        WHERE u.rol = 'residente'
        GROUP BY u.id_usuario, nombre_completo, d.numero
        ORDER BY u.id_usuario;
    """)

    residentes = []
    for row in cur.fetchall():
        print("🧩 Residente encontrado:", row)  # 👈 imprimimos para verificar
        residentes.append({
            'id_usuario': row[0],
            'nombre': row[1],
            'departamento': row[2],
            'ultimo_pago': row[3],
            'estado': row[4]
        })

    # Mostrar conteo en consola
    print("✅ Total residentes:", len(residentes))

    # Pagos
    cur.execute("""
        SELECT id_pago, monto, tipo, estado, fecha
        FROM pago
        ORDER BY fecha DESC;
    """)
    pagos = [
        {'id_pago': p[0], 'monto': p[1], 'tipo': p[2], 'estado': p[3], 'fecha': p[4]}
        for p in cur.fetchall()
    ]

    cur.close()
    conn.close()

    return render_template('administrador/pagos.html', residentes=residentes, pagos=pagos)



@app.route('/reportes_financieros')
@login_required
@role_required(['administrador'])
def reportes_financieros():
    from io import BytesIO
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    import pandas as pd

    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')
    exportar = request.args.get('exportar')

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    condiciones = []
    params = []

    if fecha_inicio:
        condiciones.append("p.fecha >= %s")
        params.append(fecha_inicio)
    if fecha_fin:
        condiciones.append("p.fecha <= %s")
        params.append(fecha_fin)

    where_clause = "WHERE " + " AND ".join(condiciones) if condiciones else ""

    try:
        # 💵 INGRESOS
        cur.execute(f"""
            SELECT 
                p.fecha,
                u.nombre || ' ' || u.apellido AS descripcion,
                p.monto,
                'Ingreso' AS tipo
            FROM pago p
            JOIN relacion_usuario_pago rup ON rup.id_pago = p.id_pago
            JOIN usuario u ON u.id_usuario = rup.id_usuario
            {where_clause}
            AND p.estado = 'pagado'
            ORDER BY p.fecha DESC;
        """, params)
        ingresos = cur.fetchall()

        # 💸 EGRESOS
        cur.execute(f"""
            SELECT 
                pp.fecha,
                per.nombre || ' (' || per.cargo || ')' AS descripcion,
                pp.monto,
                'Egreso' AS tipo
            FROM pago_personal pp
            JOIN personal per ON per.id_personal = pp.id_personal
            {where_clause.replace('p.', 'pp.')}
            ORDER BY pp.fecha DESC;
        """, params)
        egresos = cur.fetchall()

        # 🔄 Unificar
        reportes = ingresos + egresos
        reportes.sort(key=lambda x: x['fecha'], reverse=True)

        # 🧮 Totales
        total_ingresos = sum(r['monto'] for r in reportes if r['tipo'] == 'Ingreso')
        total_egresos = sum(r['monto'] for r in reportes if r['tipo'] == 'Egreso')
        saldo_final = total_ingresos - total_egresos

        resumen = {
            'total_ingresos': total_ingresos,
            'total_egresos': total_egresos,
            'saldo_final': saldo_final
        }

        # ------------------------------------------------------------
        # EXPORTAR PDF
        # ------------------------------------------------------------
        if exportar == 'pdf':
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            elements = []

            styles = getSampleStyleSheet()
            elements.append(Paragraph("<b>REPORTE FINANCIERO - NEOTOWER</b>", styles['Title']))
            elements.append(Spacer(1, 12))

            resumen_data = [
                ["Total Ingresos", f"{total_ingresos:.2f} Bs"],
                ["Total Egresos", f"{total_egresos:.2f} Bs"],
                ["Saldo Final", f"{saldo_final:.2f} Bs"]
            ]
            resumen_table = Table(resumen_data, colWidths=[150, 150])
            resumen_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER')
            ]))
            elements.append(resumen_table)
            elements.append(Spacer(1, 20))

            # Tabla de movimientos
            data = [["Fecha", "Tipo", "Descripción", "Monto (Bs.)"]]
            for r in reportes:
                data.append([
                    str(r['fecha']),
                    r['tipo'],
                    r['descripcion'],
                    f"{r['monto']:.2f}"
                ])

            table = Table(data, colWidths=[100, 80, 220, 100])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
            ]))
            elements.append(table)

            doc.build(elements)
            buffer.seek(0)
            return send_file(buffer, as_attachment=True,
                             download_name="reporte_financiero.pdf",
                             mimetype='application/pdf')

        # ------------------------------------------------------------
        # EXPORTAR EXCEL
        # ------------------------------------------------------------
        elif exportar == 'excel':
            df = pd.DataFrame(reportes)
            buffer = BytesIO()
            df.to_excel(buffer, index=False, sheet_name="Reporte Financiero")
            buffer.seek(0)
            return send_file(buffer, as_attachment=True,
                             download_name="reporte_financiero.xlsx",
                             mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

    except Exception as e:
        flash(f"❌ Error al generar reporte: {type(e).__name__} → {e}", "danger")
        reportes = []
        resumen = {'total_ingresos': 0, 'total_egresos': 0, 'saldo_final': 0}
    finally:
        cur.close()
        conn.close()

    # Modo normal (HTML)
    return render_template('administrador/reportes_financieros.html',
                           reportes=reportes, resumen=resumen)





@app.route('/usuario/estado_cuenta')
@login_required
def estado_cuenta():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT id_pago, fecha_pago, monto, estado, situacion, dias_retraso
            FROM vista_estado_cuenta
            WHERE id_usuario = %s
            ORDER BY fecha_pago DESC;
        """, (session['user_id'],))
        pagos = cur.fetchall()

        total_pendiente = sum(p['monto'] for p in pagos if p['estado'] == 'pendiente')
        total_pagado = sum(p['monto'] for p in pagos if p['estado'] == 'pagado')

    except Exception as e:
        flash(f"❌ Error al obtener estado de cuenta: {e}", "danger")
        pagos = []
        total_pendiente = total_pagado = 0
    finally:
        cur.close()
        conn.close()

    return render_template('usuario/estado_cuenta.html',
                           pagos=pagos,
                           total_pendiente=total_pendiente,
                           total_pagado=total_pagado)


@app.route('/administrador/morosidad')
@login_required
@role_required(['administrador'])
def morosidad():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT 
                id_usuario,
                residente,
                COUNT(*) FILTER (WHERE situacion = 'Moroso') AS total_morosidades,
                SUM(monto) FILTER (WHERE situacion = 'Moroso') AS deuda_total,
                MAX(dias_retraso) AS max_dias_retraso
            FROM vista_estado_cuenta
            GROUP BY id_usuario, residente
            HAVING COUNT(*) FILTER (WHERE situacion = 'Moroso') > 0
            ORDER BY deuda_total DESC;
        """)
        morosos = cur.fetchall()
    except Exception as e:
        flash(f"❌ Error al obtener morosidad: {e}", "danger")
        morosos = []
    finally:
        cur.close()
        conn.close()

    return render_template('administrador/morosidad.html', morosos=morosos)





@app.route('/admin/pago_personal/guardar', methods=['POST'])
@login_required
@role_required(['administrador'])
def guardar_pago_personal():
    id_personal = request.form.get('id_personal')
    monto = float(request.form.get('monto'))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO pago_personal (id_personal, fecha, monto)
            VALUES (%s, CURRENT_DATE, %s)
        """, (id_personal, monto))
        conn.commit()

        # 🔥 Registrar egreso automático
        actualizar_reporte_financiero(monto, 'egreso')

        flash('Pago al personal registrado y reflejado en el reporte financiero ✅', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al registrar pago: {e}', 'danger')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('gestion_personal'))




# --------------------------
# CONSUMO
# --------------------------
@app.route('/usuario/consumo')
@login_required
def consumo():
    consumo_actual = {
        'agua': 15.5,
        'electricidad': 320,
        'gas': 8.2,
        'fecha': datetime.now().strftime('%Y-%m-%d')
    }
    historial = [
        {'fecha': '2025-08-01', 'agua': 12.3, 'electricidad': 280, 'gas': 7.1},
        {'fecha': '2025-07-01', 'agua': 13.0, 'electricidad': 295, 'gas': 7.5},
    ]
    return render_template('usuario/consumo.html',
                           consumo_actual=consumo_actual,
                           historial=historial)

@app.route('/usuario/historico_consumo')
@login_required
def historico_consumo():
    datos_historicos = [
        {'fecha': '2025-01', 'agua': 15.5, 'electricidad': 320, 'gas': 8.2, 'alerta': False},
        {'fecha': '2024-12', 'agua': 14.2, 'electricidad': 295, 'gas': 7.8, 'alerta': True},
        {'fecha': '2024-11', 'agua': 13.8, 'electricidad': 280, 'gas': 7.5, 'alerta': False},
    ]
    fecha_fin_default = datetime.now().strftime('%Y-%m')
    fecha_inicio_default = (datetime.now() - timedelta(days=365)).strftime('%Y-%m')
    return render_template('usuario/historico_consumo.html',
                           historial=datos_historicos,
                           fecha_inicio_default=fecha_inicio_default,
                           fecha_fin_default=fecha_fin_default)



# --------------------------
# LISTAR RESERVAS (solo del usuario logueado)
# --------------------------
@app.route('/usuario/reservas')
@login_required
def reservas():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("""
            SELECT id_reserva, tipo, descripcion, estado,
                   fecha_inicio, horario,
                   numero_personas, costo_reserva
            FROM reserva
            WHERE id_usuario = %s
            ORDER BY fecha_inicio DESC
        """, (session['user_id'],))
        reservas = cur.fetchall()

        # badge por estado (para tu template)
        for r in reservas:
            estado = (r.get('estado') or '').lower()
            r['estado_badge'] = (
                'warning text-dark' if estado == 'pendiente' else
                'success'           if estado == 'confirmada' else
                'danger'            if estado == 'cancelada'  else
                'secondary'
            )
    except Exception as e:
        flash(f"Error cargando reservas: {e}", "danger")
        reservas = []
    finally:
        cur.close()
        conn.close()

    return render_template('usuario/reservas.html', reservas=reservas)


# --------------------------
# FORMULARIO NUEVA RESERVA (solo GET, no usa MFA)
# --------------------------
@app.route('/usuario/reservas/nueva', methods=['GET'])
@login_required
def nueva_reserva():
    return render_template('usuario/formulario_reserva.html')


# --------------------------
# GUARDAR RESERVA (inserta con id_usuario, no usa MFA)
# --------------------------
@app.route('/usuario/reservas/guardar', methods=['POST'])
@login_required
def guardar_reserva():
    user_id = session['user_id']
    tipo = request.form.get('tipo')
    descripcion = request.form.get('descripcion')
    fecha_inicio = request.form.get('fecha_inicio')
    horario = request.form.get('horario')
    numero_personas = request.form.get('numero_personas') or 1
    costo_reserva = request.form.get('costo_reserva') or 0

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("""
            INSERT INTO reserva (
                id_usuario, tipo, descripcion, estado,
                fecha_inicio, horario, numero_personas, costo_reserva
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id_reserva
        """, (
            user_id,
            tipo,
            descripcion,
            'pendiente',
            fecha_inicio,
            horario,
            numero_personas,
            costo_reserva
        ))

        nueva_id = cur.fetchone()['id_reserva']
        conn.commit()
        flash('✅ Reserva creada con éxito. Está pendiente de confirmación.', 'success')
        return redirect(url_for('detalle_reserva', id_reserva=nueva_id))

    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al crear la reserva: {e}", "danger")
        return redirect(url_for('nueva_reserva'))
    finally:
        cur.close()
        conn.close()


@app.route('/usuario/reservas/<int:id_reserva>')
@login_required
def detalle_reserva(id_reserva):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("""
            SELECT id_reserva, id_usuario, tipo, descripcion, estado,
                   fecha_inicio, horario, numero_personas, costo_reserva
            FROM reserva
            WHERE id_reserva = %s
        """, (id_reserva,))
        reserva = cur.fetchone()

        if not reserva or reserva['id_usuario'] != session['user_id']:
            flash("Reserva no encontrada", "warning")
            return redirect(url_for('reservas'))

        # 👇 prevenir error si el template aún espera fecha_fin
        reserva['fecha_fin'] = reserva.get('fecha_inicio')

        return render_template('usuario/detalle_reserva.html', reserva=reserva)
    except Exception as e:
        flash(f"Error cargando reserva: {e}", "danger")
        return redirect(url_for('reservas'))
    finally:
        cur.close()
        conn.close()

# --------------------------
# ELIMINAR RESERVA
# --------------------------
@app.route('/usuario/reservas/<int:id_reserva>/eliminar', methods=['POST'])
@login_required
def eliminar_reserva(id_reserva):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Eliminar la reserva solo si pertenece al usuario actual
        cur.execute("""
            DELETE FROM reserva 
            WHERE id_reserva = %s AND id_usuario = %s
            RETURNING id_reserva
        """, (id_reserva, session['user_id']))
        
        eliminado = cur.fetchone()
        conn.commit()

        if eliminado:
            flash(f"✅ Reserva #{id_reserva} eliminada correctamente", "success")
        else:
            flash("⚠️ No puedes eliminar esta reserva (no existe o no es tuya).", "warning")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al eliminar la reserva: {e}", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('reservas'))

# --------------------------
# CANCELAR RESERVA (para el fetch POST del template)
# --------------------------
@app.route('/usuario/reservas/<int:id_reserva>/cancelar', methods=['POST'])
@login_required
def cancelar_reserva(id_reserva):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("""
            UPDATE reserva
            SET estado = 'cancelada'
            WHERE id_reserva = %s AND id_usuario = %s
            RETURNING id_reserva
        """, (id_reserva, session['user_id']))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return jsonify({"success": False, "message": "Reserva no encontrada"}), 404
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cur.close()
        conn.close()


    
 # --------------------------
# ENTREGAR AMBIENTE
# --------------------------
@app.route('/usuario/reservas/<int:id_reserva>/entregar', methods=['POST'])
@login_required
def entregar_ambiente(id_reserva):
    comentario = request.form.get('comentario')
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE reserva 
            SET estado = 'entregado', 
                descripcion = COALESCE(descripcion, '') || ' | Entregado: ' || %s
            WHERE id_reserva = %s
        """, (comentario, id_reserva))
        conn.commit()
        flash("✅ Entrega registrada correctamente.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al entregar el ambiente: {e}", "danger")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('detalle_reserva', id_reserva=id_reserva))


# --------------------------
# GENERAR FACTURA CON QR
# --------------------------
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import send_file, flash, redirect, url_for
from io import BytesIO
import qrcode
import os
from PIL import Image

# --------------------------
# GESTIÓN DE RESERVAS (ADMIN)
# --------------------------
@app.route('/admin/reservas')
@role_required(['administrador'])
def gestion_reservas():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("""
    SELECT r.id_reserva,
           r.tipo,
           r.descripcion,
           r.estado,
           r.fecha_inicio,
           r.horario,
           r.numero_personas,
           r.costo_reserva,
           (u.nombre || ' ' || u.apellido) AS residente
    FROM reserva r
    JOIN usuario u ON r.id_usuario = u.id_usuario
    ORDER BY r.id_reserva DESC;
""")

        reservas = cur.fetchall()

        # Badge (color por estado)
        for r in reservas:
            estado = (r.get('estado') or '').lower()
            r['estado_badge'] = (
                'warning text-dark' if estado == 'pendiente' else
                'success' if estado == 'confirmada' else
                'danger' if estado == 'cancelada' else
                'secondary'
            )

    except Exception as e:
        flash(f"❌ Error al cargar las reservas: {e}", "danger")
        reservas = []
    finally:
        cur.close()
        conn.close()

    return render_template('administrador/gestion_reservas.html', reservas=reservas)
# --------------------------
# APROBAR RESERVA (ADMIN)
# --------------------------
@app.route('/admin/reservas/<int:id_reserva>/aprobar', methods=['POST'])
@role_required(['administrador'])
def admin_aprobar_reserva(id_reserva):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE reserva SET estado = 'confirmada'
            WHERE id_reserva = %s
        """, (id_reserva,))
        conn.commit()
        flash("✅ Reserva aprobada correctamente.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al aprobar la reserva: {e}", "danger")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('gestion_reservas'))


# --------------------------
# RECHAZAR RESERVA (ADMIN)
# --------------------------
@app.route('/admin/reservas/<int:id_reserva>/rechazar', methods=['POST'])
@role_required(['administrador'])
def admin_rechazar_reserva(id_reserva):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE reserva SET estado = 'cancelada'
            WHERE id_reserva = %s
        """, (id_reserva,))
        conn.commit()
        flash("🚫 Reserva rechazada correctamente.", "danger")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al rechazar la reserva: {e}", "danger")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('gestion_reservas'))


# --------------------------
# ACEPTAR CANCELACIÓN (ADMIN)
# --------------------------
@app.route('/admin/reservas/<int:id_reserva>/aceptar_cancelacion', methods=['POST'])
@role_required(['administrador'])
def admin_aceptar_cancelacion(id_reserva):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE reserva SET estado = 'cancelada'
            WHERE id_reserva = %s
        """, (id_reserva,))
        conn.commit()
        flash("⚠️ Cancelación aceptada correctamente.", "warning")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al aceptar cancelación: {e}", "danger")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('gestion_reservas'))

# --------------------------
# DETALLE DE RESERVA (ADMIN)
# --------------------------
@app.route('/admin/reservas/<int:id_reserva>')
@role_required(['administrador'])
def detalle_reserva_admin(id_reserva):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("""
            SELECT r.id_reserva, r.tipo, r.descripcion, r.estado,
                   r.fecha_inicio, r.horario, r.numero_personas, r.costo_reserva,
                   (u.nombre || ' ' || u.apellido) AS residente, u.email
            FROM reserva r
            JOIN usuario u ON r.id_usuario = u.id_usuario
            WHERE r.id_reserva = %s
        """, (id_reserva,))
        reserva = cur.fetchone()
        if not reserva:
            flash("⚠️ Reserva no encontrada.", "warning")
            return redirect(url_for('gestion_reservas'))
        return render_template('administrador/detalle_reserva_admin.html', reserva=reserva)
    except Exception as e:
        flash(f"❌ Error cargando detalle: {e}", "danger")
        return redirect(url_for('gestion_reservas'))
    finally:
        cur.close()
        conn.close()





@app.route('/perfil/actualizar', methods=['POST'])
@login_required
def actualizar_perfil():
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        nombre = request.form['nombre'].strip()
        apellido = request.form['apellido'].strip()
        telefono = request.form['telefono'].strip()

        # actualizar usuario
        cur.execute("""
            UPDATE usuario
            SET nombre = %s, apellido = %s
            WHERE id_usuario = %s
        """, (nombre, apellido, session['user_id']))

        # actualizar residente
        cur.execute("""
            UPDATE residente
            SET telefono = %s
            WHERE id_usuario = %s
        """, (telefono, session['user_id']))

        conn.commit()
        flash("Perfil actualizado correctamente ✅", "success")

    except Exception as e:
        conn.rollback()
        flash("Error al actualizar perfil: " + str(e), "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('usuario_perfil'))





@app.route('/admin/residentes')
@login_required
@role_required(['administrador'])
def gestion_residentes():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Obtener lista de residentes
        cur.execute("""
            SELECT r.id_residente,
                   r.nombre,
                   r.apellido,
                   r.email,
                   r.telefono,
                   r.fecha_registro,
                   r.estado,
                   u.rol,
                   CASE 
                       WHEN u.rol = 'propietario' THEN TRUE
                       ELSE FALSE
                   END AS es_propietario
            FROM residente r
            LEFT JOIN usuario u ON r.id_usuario = u.id_usuario
            ORDER BY r.fecha_registro DESC;
        """)
        residentes = cur.fetchall()

        # Estadísticas
        total_residentes = len(residentes)
        activos = sum(1 for r in residentes if r["estado"] == "activo")
        con_deudas = 0  # si no tienes tabla de pagos
        nuevos_mes = sum(
            1 for r in residentes
            if isinstance(r["fecha_registro"], date) and r["fecha_registro"].month == date.today().month
        )

        estadisticas = {
            "total_residentes": total_residentes,
            "residentes_activos": activos,
            "con_deudas": con_deudas,
            "nuevos_mes": nuevos_mes
        }

        # Departamentos
        cur.execute("SELECT id_depto, piso, numero, estado FROM departamento ORDER BY piso, numero")
        departamentos = cur.fetchall()

        return render_template(
            "administrador/gestion_residentes.html",
            residentes=residentes,
            estadisticas=estadisticas,
            departamentos=departamentos
        )

    except Exception as e:
        flash(f"Error cargando residentes: {e}", "danger")
        return render_template("administrador/gestion_residentes.html",
                               residentes=[], estadisticas={}, departamentos=[])
    finally:
        cur.close()
        conn.close()



@app.route('/admin/residente/<int:id_residente>')
@login_required
@role_required(['administrador'])
def admin_perfil_residente(id_residente):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("""
            SELECT r.id_residente, r.telefono, r.fecha_registro,
                   u.nombre, u.apellido, u.email, u.rol
            FROM residente r
            JOIN usuario u ON r.id_usuario = u.id_usuario
            WHERE r.id_residente = %s
        """, (id_residente,))
        residente = cur.fetchone()

        if not residente:
            flash("Residente no encontrado", "warning")
            return redirect(url_for('gestion_residentes'))

        # Departamentos asociados
        cur.execute("""
            SELECT d.numero, d.piso, d.estado
            FROM relacion_residente_departamento rrd
            JOIN departamento d ON d.id_depto = rrd.id_depto
            WHERE rrd.id_residente = %s
        """, (id_residente,))
        departamentos = cur.fetchall()

        return render_template(
            'administrador/perfil_residente.html',
            residente=residente,
            departamentos=departamentos
        )
    except Exception as e:
        flash(f"Error cargando perfil: {e}", "danger")
        return redirect(url_for('gestion_residentes'))
    finally:
        cur.close()
        conn.close()



@app.route('/admin/residentes/<int:id_residente>/editar')
@login_required
@role_required(['administrador'])
def admin_editar_residente(id_residente):
    # Por ahora solo redirige o muestra un placeholder
    flash(f"Editar residente {id_residente} en construcción", "info")
    return redirect(url_for('gestion_residentes'))

@app.route('/admin/residentes/<int:id_residente>/historial')
@login_required
@role_required(['administrador'])
def admin_historial_residente(id_residente):
    flash(f"Historial de residente {id_residente} en construcción", "info")
    return redirect(url_for('gestion_residentes'))




@app.route('/admin/residentes/<int:id_residente>/estado/<nuevo_estado>')
@login_required
@role_required(['administrador'])
def admin_cambiar_estado_residente(id_residente, nuevo_estado):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE residente SET estado = %s WHERE id_residente = %s",
                    (nuevo_estado, id_residente))
        conn.commit()
        flash(f"Estado del residente {id_residente} cambiado a {nuevo_estado}", "success")
    except Exception as e:
        flash(f"Error cambiando estado: {e}", "danger")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('gestion_residentes'))



# --------------------------
# REPORTES DE AUDITORÍA (ADMIN)
# --------------------------
@app.route('/admin/auditoria')
@login_required
@role_required(['administrador'])
def reportes_auditoria():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        fecha_inicio = request.args.get("fecha_inicio")
        fecha_fin = request.args.get("fecha_fin")
        usuario = request.args.get("usuario")  # ⚠️ tu tabla actual no tiene usuario directo

        query = """
                SELECT a.id_auditoria,
                    a.fecha_auditoria AS fecha,
                    a.resultado,
                    e.tipo AS accion,
                    'Evento de seguridad' AS detalle
                FROM auditoria a
                LEFT JOIN evento_seguridad e ON a.id_evento = e.id_evento
                WHERE 1=1
            """
        params = []

        if fecha_inicio:
            query += " AND a.fecha_auditoria >= %s"
            params.append(fecha_inicio)
        if fecha_fin:
            query += " AND a.fecha_auditoria <= %s"
            params.append(fecha_fin)

        query += " ORDER BY a.fecha_auditoria DESC"

        cur.execute(query, tuple(params))
        auditoria = cur.fetchall()

        return render_template("administrador/reportes_auditoria.html", auditoria=auditoria)

    except Exception as e:
        flash(f"Error cargando auditoría: {e}", "danger")
        return render_template("administrador/reportes_auditoria.html", auditoria=[])
    finally:
        cur.close()
        conn.close()


# --------------------------
# --------------------------
# CONFIGURACIONES (ADMIN)
# --------------------------
@app.route('/admin/configuraciones')
@login_required
@role_required(['administrador'])
def configuraciones():
    # Datos ficticios por ahora
    settings = {
        'version': '1.0',
        'nombre_sistema': 'NEOTOWER',
        'soporte_email': 'soporte@neotower.com'
    }
    return render_template('administrador/configuraciones.html', settings=settings)


# --------------------------
# FACTURAS (ADMIN)
# --------------------------
@app.route('/admin/facturas')
@login_required
@role_required(['administrador'])
def facturas():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM factura ORDER BY fecha_emision DESC;")
    facturas = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('administrador/facturas.html', facturas=facturas)




@app.route('/admin/facturas/nueva', methods=['GET', 'POST'])
@login_required
@role_required(['administrador'])
def nueva_factura():
    if request.method == 'POST':
        id_residente = request.form.get('id_residente')
        monto_total = request.form.get('monto_total')
        descripcion = request.form.get('descripcion')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO factura (id_residente, monto_total, descripcion, fecha_emision, estado)
            VALUES (%s, %s, %s, %s, 'pendiente');
        """, (id_residente, monto_total, descripcion, datetime.now()))
        conn.commit()
        cur.close()
        conn.close()

        flash('✅ Factura creada exitosamente.', 'success')
        return redirect(url_for('facturas'))
    return render_template('administrador/nueva_factura.html')



@app.route('/admin/facturas/<int:id_factura>')
@login_required
@role_required(['administrador'])
def ver_factura(id_factura):
    """Ver detalle de una factura"""
    factura = {"id_factura": id_factura, "fecha": datetime.now().date(),
               "monto": 500.00, "estado": "Pendiente", "residente": "Dummy"}
    return render_template('administrador/ver_factura.html', factura=factura)


@app.route('/admin/facturas/<int:id_factura>/editar')
@login_required
@role_required(['administrador'])
def editar_factura(id_factura):
    """Editar factura existente"""
    factura = {"id_factura": id_factura, "fecha": datetime.now().date(),
               "monto": 500.00, "estado": "Pendiente", "residente": "Dummy"}
    return render_template('administrador/editar_factura.html', factura=factura)


@app.route('/admin/facturas/<int:id_factura>/eliminar')
@login_required
@role_required(['administrador'])
def eliminar_factura(id_factura):
    """Eliminar factura"""
    flash(f"Factura #{id_factura} eliminada correctamente ✅", "success")
    return redirect(url_for('facturas'))

# --------------------------
# GESTIÓN DE PERSONAL (ADMIN) en tiempo real
# --------------------------
@app.route('/administrador/personal')
def gestion_personal():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            p.id_personal, 
            p.nombre, 
            p.cargo, 
            p.salario,
            (
                SELECT MAX(pp.fecha) 
                FROM pago_personal pp 
                WHERE pp.id_personal = p.id_personal
            ) AS ultimo_pago
        FROM personal p
        ORDER BY p.id_personal;
    """)

    personal = []

    filas = cur.fetchall()
    for r in filas:
        # detectar si r es tupla o diccionario
        if isinstance(r, dict):
            id_personal = r.get('id_personal')
            nombre = r.get('nombre')
            cargo = r.get('cargo')
            salario = r.get('salario')
            ultimo_pago_raw = r.get('ultimo_pago')
        else:
            id_personal = r[0]
            nombre = r[1]
            cargo = r[2]
            salario = r[3]
            ultimo_pago_raw = r[4] if len(r) > 4 else None

        # formatear fecha
        if ultimo_pago_raw:
            try:
                fecha = ultimo_pago_raw.strftime('%d/%m/%Y')
            except Exception:
                fecha = str(ultimo_pago_raw)
        else:
            fecha = "Sin pagos"

        personal.append({
            "id_personal": id_personal,
            "nombre": nombre,
            "cargo": cargo,
            "salario": salario,
            "ultimo_pago": fecha
        })

    cur.close()
    conn.close()

    return render_template('administrador/personal.html', personal=personal)





@app.route('/administrador/personal/nuevo', methods=['GET', 'POST'])
@login_required
@role_required(['administrador'])
def nuevo_personal():
    """Crear nuevo personal"""
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        cargo = request.form.get('cargo')
        salario = request.form.get('salario')

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO personal (nombre, cargo, salario) VALUES (%s, %s, %s)",
                (nombre, cargo, salario)
            )
            conn.commit()
            flash("✅ Personal agregado correctamente", "success")
            return redirect(url_for('gestion_personal'))
        except Exception as e:
            conn.rollback()
            flash(f"❌ Error al agregar personal: {e}", "danger")
        finally:
            cur.close()
            conn.close()

    return render_template("administrador/nuevo_personal.html")


@app.route('/administrador/personal/<int:id_personal>')
@login_required
@role_required(['administrador'])
def ver_personal(id_personal):
    """Ver detalle de un personal"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT * FROM personal WHERE id_personal = %s", (id_personal,))
        persona = cur.fetchone()
        if not persona:
            flash("Personal no encontrado", "warning")
            return redirect(url_for("gestion_personal"))
    except Exception as e:
        flash(f"Error al cargar personal: {e}", "danger")
        persona = None
    finally:
        cur.close()
        conn.close()

    return render_template("administrador/ver_personal.html", persona=persona)


@app.route('/administrador/personal/<int:id_personal>/editar', methods=['GET', 'POST'])
@login_required
@role_required(['administrador'])
def editar_personal(id_personal):
    """Editar datos de un personal"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        cargo = request.form.get('cargo')
        salario = request.form.get('salario')
        try:
            cur.execute(
                "UPDATE personal SET nombre=%s, cargo=%s, salario=%s WHERE id_personal=%s",
                (nombre, cargo, salario, id_personal)
            )
            conn.commit()
            flash("✏️ Personal actualizado correctamente", "success")
            return redirect(url_for("gestion_personal"))
        except Exception as e:
            conn.rollback()
            flash(f"❌ Error al actualizar personal: {e}", "danger")
    else:
        cur.execute("SELECT * FROM personal WHERE id_personal=%s", (id_personal,))
        persona = cur.fetchone()
        if not persona:
            flash("Personal no encontrado", "warning")
            return redirect(url_for("gestion_personal"))

    cur.close()
    conn.close()
    return render_template("administrador/editar_personal.html", persona=persona)


@app.route('/administrador/personal/<int:id_personal>/eliminar')
@login_required
@role_required(['administrador'])
def eliminar_personal(id_personal):
    """Eliminar personal"""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM personal WHERE id_personal=%s", (id_personal,))
        conn.commit()
        flash(f"🗑️ Personal #{id_personal} eliminado correctamente", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al eliminar personal: {e}", "danger")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for("gestion_personal"))



# --------------------------
# GESTIÓN DE CONSUMOS (ADMIN)
# --------------------------
@app.route('/administrador/consumos', endpoint="gestion_consumos")
@login_required
@role_required(['administrador'])
def gestion_consumos():
    """Listado de consumos"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("""
            SELECT c.id_consumo, c.tipo, c.alerta,
                   hc.fecha_lectura,
                   hc.consumo_agua, hc.consumo_electricidad, hc.consumo_gas
            FROM consumo c
            LEFT JOIN histo_consumo hc ON hc.id_consumo = c.id_consumo
            ORDER BY hc.fecha_lectura DESC NULLS LAST
        """)
        consumos = cur.fetchall()
    except Exception as e:
        flash(f"Error al cargar consumos: {e}", "danger")
        consumos = []
    finally:
        cur.close()
        conn.close()

    return render_template("administrador/consumos.html", consumos=consumos)


@app.route('/administrador/consumos/nuevo', methods=['POST'])
@login_required
@role_required(['administrador'])
def nuevo_consumo():
    tipo = request.form.get("tipo")  # agua, luz, gas
    alerta = request.form.get("alerta") == "on"  # checkbox opcional

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO consumo (tipo, alerta)
            VALUES (%s, %s)
        """, (tipo, alerta))
        conn.commit()
        flash("✅ Consumo registrado correctamente", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al registrar consumo: {e}", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("gestion_consumos"))


@app.route('/administrador/consumos/<int:id_consumo>/eliminar')
@login_required
@role_required(['administrador'])
def eliminar_consumo(id_consumo):
    """Eliminar un consumo"""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM consumo WHERE id_consumo = %s", (id_consumo,))
        conn.commit()
        flash("🗑️ Consumo eliminado correctamente", "info")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al eliminar consumo: {e}", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("gestion_consumos"))



# --------------------------
# GESTIÓN DE PAGOS (ADMIN)
# --------------------------
@app.route('/administrador/pagos')
@login_required
@role_required(['administrador'])
def gestion_pagos():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)  # Devuelve diccionarios

    try:
        # 🔹 1️⃣ Obtener lista de residentes con estado de pago
        cur.execute("""
            SELECT 
                u.id_usuario,
                CONCAT(u.nombre, ' ', u.apellido) AS nombre_completo,
                COALESCE(d.numero, 'N/A') AS departamento,
                COALESCE(TO_CHAR(MAX(p.fecha), 'DD/MM/YYYY'), 'Sin pagos') AS ultimo_pago,
                CASE
                    WHEN COUNT(p.id_pago) = 0 THEN 'Sin pagos'
                    WHEN BOOL_OR(p.estado = 'pendiente') THEN 'Pendiente'
                    ELSE 'Pagado'
                END AS estado
            FROM usuario u
            JOIN residente r ON r.id_usuario = u.id_usuario
            LEFT JOIN departamento d ON d.id_residente = r.id_residente
            LEFT JOIN relacion_usuario_pago rup ON rup.id_usuario = u.id_usuario
            LEFT JOIN pago p ON p.id_pago = rup.id_pago
            WHERE u.rol = 'residente'
            GROUP BY u.id_usuario, nombre_completo, d.numero
            ORDER BY u.id_usuario;
        """)
        residentes = [
            {
                'id_usuario': row['id_usuario'],
                'nombre': row['nombre_completo'],
                'departamento': row['departamento'],
                'ultimo_pago': row['ultimo_pago'],
                'estado': row['estado']
            }
            for row in cur.fetchall()
        ]

        # 🔹 2️⃣ Obtener todos los pagos existentes
        cur.execute("""
            SELECT id_pago, monto, tipo, estado, fecha
            FROM pago
            ORDER BY fecha DESC;
        """)
        pagos = cur.fetchall()

        # 🔹 3️⃣ Obtener morosidad desde la vista
        cur.execute("""
            SELECT 
                id_usuario,
                residente,
                COUNT(*) FILTER (WHERE situacion = 'Moroso') AS total_morosidades,
                SUM(monto) FILTER (WHERE situacion = 'Moroso') AS deuda_total,
                MAX(dias_retraso) AS max_dias_retraso
            FROM vista_estado_cuenta
            GROUP BY id_usuario, residente
            HAVING COUNT(*) FILTER (WHERE situacion = 'Moroso') > 0
            ORDER BY deuda_total DESC;
        """)
        morosos = cur.fetchall()

        total_morosos = len(morosos)
        total_deuda = sum(m['deuda_total'] or 0 for m in morosos)

    except Exception as e:
        conn.rollback()
        flash(f"❌ Error cargando pagos: {type(e).__name__} → {e}", "danger")
        residentes, pagos, morosos = [], [], []
        total_morosos = total_deuda = 0
    finally:
        cur.close()
        conn.close()

    print("✅ Total residentes mostrados:", len(residentes))
    return render_template(
        "administrador/pagos.html",
        residentes=residentes,
        pagos=pagos,
        morosos=morosos,
        total_morosos=total_morosos,
        total_deuda=total_deuda
    )


@app.route('/administrador/pagos/nuevo', methods=["POST"])
@login_required
@role_required(['administrador'])
def nuevo_pago():
    monto = request.form.get("monto")
    tipo = request.form.get("tipo")
    estado = request.form.get("estado")
    fecha = request.form.get("fecha")

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO pago (monto, tipo, estado, fecha)
            VALUES (%s, %s, %s, %s)
        """, (monto, tipo, estado, fecha))
        conn.commit()
        flash("✅ Pago registrado correctamente", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al registrar pago: {e}", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("gestion_pagos"))


@app.route('/administrador/pagos/<int:id_pago>/eliminar')
@login_required
@role_required(['administrador'])
def eliminar_pago(id_pago):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM pago WHERE id_pago = %s", (id_pago,))
        conn.commit()
        flash("🗑️ Pago eliminado correctamente", "info")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al eliminar pago: {e}", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("gestion_pagos"))


# --------------------------
# ADMIN - Crear Residente
# --------------------------
@app.route('/admin/residentes/crear', methods=['POST'])
@login_required
@role_required(['administrador'])
def admin_crear_residente():
    data = request.form

    nombre = data.get('nombre')
    apellido = data.get('apellido')
    email = data.get('email')
    telefono = data.get('telefono')
    password = data.get('password')
    tipo_residente = data.get('tipo_residente')
    departamentos = request.form.getlist('departamentos')

    if not nombre or not apellido or not email or not password:
        return jsonify({'success': False, 'message': 'Faltan datos obligatorios'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Verificar si el email ya existe
        cur.execute("SELECT id_usuario FROM usuario WHERE email = %s", (email,))
        if cur.fetchone():
            return jsonify({'success': False, 'message': 'El email ya está registrado'}), 400

        # Crear usuario
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cur.execute("""
            INSERT INTO usuario (rol, nombre, apellido, email, password)
            VALUES (%s, %s, %s, %s, %s) RETURNING id_usuario
        """, ('residente', nombre, apellido, email, hashed_password))
        id_usuario = cur.fetchone()['id_usuario']

        # Crear residente
        cur.execute("""
            INSERT INTO residente (id_usuario, nombre, apellido, email, telefono, fecha_registro)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id_residente
        """, (id_usuario, nombre, apellido, email, telefono, datetime.now()))
        id_residente = cur.fetchone()['id_residente']

        # Asignar departamentos
        for depto_id in departamentos:
            cur.execute("""
                INSERT INTO residente_departamento (id_residente, id_depto)
                VALUES (%s, %s)
            """, (id_residente, depto_id))

        conn.commit()
        return jsonify({'success': True, 'message': 'Residente creado con éxito'})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# --------------------------
# ADMIN - Gestión Departamentos
# --------------------------
@app.route('/admin/departamentos')
@login_required
@role_required(['administrador'])
def gestion_departamentos():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id_depto, piso, numero, estado FROM departamento ORDER BY piso, numero")
    departamentos = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('administrador/gestion_departamentos.html', departamentos=departamentos)


@app.route('/admin/departamentos/crear', methods=['POST'])
@login_required
@role_required(['administrador'])
def crear_departamento():
    piso = request.form.get('piso')
    numero = request.form.get('numero')
    estado = request.form.get('estado', 'disponible')

    if not piso or not numero:
        flash('⚠️ Faltan datos: Piso y número son obligatorios.', 'warning')
        return redirect(url_for('gestion_departamentos'))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO departamento (piso, numero, estado)
            VALUES (%s, %s, %s)
        """, (piso, numero, estado))
        conn.commit()
        flash('✅ Departamento creado correctamente.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'❌ Error al crear departamento: {e}', 'danger')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('gestion_departamentos'))



@app.route('/admin/departamentos/<int:id_depto>/editar', methods=['GET', 'POST'])
@login_required
@role_required(['administrador'])
def editar_departamento(id_depto):
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        piso = request.form.get('piso')
        numero = request.form.get('numero')
        estado = request.form.get('estado')
        cur.execute("""
            UPDATE departamento
            SET piso = %s, numero = %s, estado = %s
            WHERE id_depto = %s
        """, (piso, numero, estado, id_depto))
        conn.commit()
        cur.close()
        conn.close()
        flash('Departamento actualizado', 'success')
        return redirect(url_for('gestion_departamentos'))
    else:
        cur.execute("SELECT * FROM departamento WHERE id_depto = %s", (id_depto,))
        depto = cur.fetchone()
        cur.close()
        conn.close()
        return render_template('administrador/editar_departamento.html', depto=depto)


@app.route('/admin/departamentos/<int:id_depto>/eliminar')
@login_required
@role_required(['administrador'])
def eliminar_departamento(id_depto):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM departamento WHERE id_depto = %s", (id_depto,))
        conn.commit()
        flash('Departamento eliminado', 'info')
    except Exception as e:
        conn.rollback()
        flash(f'Error: {e}', 'danger')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('gestion_departamentos'))



# --------------------------
# GESTIÓN DE ACCESOS (Admin)
# --------------------------
@app.route('/admin/accesos')
@login_required
@role_required(['administrador'])
def gestion_accesos():
    conn = get_db_connection()
    cur = conn.cursor()
    accesos = []
    try:
        cur.execute("""
            SELECT a.id_acceso, a.tipo, a.fecha, a.estado,
                   r.nombre || ' ' || r.apellido AS residente
            FROM acceso a
            LEFT JOIN residente r ON a.id_residente = r.id_residente
            ORDER BY a.fecha DESC
        """)
        accesos = cur.fetchall()
    except Exception as e:
        flash("Error cargando accesos: " + str(e), "danger")
    finally:
        cur.close()
        conn.close()

    return render_template("administrador/gestion_accesos.html", accesos=accesos)


@app.route('/admin/accesos/nuevo', methods=['GET', 'POST'])
@login_required
@role_required(['administrador'])
def crear_acceso():
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        id_residente = request.form['id_residente']
        tipo = request.form['tipo']
        estado = request.form['estado']

        try:
            cur.execute("""
                INSERT INTO acceso (id_residente, tipo, estado)
                VALUES (%s, %s, %s)
            """, (id_residente, tipo, estado))
            conn.commit()
            flash("✅ Acceso creado correctamente", "success")
            return redirect(url_for('gestion_accesos'))
        except Exception as e:
            conn.rollback()
            flash("❌ Error al crear acceso: " + str(e), "danger")
    # Cargar residentes
    cur.execute("SELECT id_residente, nombre, apellido FROM residente ORDER BY nombre")
    residentes = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("administrador/crear_acceso.html", residentes=residentes)


@app.route('/admin/accesos/<int:id_acceso>/editar', methods=['GET', 'POST'])
@login_required
@role_required(['administrador'])
def editar_acceso(id_acceso):
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        tipo = request.form['tipo']
        estado = request.form['estado']
        try:
            cur.execute("""
                UPDATE acceso SET tipo = %s, estado = %s WHERE id_acceso = %s
            """, (tipo, estado, id_acceso))
            conn.commit()
            flash("✏️ Acceso actualizado correctamente", "success")
            return redirect(url_for('gestion_accesos'))
        except Exception as e:
            conn.rollback()
            flash("❌ Error al editar acceso: " + str(e), "danger")

    cur.execute("SELECT * FROM acceso WHERE id_acceso = %s", (id_acceso,))
    acceso = cur.fetchone()
    cur.close()
    conn.close()
    return render_template("administrador/editar_acceso.html", acceso=acceso)


@app.route('/admin/accesos/<int:id_acceso>/eliminar')
@login_required
@role_required(['administrador'])
def eliminar_acceso(id_acceso):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM acceso WHERE id_acceso = %s", (id_acceso,))
        conn.commit()
        flash("🗑️ Acceso eliminado correctamente", "info")
    except Exception as e:
        conn.rollback()
        flash("❌ Error al eliminar acceso: " + str(e), "danger")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('gestion_accesos'))


#----------------------RUS Y MARTINEZ--------------------------------------------
# --------------------------
# GESTIÓN DE INCIDENTES (ADMIN)
# --------------------------
@app.route('/admin/gestion_incidentes')
@role_required(['administrador'])
def gestion_incidentes():
    """Panel de mantenimiento y tickets para el administrador"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        # 🔸 Contadores de estados
        cur.execute("""
            SELECT 
                SUM(CASE WHEN estado = 'Abierto' THEN 1 ELSE 0 END) AS abiertos,
                SUM(CASE WHEN estado = 'En Progreso' THEN 1 ELSE 0 END) AS progreso,
                SUM(CASE WHEN estado = 'Cerrado' THEN 1 ELSE 0 END) AS cerrados
            FROM incidente;
        """)
        contadores = cur.fetchone() or {'abiertos': 0, 'progreso': 0, 'cerrados': 0}

        # 🔸 Tiempo promedio de cierre (en horas)
        cur.execute("""
            SELECT 
                ROUND(AVG(EXTRACT(EPOCH FROM (fecha_cierre - fecha_reporte)) / 3600)::numeric, 2)
                AS horas_promedio_cierre
            FROM incidente
            WHERE fecha_cierre IS NOT NULL;
        """)
        kpi = cur.fetchone() or {'horas_promedio_cierre': 0}

        # 🔸 Listar los 10 incidentes más recientes
        cur.execute("""
            SELECT 
                i.id_incidente,
                i.descripcion,
                i.fecha_reporte,
                i.estado,
                i.gravedad,
                p.nombre AS tecnico,
                r.id_residente,
                u.nombre || ' ' || u.apellido AS residente
            FROM incidente i
            LEFT JOIN personal p ON i.personal_asignado = p.id_personal
            LEFT JOIN residente r ON i.id_residente = r.id_residente
            LEFT JOIN usuario u ON r.id_usuario = u.id_usuario
            ORDER BY i.fecha_reporte DESC
            LIMIT 10;
        """)
        incidentes = cur.fetchall()

    except Exception as e:
        flash(f"❌ Error al cargar los incidentes: {e}", "danger")
        contadores, kpi, incidentes = {}, {}, []
    finally:
        cur.close()
        conn.close()

    return render_template(
        'administrador/gestion_incidentes.html',
        incidentes=incidentes,
        contadores=contadores,
        kpi=kpi
    )


@app.route('/admin/asignar_tecnico/<int:id_incidente>', methods=['GET', 'POST'])
@role_required(['administrador'])
def asignar_tecnico(id_incidente):
    """Asignar técnico a un incidente"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'POST':
        id_tecnico = request.form.get('id_tecnico')

        if not id_tecnico:
            flash("⚠️ Debes seleccionar un técnico.", "warning")
            return redirect(url_for('asignar_tecnico', id_incidente=id_incidente))

        try:
            cur.execute("""
                UPDATE incidente
                SET personal_asignado = %s, estado = 'En Progreso'
                WHERE id_incidente = %s;
            """, (id_tecnico, id_incidente))
            conn.commit()
            flash("👷 Técnico asignado correctamente.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"❌ Error al asignar técnico: {e}", "danger")
        finally:
            cur.close()
            conn.close()

        return redirect(url_for('gestion_incidentes'))

    # -------------------------
    # Obtener lista de técnicos
    # -------------------------
    cur.execute("""
        SELECT id_personal, nombre, cargo
        FROM personal
        WHERE LOWER(cargo) LIKE 'tecnico%' 
           OR LOWER(cargo) LIKE 'técnico%'
           OR LOWER(cargo) LIKE 'mantenimiento%'
        ORDER BY nombre;
    """)
    tecnicos = cur.fetchall()
    cur.close()
    conn.close()

    if not tecnicos:
        flash("⚠️ No hay personal técnico registrado.", "warning")

    return render_template('administrador/asignar_tecnico.html',
                           id_incidente=id_incidente, tecnicos=tecnicos)



@app.route('/admin/incidente/<int:id_incidente>')
@role_required(['administrador'])
def ver_incidencia(id_incidente):
    """Ver detalles de un incidente"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT i.id_incidente, i.descripcion, i.fecha_reporte, i.fecha_cierre,
               i.estado, i.gravedad, i.evidencia, p.nombre AS tecnico
        FROM incidente i
        LEFT JOIN personal p ON i.personal_asignado = p.id_personal
        WHERE i.id_incidente = %s;
    """, (id_incidente,))
    incidencia = cur.fetchone()
    cur.close()
    conn.close()

    if not incidencia:
        flash("❌ No se encontró el ticket solicitado.", "danger")
        return redirect(url_for('gestion_incidentes'))

    return render_template('administrador/ver_incidencia.html', incidencia=incidencia)


@app.route('/admin/cerrar_incidencia/<int:id_incidente>')
@role_required(['administrador'])
def cerrar_incidencia(id_incidente):
    """Cerrar un incidente"""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE incidente
            SET estado = 'Cerrado', fecha_cierre = CURRENT_DATE
            WHERE id_incidente = %s;
        """, (id_incidente,))
        conn.commit()
        flash("✅ Ticket cerrado correctamente.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al cerrar el ticket: {e}", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('gestion_incidentes'))


@app.route('/admin/historial_tickets')
@role_required(['administrador'])
def admin_historial_tickets():
    """Historial completo de incidentes"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT i.id_incidente, i.descripcion, i.fecha_reporte, i.fecha_cierre,
               i.estado, i.gravedad, p.nombre AS tecnico
        FROM incidente i
        LEFT JOIN personal p ON i.personal_asignado = p.id_personal
        ORDER BY i.fecha_reporte DESC;
    """)
    historial = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('administrador/historial_tickets.html', historial=historial)




# ===============================================================
# -------------------- INCIDENTES (RESIDENTE) --------------------
# ===============================================================

def get_residente_id_by_user_id(user_id):
    """Devuelve el id_residente asociado al usuario logueado"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id_residente FROM residente WHERE id_usuario = %s;", (user_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row['id_residente'] if row else None


@app.route('/guardar_incidencia', methods=['POST'])
@role_required(['residente'])
def guardar_incidencia():
    """Residente reporta una incidencia"""
    descripcion = request.form.get('descripcion')
    gravedad = request.form.get('gravedad')
    evidencia = request.files.get('evidencia')

    user_id = session.get('user_id')
    residente_id = get_residente_id_by_user_id(user_id)

    if not residente_id:
        flash("❌ No se encontró residente asociado.", "danger")
        return redirect(url_for('dashboard'))

    # Verificar que el residente tiene un departamento asignado
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT id_depto, numero 
        FROM departamento 
        WHERE id_residente = %s
    """, (residente_id,))
    departamento = cur.fetchone()
    if not departamento:
        flash("⚠️ No tienes un departamento asignado.", "warning")
        cur.close()
        conn.close()
        return redirect(url_for('dashboard'))

    evidencia_nombre = None
    if evidencia and evidencia.filename:
        nombre_seguro = secure_filename(evidencia.filename)
        nombre_unico = f"{uuid.uuid4().hex}_{nombre_seguro}"
        evidencia_path = os.path.join(app.config['UPLOAD_FOLDER'], nombre_unico)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        evidencia.save(evidencia_path)
        evidencia_nombre = nombre_unico

    try:
        cur.execute("""
            INSERT INTO incidente (descripcion, evidencia, fecha_reporte, estado, gravedad, id_residente)
            VALUES (%s, %s, CURRENT_TIMESTAMP, 'Abierto', %s, %s);
        """, (descripcion, evidencia_nombre, gravedad, residente_id))
        conn.commit()
        flash("✅ Incidente reportado exitosamente.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al registrar incidencia: {e}", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('ver_mis_incidentes'))


@app.route('/mis_incidentes')
@login_required_role('residente')
def ver_mis_incidentes():
    """Lista los incidentes del residente actual"""
    user_id = session.get('user_id')
    residente_id = get_residente_id_by_user_id(user_id)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("""
            SELECT 
                i.id_incidente,
                i.descripcion,
                i.fecha_reporte,
                i.estado,
                i.gravedad,
                i.evidencia,
                i.fecha_cierre,
                p.nombre AS tecnico,
                d.numero AS departamento
            FROM incidente i
            LEFT JOIN personal p ON i.personal_asignado = p.id_personal
            LEFT JOIN departamento d ON d.id_residente = i.id_residente
            WHERE i.id_residente = %s
            ORDER BY i.fecha_reporte DESC;
        """, (residente_id,))
        incidentes = cur.fetchall()
    except Exception as e:
        flash(f"❌ Error al cargar tus incidentes: {e}", "danger")
        incidentes = []
    finally:
        cur.close()
        conn.close()

    return render_template('usuario/mis_incidentes.html', incidentes=incidentes)



@app.route('/usuario/incidencias/nueva', methods=['GET', 'POST'])
@login_required_role('residente')  # Usa tu decorador de rol personalizado
def reportar_incidencia():
    """Permite al residente reportar una nueva incidencia"""
    if request.method == 'POST':
        titulo = request.form.get('titulo')
        descripcion = request.form.get('descripcion')
        area = request.form.get('area')
        prioridad = request.form.get('prioridad')
        evidencia = request.files.get('imagen')  # tu input de imagen/evidencia

        evidencia_nombre = None
        if evidencia and evidencia.filename:
            nombre_seguro = secure_filename(evidencia.filename)
            evidencia_nombre = f"{uuid.uuid4().hex}_{nombre_seguro}"
            ruta_guardado = os.path.join(app.config.get('UPLOAD_FOLDER', 'uploads'), evidencia_nombre)
            os.makedirs(os.path.dirname(ruta_guardado), exist_ok=True)
            evidencia.save(ruta_guardado)

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute("""
                INSERT INTO incidente (
                    id_usuario, titulo, descripcion, area, prioridad, evidencia, estado, fecha_reporte
                ) VALUES (%s, %s, %s, %s, %s, %s, 'pendiente', NOW())
            """, (
                session['user_id'],
                titulo,
                descripcion,
                area,
                prioridad,
                evidencia_nombre
            ))
            conn.commit()
            flash("✅ Incidencia reportada correctamente.", "success")
            return redirect(url_for('ver_mis_incidentes'))

        except Exception as e:
            conn.rollback()
            flash(f"❌ Error al registrar incidencia: {e}", "danger")

        finally:
            cur.close()
            conn.close()

    # Si es GET, mostramos el formulario
    return render_template("usuario/reportar_incidencia.html")

# ===============================================================
# --------------------- RESERVAS Y FACTURAS ----------------------
# ===============================================================

@app.route('/usuario/reservas/<int:id_reserva>/factura')
@role_required(['residente'])
def generar_factura_reserva(id_reserva):
    """Genera factura PDF con QR"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT r.id_reserva, r.tipo, r.descripcion, r.fecha_inicio, r.horario,
               r.numero_personas, r.costo_reserva, r.estado, u.nombre, u.apellido
        FROM reserva r
        JOIN usuario u ON r.id_usuario = u.id_usuario
        WHERE r.id_reserva = %s;
    """, (id_reserva,))
    reserva = cur.fetchone()
    cur.close()
    conn.close()

    if not reserva:
        flash("❌ Reserva no encontrada.", "danger")
        return redirect(url_for('reservas'))

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 16)
    p.drawString(200, 760, "FACTURA DE RESERVA")
    p.setFont("Helvetica", 11)
    p.drawString(100, 740, "Sistema NEOTOWER")
    p.line(100, 735, 500, 735)

    y = 710
    for texto in [
        f"Cliente: {reserva['nombre']} {reserva['apellido']}",
        f"Ambiente: {reserva['tipo']}",
        f"Fecha: {reserva['fecha_inicio']}",
        f"Horario: {reserva['horario']}",
        f"N° Personas: {reserva['numero_personas']}",
        f"Estado: {reserva['estado'].capitalize()}",
        f"Costo Total: Bs. {reserva['costo_reserva']}"
    ]:
        p.drawString(100, y, texto)
        y -= 15

    qr_data = f"Reserva #{reserva['id_reserva']} | Cliente: {reserva['nombre']} {reserva['apellido']} | {reserva['tipo']} | {reserva['fecha_inicio']}"
    qr_img = qrcode.make(qr_data)
    qr_path = os.path.join("static", f"qr_reserva_{id_reserva}.png")
    qr_img.save(qr_path)

    try:
        p.drawInlineImage(qr_path, 400, 600, 120, 120)
    except:
        pass

    p.setFont("Helvetica-Oblique", 9)
    p.drawString(100, 100, "Gracias por usar NEOTOWER - Su comodidad es nuestra prioridad.")
    p.showPage()
    p.save()
    buffer.seek(0)
    try:
        os.remove(qr_path)
    except:
        pass

    return send_file(buffer, as_attachment=True,
                     download_name=f"factura_reserva_{id_reserva}.pdf",
                     mimetype="application/pdf")




#----------------------hasan--------------------------------------------



# --------------------------
# DASHBOARD ADMINISTRATIVO PAGOS (CSV)
# --------------------------
@app.route('/admin/dashboardpagos')
@login_required
@role_required(['administrador'])
def dashboardpagos():
    import pandas as pd
    from datetime import datetime, timedelta

    # ==== 0) Entrada y filtros ====
    # CSV de pagos exportado desde tu BD
    path = "dataset_pagos.csv"  # ajusta si lo mueves a /static/data/dataset_pagos.csv

    # Filtros via querystring (?fecha_inicio=YYYY-MM-DD&fecha_fin=YYYY-MM-DD&estado=Pagado&departamento=101)
    q_fecha_inicio = request.args.get("fecha_inicio", "").strip() or None
    q_fecha_fin    = request.args.get("fecha_fin", "").strip() or None
    q_estado       = request.args.get("estado", "").strip() or None
    q_depto        = request.args.get("departamento", "").strip() or None

    df = pd.read_csv(path)

    # ==== 1) Normalización robusta de columnas ====
    original_cols = df.columns.tolist()
    cols_norm = {c: c.lower().strip().replace(" ", "").replace("_", "") for c in original_cols}

    def pick_col(candidates):
        # Coincidencia exacta de nombre normalizado
        for cand in candidates:
            key = cand.lower().replace(" ", "").replace("_", "")
            for orig, norm in cols_norm.items():
                if norm == key:
                    return orig
        # Fallback por palabras
        keys = set(k for cand in candidates for k in cand.lower().replace("_", " ").split())
        for orig in original_cols:
            low = orig.lower()
            if any(k in low for k in keys):
                return orig
        return None

    col_fecha   = pick_col(["fecha_pago", "fecha", "date", "payment_date"])
    col_monto   = pick_col(["monto_pago", "monto", "importe", "amount", "total"])
    col_estado  = pick_col(["estado_pago", "estado", "status", "estatus", "situacion"])
    col_tipo    = pick_col(["tipo_pago", "tipo", "concepto", "categoria"])
    col_depto   = pick_col(["departamento", "id_departamento", "id_depto", "nro_departamento"])
    col_idres   = pick_col(["id_residente", "residente_id", "id"])
    col_venc    = pick_col(["fecha_vencimiento", "vencimiento", "due_date"])
    col_retraso = pick_col(["retraso_dias", "dias_retraso", "delay_days"])

    if not all([col_fecha, col_monto, col_estado]):
        faltan = [n for n, v in {"fecha": col_fecha, "monto": col_monto, "estado": col_estado}.items() if v is None]
        raise ValueError(f"Faltan columnas obligatorias en dataset_pagos.csv: {', '.join(faltan)}. Presentes: {original_cols}")

    # ==== 2) Tipos y columnas de trabajo ====
    df["_fecha"]  = pd.to_datetime(df[col_fecha], errors="coerce", dayfirst=True, infer_datetime_format=True)
    s = df[col_monto].astype(str).str.replace(r"[^\d,.\-]", "", regex=True)
    s = s.str.replace(".", "", regex=False).str.replace(",", ".", regex=False)
    df["_monto"]  = pd.to_numeric(s, errors="coerce")
    df["_estado"] = df[col_estado].astype(str).str.strip().str.lower()
    df["_tipo"]   = df[col_tipo].astype(str).str.strip() if col_tipo else "Desconocido"
    df["_depto"]  = df[col_depto].astype(str).str.strip() if col_depto else None
    df["_venc"]   = pd.to_datetime(df[col_venc], errors="coerce", dayfirst=True) if col_venc else None
    df["_retraso"]= pd.to_numeric(df[col_retraso], errors="coerce") if col_retraso else None
    df["_mes"]    = df["_fecha"].dt.to_period("M")

    # ==== 3) Aplicar filtros ====
    mask = pd.Series(True, index=df.index)
    if q_fecha_inicio:
        try:
            fi = pd.to_datetime(q_fecha_inicio).date()
            mask &= df["_fecha"].dt.date >= fi
        except Exception:
            pass
    if q_fecha_fin:
        try:
            ff = pd.to_datetime(q_fecha_fin).date()
            mask &= df["_fecha"].dt.date <= ff
        except Exception:
            pass
    if q_estado:
        mask &= df["_estado"].str.contains(q_estado.strip().lower(), na=False)
    if q_depto and col_depto:
        mask &= df["_depto"] == q_depto

    dff = df.loc[mask].copy()

    # ==== 4) KPIs (punto 1) ====
    total_registros   = int(dff["_monto"].notna().sum())
    monto_total       = float(dff["_monto"].sum(skipna=True))
    monto_promedio    = float(dff["_monto"].mean(skipna=True)) if total_registros else 0.0
    monto_max         = float(dff["_monto"].max(skipna=True)) if total_registros else 0.0
    monto_min         = float(dff["_monto"].min(skipna=True)) if total_registros else 0.0
    residentes_unicos = int(dff[col_idres].nunique()) if col_idres else None

    vc_estados  = dff["_estado"].value_counts(dropna=False)
    retrasados  = int(vc_estados[[e for e in vc_estados.index if isinstance(e,str) and ("retras" in e or "vencid" in e)]].sum()) if not vc_estados.empty else 0
    ontime      = total_registros - retrasados
    porc_mora   = (retrasados/total_registros*100) if total_registros else 0.0
    porc_ontime = (ontime/total_registros*100) if total_registros else 0.0

    # Mes actual vs anterior (por monto)
    hoy = datetime.now().date()
    mes_actual   = pd.Period(hoy, freq="M")
    mes_anterior = mes_actual - 1
    montos_mensuales = dff.dropna(subset=["_mes","_monto"]).groupby("_mes")["_monto"].sum().sort_index()
    monto_mes_actual   = float(montos_mensuales.get(mes_actual, 0.0))
    monto_mes_anterior = float(montos_mensuales.get(mes_anterior, 0.0))
    growth_mes = ((monto_mes_actual - monto_mes_anterior)/monto_mes_anterior*100) if monto_mes_anterior else (100.0 if monto_mes_actual>0 else 0.0)

    prom_retraso_dias = float(dff["_retraso"][dff["_retraso"]>0].mean()) if col_retraso and dff["_retraso"].notna().any() else 0.0
    p95_monto         = float(dff["_monto"].quantile(0.95)) if total_registros else 0.0
    mediana_monto     = float(dff["_monto"].median()) if total_registros else 0.0

    # ==== 5) Tablas útiles (próximos vencimientos / top morosos) ====
    proximos_venc = []
    if col_venc:
        dentro_7 = (dff["_venc"].dt.date >= hoy) & (dff["_venc"].dt.date <= (hoy + timedelta(days=7)))
        sub = dff.loc[dentro_7, ["_depto", col_idres, "_monto", "_venc", "_estado", "_tipo"]].copy() if col_idres else dff.loc[dentro_7, ["_depto", "_monto", "_venc", "_estado", "_tipo"]].copy()
        sub = sub.sort_values("_venc").head(10)
        proximos_venc = sub.assign(
            vencimiento=sub["_venc"].dt.strftime("%d/%m/%Y"),
            estado=sub["_estado"].str.title(),
            monto=sub["_monto"].round(2),
        )[[("_depto"), ("monto"), ("vencimiento"), ("estado"), ("_tipo")] + ([col_idres] if col_idres else [])] \
        .rename(columns={"_depto":"departamento", "_tipo":"tipo", col_idres:"id_residente"}) \
        .to_dict(orient="records")

    morosos = []
    if col_idres:
        mask_mora = dff["_estado"].str.contains("retras|vencid", na=False)
        top = (dff[mask_mora]
               .groupby([col_idres] + (["_depto"] if col_depto else []))["_monto"].sum()
               .sort_values(ascending=False).head(10).reset_index())
        morosos = top.rename(columns={col_idres:"id_residente","_monto":"monto_total","_depto":"departamento"}) \
                    .assign(monto_total=lambda d: d["_monto"].round(2) if "_monto" in d.columns else d["monto_total"].round(2)) \
                    .to_dict(orient="records")

    # ==== 6) Series y distribuciones para gráficos (punto 2) ====
    # a) Ingresos por mes
    serie_montos_mes = montos_mensuales.round(2)
    # b) Cantidad de pagos por mes
    serie_cant_mes   = dff.groupby("_mes")["_monto"].count().reindex(serie_montos_mes.index, fill_value=0)
    # c) Stacked por estado
    stacked = (dff.groupby(["_mes","_estado"])["_monto"].count().unstack(fill_value=0).sort_index())
    stacked_meses   = [str(p) for p in stacked.index]
    stacked_estados = [str(c) for c in stacked.columns]
    stacked_data    = {e: stacked[e].tolist() for e in stacked_estados}
    # d) Dona por tipo
    tipos_vc = dff["_tipo"].value_counts().head(8)
    # e) Top departamentos por monto total (si hay columna)
    top_deptos_labels, top_deptos_values = [], []
    if col_depto:
        top_deptos = dff.groupby("_depto")["_monto"].sum().sort_values(ascending=False).head(10).round(2)
        top_deptos_labels = top_deptos.index.astype(str).tolist()
        top_deptos_values = top_deptos.values.tolist()
    # f) Histograma de montos
    montos = dff["_monto"].dropna()
    if len(montos) > 0:
        bins = [0, 200, 400, 600, 800, 1000, 1500, 2000, max(montos.max(), 2000)]
        labels = [f"{int(bins[i])}–{int(bins[i+1])}" for i in range(len(bins)-1)]
        hist_counts = pd.cut(montos, bins=bins, labels=labels, include_lowest=True).value_counts().reindex(labels, fill_value=0)
    else:
        labels, hist_counts = [], []

    charts = {
        "meses": [str(p) for p in serie_montos_mes.index],
        "montos_por_mes": serie_montos_mes.tolist(),
        "cantidad_por_mes": serie_cant_mes.tolist(),
        "stacked_meses": stacked_meses,
        "stacked_estados": stacked_estados,
        "stacked_data": stacked_data,
        "tipos_labels": tipos_vc.index.tolist(),
        "tipos_values": tipos_vc.values.tolist(),
        "top_deptos_labels": top_deptos_labels,
        "top_deptos_values": top_deptos_values,
        "hist_labels": labels,
        "hist_values": hist_counts.tolist() if hasattr(hist_counts, "tolist") else [],
    }

    # ==== 7) Alertas (punto 4) ====
    alertas = []
    if porc_mora >= 20:
        alertas.append({"nivel": "danger", "mensaje": f"Tasa de morosidad alta: {porc_mora:.1f}% de pagos en retraso."})
    if proximos_venc and len(proximos_venc) >= 5:
        alertas.append({"nivel": "warning", "mensaje": f"{len(proximos_venc)} pagos vencen en los próximos 7 días."})
    if monto_mes_anterior and growth_mes < -10:
        alertas.append({"nivel": "warning", "mensaje": f"Caída de ingresos del mes {growth_mes:.1f}% vs. mes anterior."})
    if p95_monto > (mediana_monto * 2 if mediana_monto else 0):
        alertas.append({"nivel": "info", "mensaje": "Hay montos atípicamente altos (p95 ≫ mediana). Revisa casos especiales."})

    # ==== 8) Recomendaciones rápidas (ligadas a alertas) ====
    recomendaciones = []
    if porc_mora > 0:
        recomendaciones.append("Programa recordatorios automáticos 3 y 1 día antes del vencimiento (email/WhatsApp).")
    if prom_retraso_dias >= 3:
        recomendaciones.append(f"Ajusta plazos o recargos: el retraso promedio es {prom_retraso_dias:.1f} días.")
    if growth_mes < 0:
        recomendaciones.append("Revisa el calendario de emisión para evitar baches de caja.")
    if not recomendaciones:
        recomendaciones.append("Liquidez estable. Mantén el esquema actual de cobros.")

    # ==== 9) Resumen y render ====
    resumen = {
        "total_registros": total_registros,
        "monto_total": round(monto_total, 2),
        "monto_promedio": round(monto_promedio, 2),
        "monto_max": round(monto_max, 2),
        "monto_min": round(monto_min, 2),
        "residentes_unicos": residentes_unicos,
        "porc_ontime": round(porc_ontime, 1),
        "porc_mora": round(porc_mora, 1),
        "prom_retraso_dias": round(prom_retraso_dias, 1),
        "p95_monto": round(p95_monto, 2),
        "mediana_monto": round(mediana_monto, 2),
        "monto_mes_actual": round(monto_mes_actual, 2),
        "monto_mes_anterior": round(monto_mes_anterior, 2),
        "growth_mes": round(growth_mes, 1),
    }

    tablas = {"proximos_venc": proximos_venc, "morosos": morosos}

    # Para los selects de filtros
    estados_unicos = sorted(set(df["_estado"].dropna().str.title().tolist()))
    deptos_unicos  = sorted(set(df["_depto"].dropna().tolist())) if col_depto else []

    return render_template("dashboardpagos.html",
                           resumen=resumen,
                           charts=charts,
                           alertas=alertas,
                           recomendaciones=recomendaciones,
                           tablas=tablas,
                           filtros={
                               "fecha_inicio": q_fecha_inicio or "",
                               "fecha_fin": q_fecha_fin or "",
                               "estado": q_estado or "",
                               "departamento": q_depto or ""
                           },
                           opciones={
                               "estados": estados_unicos,
                               "departamentos": deptos_unicos
                           })

def _admin_pagos_view_data():
    """
    Lee dataset_pagos (.csv/.xlsx/.xls), aplica normalización y FILTROS del dashboard
    y devuelve DataFrames listos para export + KPIs.
    Filtros esperados en query: fecha_inicio, fecha_fin, estado, tipo, departamento, residente
    """
    import pandas as pd, os
    from datetime import datetime

    # ------- filtros (ajusta si tus nombres difieren) -------
    file_path = "dataset_pagos.csv"  # cambia si lo moviste a /static/data/
    q_fecha_inicio = request.args.get("fecha_inicio", "").strip() or None
    q_fecha_fin    = request.args.get("fecha_fin", "").strip() or None
    q_estado       = request.args.get("estado", "").strip() or None
    q_tipo         = request.args.get("tipo", "").strip() or None
    q_depto        = request.args.get("departamento", "").strip() or None
    q_residente    = request.args.get("residente", "").strip() or None  # opcional

    # ------- lectura simple/tolerante -------
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".xlsx", ".xls"):
        df = pd.read_excel(file_path)
    else:
        df = pd.read_csv(file_path, encoding="utf-8", sep=None, engine="python")
    df.columns = [str(c).strip() for c in df.columns]
    original_cols = df.columns.tolist()
    norm = {c: c.lower().strip().replace(" ", "").replace("_", "") for c in original_cols}

    def pick_col(cands):
        for cand in cands:
            key = cand.lower().replace(" ", "").replace("_", "")
            for orig, n in norm.items():
                if n == key: return orig
        keys = set(k for cand in cands for k in cand.lower().replace("_", " ").split())
        for orig in original_cols:
            low = orig.lower()
            if any(k in low for k in keys): return orig
        return None

    col_fecha   = pick_col(["fecha", "fechapago", "fecha_pago", "fechaemision", "fecha_emision"])
    col_monto   = pick_col(["monto", "importe", "total"])
    col_estado  = pick_col(["estado", "estadopago", "estado_pago"])
    col_tipo    = pick_col(["tipo", "concepto", "categoria"])
    col_depto   = pick_col(["departamento", "unidad", "nro_departamento", "id_departamento"])
    col_resid   = pick_col(["id_residente", "residente_id", "idusuario", "id_usuario", "residente"])

    if not col_fecha or not col_monto:
        raise ValueError("dataset_pagos: faltan columnas clave (fecha/monto).")

    # ------- normalización -------
    df["_fecha"]  = pd.to_datetime(df[col_fecha], errors="coerce", dayfirst=True)
    s = (df[col_monto].astype(str)
                    .str.replace(r"[^\d,.\-]", "", regex=True)
                    .str.replace(".", "", regex=False)
                    .str.replace(",", ".", regex=False))
    df["_monto"]  = pd.to_numeric(s, errors="coerce")
    df["_estado"] = (df[col_estado].astype(str).str.strip().str.title() if col_estado else "Desconocido")
    df["_tipo"]   = (df[col_tipo].astype(str).str.strip().str.title() if col_tipo else "General")
    df["_depto"]  = (df[col_depto].astype(str).str.strip() if col_depto else None)
    df["_resid"]  = (df[col_resid].astype(str).str.strip() if col_resid else None)
    df["_dia"]    = df["_fecha"].dt.date
    df["_mes"]    = df["_fecha"].dt.to_period("M")

    # ------- filtros -------
    mask = pd.Series(True, index=df.index)
    if q_fecha_inicio:
        try: fi = pd.to_datetime(q_fecha_inicio).date(); mask &= (df["_dia"] >= fi)
        except: pass
    if q_fecha_fin:
        try: ff = pd.to_datetime(q_fecha_fin).date(); mask &= (df["_dia"] <= ff)
        except: pass
    if q_estado:
        mask &= df["_estado"].str.contains(q_estado, case=False, na=False)
    if q_tipo:
        mask &= df["_tipo"].str.contains(q_tipo, case=False, na=False)
    if q_depto and col_depto:
        mask &= (df["_depto"] == q_depto)
    if q_residente and col_resid:
        mask &= df["_resid"].str.contains(q_residente, case=False, na=False)

    dff = df.loc[mask].copy()

    # ------- DataFrames export -------
    df_detalle = pd.DataFrame({
        "Fecha": dff["_fecha"].dt.strftime("%Y-%m-%d"),
        "Tipo": dff["_tipo"],
        "Estado": dff["_estado"],
        "Monto (Bs)": dff["_monto"].round(2),
        **({"Departamento": dff["_depto"]} if col_depto else {}),
        **({"Residente": dff["_resid"]} if col_resid else {})
    })

    # mensual y agregados
    mensual = (dff.dropna(subset=["_mes","_monto"])
                 .groupby("_mes")["_monto"].sum().sort_index().round(2))
    df_mensual = pd.DataFrame({"Mes": [str(p) for p in mensual.index], "Recaudado (Bs)": mensual.values})

    por_estado = (dff.groupby("_estado")["_monto"]
                    .agg(Total="sum", Registros="count")
                    .round(2).reset_index().rename(columns={"_estado":"Estado"}))

    por_tipo = (dff.groupby("_tipo")["_monto"]
                  .agg(Total="sum", Registros="count")
                  .round(2).reset_index().rename(columns={"_tipo":"Tipo"}))

    # ------- KPIs -------
    total_registros = int(dff["_monto"].notna().sum())
    recaudado       = float(dff.loc[dff["_estado"].str.lower()=="pagado", "_monto"].sum())
    pendiente       = float(dff.loc[dff["_estado"].str.lower().isin(["pendiente","vencido","en deuda","impago"]), "_monto"].sum())
    ticket_prom     = float(dff["_monto"].mean()) if total_registros else 0.0
    pago_max        = float(dff["_monto"].max()) if total_registros else 0.0
    ultimo_pago_fec = None
    if "pagado" in dff["_estado"].str.lower().unique():
        ult = dff.loc[dff["_estado"].str.lower()=="pagado", "_fecha"].max()
        ultimo_pago_fec = ult.strftime("%Y-%m-%d") if pd.notna(ult) else None
    tasa_morosidad  = (pendiente / (recaudado + pendiente) * 100.0) if (recaudado + pendiente) > 0 else 0.0

    kpis = pd.DataFrame([
        {"KPI":"Total registros", "Valor": total_registros},
        {"KPI":"Recaudado (Bs)", "Valor": round(recaudado,2)},
        {"KPI":"Pendiente (Bs)", "Valor": round(pendiente,2)},
        {"KPI":"Tasa morosidad (%)", "Valor": round(tasa_morosidad,1)},
        {"KPI":"Ticket promedio (Bs)", "Valor": round(ticket_prom,2)},
        {"KPI":"Pago máximo (Bs)", "Valor": round(pago_max,2)},
        {"KPI":"Último pago", "Valor": ultimo_pago_fec or "-"},
    ])

    return df_detalle, df_mensual, por_estado, por_tipo, kpis

@app.route('/admin/dashboardpagos/export/excel')
@login_required
@role_required(['administrador'])
def admin_pagos_export_excel():
    import io, pandas as pd
    from flask import send_file

    try:
        df_detalle, df_mensual, df_estado, df_tipo, df_kpis = _admin_pagos_view_data()
    except Exception as e:
        flash(f"No se pudo preparar datos para Excel: {e}", "danger")
        return redirect(url_for('admin_dashboard'))  # ajusta si tu ruta es otra

    output = io.BytesIO()

    # Elegir engine disponible: xlsxwriter u openpyxl
    try:
        import xlsxwriter  # noqa
        engine = "xlsxwriter"
    except Exception:
        try:
            import openpyxl  # noqa
            engine = "openpyxl"
        except Exception:
            flash("No hay motor Excel disponible. Instala 'openpyxl' o 'xlsxwriter'.", "danger")
            return redirect(url_for('admin_dashboard'))

    with pd.ExcelWriter(output, engine=engine) as writer:
        df_kpis.to_excel(writer, index=False, sheet_name="KPIs")
        df_detalle.to_excel(writer, index=False, sheet_name="Pagos_Detalle")
        df_mensual.to_excel(writer, index=False, sheet_name="Pagos_Mensual")
        df_estado.to_excel(writer, index=False, sheet_name="Por_Estado")
        df_tipo.to_excel(writer, index=False, sheet_name="Por_Tipo")

    output.seek(0)
    return send_file(output,
                     as_attachment=True,
                     download_name="pagos_admin_export.xlsx",
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

@app.route('/admin/dashboardpagos/export/pdf')
@login_required
@role_required(['administrador'])
def admin_pagos_export_pdf():
    # Importar reportlab con manejo de ausencia
    try:
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
    except ModuleNotFoundError:
        flash("PDF no disponible: instala 'reportlab' (pip install reportlab).", "danger")
        return redirect(url_for('admin_dashboard'))

    from flask import send_file
    import io, pandas as pd
    from datetime import datetime

    try:
        df_detalle, df_mensual, df_estado, df_tipo, df_kpis = _admin_pagos_view_data()

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, title="Pagos - Resumen Administrativo")
        styles = getSampleStyleSheet()
        story = []

        title = f"Resumen de Pagos (Admin) — {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        story.append(Paragraph(title, styles['Title']))
        story.append(Spacer(1, 10))

        # KPIs
        story.append(Paragraph("KPIs", styles['Heading2']))
        kpi_rows = [["KPI","Valor"]] + [[str(r["KPI"]), str(r["Valor"])] for _, r in df_kpis.iterrows()]
        tk = Table(kpi_rows, hAlign='LEFT')
        tk.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0), colors.lightgrey),
                                ('GRID',(0,0),(-1,-1), 0.5, colors.grey)]))
        story.append(tk)
        story.append(Spacer(1, 10))

        # Recaudación mensual (muestra)
        story.append(Paragraph("Recaudación Mensual (muestra)", styles['Heading2']))
        mn_rows = [["Mes","Recaudado (Bs)"]] + [[r["Mes"], f"{r['Recaudado (Bs)']:.2f}"] for _, r in df_mensual.head(24).iterrows()]
        tm = Table(mn_rows, hAlign='LEFT')
        tm.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0), colors.lightgrey),
                                ('GRID',(0,0),(-1,-1), 0.25, colors.grey)]))
        story.append(tm)
        story.append(Spacer(1, 10))

        # Por estado
        story.append(Paragraph("Por Estado", styles['Heading2']))
        es_rows = [["Estado","Total (Bs)","Registros"]] + [[r["Estado"], f"{r['Total']:.2f}", int(r["Registros"])] for _, r in df_estado.iterrows()]
        te = Table(es_rows, hAlign='LEFT')
        te.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0), colors.lightgrey),
                                ('GRID',(0,0),(-1,-1), 0.25, colors.grey)]))
        story.append(te)
        story.append(Spacer(1, 10))

        # Detalle (muestra)
        story.append(Paragraph("Detalle de Pagos (muestra)", styles['Heading2']))
        cols = ["Fecha","Tipo","Estado","Monto (Bs)"]
        if "Departamento" in df_detalle.columns: cols.append("Departamento")
        if "Residente" in df_detalle.columns: cols.append("Residente")
        det_rows = [cols]
        for _, r in df_detalle.sort_values("Fecha", ascending=False).head(30).iterrows():
            row = [r["Fecha"], r["Tipo"], r["Estado"], f"{r['Monto (Bs)']:.2f}"]
            if "Departamento" in df_detalle.columns: row.append(r["Departamento"])
            if "Residente" in df_detalle.columns: row.append(r["Residente"])
            det_rows.append(row)
        td = Table(det_rows, hAlign='LEFT')
        td.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0), colors.lightgrey),
                                ('GRID',(0,0),(-1,-1), 0.25, colors.grey)]))
        story.append(td)

        doc.build(story)
        buf.seek(0)
        return send_file(buf, as_attachment=True,
                         download_name="pagos_admin_resumen.pdf",
                         mimetype="application/pdf")
    except Exception as e:
        flash(f"No se pudo generar el PDF: {e}", "danger")
        return redirect(url_for('admin_dashboard'))

# --- DASHBOARD ADMINISTRATIVO CONSUMO (CSV/Excel) ---
@app.route('/admin/dashboardconsumo')
@login_required
@role_required(['administrador'])
def dashboardconsumo():
    import pandas as pd
    from datetime import datetime
    import os

    # === 0) Entrada y filtros ===
    file_path = "dataset_consumo.csv"   # soporta .csv, .xlsx, .xls
    q_fecha_inicio = request.args.get("fecha_inicio", "").strip() or None
    q_fecha_fin    = request.args.get("fecha_fin", "").strip() or None
    q_recurso      = request.args.get("recurso", "").strip() or None
    q_depto        = request.args.get("departamento", "").strip() or None

    # === 1) Lectura simple y tolerante ===
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".xlsx", ".xls"):
        df = pd.read_excel(file_path)
    else:
        # sep=None + engine='python' detecta comas/; etc. y evita errores por separadores
        df = pd.read_csv(file_path, encoding="utf-8", sep=None, engine="python")

    # Limpieza mínima de encabezados
    df.columns = [str(c).strip() for c in df.columns]

    # === 2) Normalización / utilidades ===
    original_cols = df.columns.tolist()
    norm = {c: c.lower().strip().replace(" ", "").replace("_", "") for c in original_cols}

    def pick_col(candidates):
        # match normalizado exacto
        for cand in candidates:
            key = cand.lower().replace(" ", "").replace("_", "")
            for orig, n in norm.items():
                if n == key:
                    return orig
        # fallback por palabras
        keys = set(k for cand in candidates for k in cand.lower().replace("_", " ").split())
        for orig in original_cols:
            low = orig.lower()
            if any(k in low for k in keys):
                return orig
        return None

    # Columnas en formato largo (si existen)
    col_fecha   = pick_col(["fecha", "fecha_lectura", "date", "timestamp", "dia"])
    col_recurso = pick_col(["recurso", "tipo", "servicio", "variable", "medida"])
    col_cant    = pick_col(["consumo", "cantidad", "kwh", "m3", "lectura", "valor"])
    col_depto   = pick_col(["departamento", "id_departamento", "nro_departamento", "unidad"])
    col_idres   = pick_col(["id_residente", "residente_id", "id"])
    col_costo   = pick_col(["costo", "monto", "importe", "costo_estimado"])
    col_hora    = pick_col(["hora", "time", "hh", "horario"])

    # === 3) Soporte a formato ANCHO -> LARGO (simple) ===
    consumo_cols = []
    for c in original_cols:
        low = c.lower()
        if ("consumo" in low) and any(k in low for k in ["agua", "electric", "luz", "gas"]):
            consumo_cols.append(c)

    if (col_recurso is None or col_cant is None) and consumo_cols:
        base_cols = [x for x in [col_fecha, col_depto, col_idres, col_costo, col_hora] if x]
        df_long = df[base_cols + consumo_cols].copy() if base_cols else df[consumo_cols].copy()
        df_long = df_long.melt(id_vars=base_cols, value_vars=consumo_cols,
                               var_name="_recurso_col", value_name="_consumo_raw")

        def map_recurso(s):
            s = str(s).lower()
            if "agua" in s: return "Agua"
            if "electric" in s or "luz" in s: return "Luz"
            if "gas" in s: return "Gas"
            return s.replace("consumo", "").replace("_", " ").strip().title()

        df_long["_recurso"] = df_long["_recurso_col"].apply(map_recurso)
        df = df_long
        col_recurso = "_recurso"
        col_cant    = "_consumo_raw"

    # Validación mínima
    if not col_fecha:
        raise ValueError(f"No se encontró columna de fecha. Presentes: {original_cols}")
    if not col_recurso or not col_cant:
        raise ValueError(
            "No se encontraron columnas de consumo y recurso. "
            "Usa columnas 'recurso' y 'consumo' o columnas tipo 'consumo_agua', 'consumo_electricidad', 'consumo_gas'."
        )

    # === 4) Tipos y columnas de trabajo ===
    df["_fecha"]   = pd.to_datetime(df[col_fecha], errors="coerce", dayfirst=True)  # simple, sin infer_datetime_format
    df["_recurso"] = df[col_recurso].astype(str).str.strip().str.title()

    # Normaliza número (acepta 1.234,56 o 1234.56)
    s = df[col_cant].astype(str).str.replace(r"[^\d,.\-]", "", regex=True)
    s = s.str.replace(".", "", regex=False).str.replace(",", ".", regex=False)
    df["_consumo"] = pd.to_numeric(s, errors="coerce")

    df["_depto"] = df[col_depto].astype(str).str.strip() if col_depto else None
    df["_costo"] = pd.to_numeric(df[col_costo], errors="coerce") if col_costo else None
    df["_hora"]  = pd.to_numeric(df[col_hora], errors="coerce") if col_hora else None
    df["_dia"]   = df["_fecha"].dt.date
    df["_mes"]   = df["_fecha"].dt.to_period("M")

    # === 5) Filtros ===
    mask = pd.Series(True, index=df.index)
    if q_fecha_inicio:
        try:
            fi = pd.to_datetime(q_fecha_inicio).date(); mask &= df["_dia"] >= fi
        except Exception: pass
    if q_fecha_fin:
        try:
            ff = pd.to_datetime(q_fecha_fin).date(); mask &= df["_dia"] <= ff
        except Exception: pass
    if q_recurso:
        mask &= df["_recurso"].str.contains(q_recurso, case=False, na=False)
    if q_depto and col_depto:
        mask &= (df["_depto"] == q_depto)

    dff = df.loc[mask].copy()

    # === 6) KPIs ===
    por_dia = dff.dropna(subset=["_dia","_consumo"]).groupby("_dia")["_consumo"].sum().sort_index()
    total_registros   = int(dff["_consumo"].notna().count())
    total_consumo     = float(dff["_consumo"].sum(skipna=True))
    consumo_prom_dia  = float(por_dia.mean()) if len(por_dia) else 0.0
    consumo_max_dia   = float(por_dia.max()) if len(por_dia) else 0.0
    dia_pico          = (por_dia.idxmax().strftime("%d/%m/%Y") if len(por_dia) else None)

    hoy = datetime.now().date()
    mes_actual   = pd.Period(hoy, freq="M")
    mes_anterior = mes_actual - 1
    consumo_mensual = dff.dropna(subset=["_mes","_consumo"]).groupby("_mes")["_consumo"].sum().sort_index()
    cons_mes_actual   = float(consumo_mensual.get(mes_actual, 0.0))
    cons_mes_anterior = float(consumo_mensual.get(mes_anterior, 0.0))
    growth_mes = ((cons_mes_actual - cons_mes_anterior)/cons_mes_anterior*100) if cons_mes_anterior else (100.0 if cons_mes_actual>0 else 0.0)

    p95_consumo = float(dff["_consumo"].quantile(0.95)) if total_registros else 0.0
    mediana     = float(dff["_consumo"].median()) if total_registros else 0.0

    # === 7) Tablas drill-down ===
    picos_recientes = []
    if len(por_dia) > 0:
        top10 = por_dia.sort_values(ascending=False).head(10).reset_index()
        top10["fecha"] = pd.to_datetime(top10["_dia"]).dt.strftime("%d/%m/%Y")
        top10 = top10.rename(columns={"_consumo": "consumo"})
        picos_recientes = top10[["fecha", "consumo"]].assign(consumo=lambda d: d["consumo"].round(2)).to_dict(orient="records")

    top_deptos = []
    if col_depto:
        agg_dep = dff.groupby("_depto")["_consumo"].sum().sort_values(ascending=False).head(10).round(2)
        top_deptos = [{"departamento": k, "consumo": float(v)} for k, v in agg_dep.items()]

    lecturas_recientes = (dff.sort_values("_fecha", ascending=False).head(20)
                            .assign(
                                fecha=lambda x: x["_fecha"].dt.strftime("%d/%m/%Y %H:%M") if col_hora else x["_fecha"].dt.strftime("%d/%m/%Y"),
                                recurso=lambda x: x["_recurso"],
                                consumo=lambda x: x["_consumo"].round(2),
                                departamento=lambda x: x["_depto"] if col_depto else None
                            ))
    cols = ["fecha","recurso","consumo"] + (["departamento"] if col_depto else [])
    lecturas_recientes = lecturas_recientes[cols].to_dict(orient="records")

    # === 8) Series para gráficos ===
    serie_dias_labels = [d.strftime("%d/%m/%Y") for d in por_dia.index]
    serie_dias_values = por_dia.round(2).tolist()

    stacked = (dff.dropna(subset=["_mes","_recurso","_consumo"])
                 .groupby(["_mes","_recurso"])["_consumo"].sum()
                 .unstack(fill_value=0).sort_index())
    stacked_meses    = [str(p) for p in stacked.index]
    stacked_recursos = [str(c) for c in stacked.columns]
    stacked_data     = {r: stacked[r].round(2).tolist() for r in stacked_recursos}

    dona_recurso = dff.groupby("_recurso")["_consumo"].sum().sort_values(ascending=False)
    dona_labels  = dona_recurso.index.tolist()
    dona_values  = dona_recurso.round(2).values.tolist()

    cons = dff["_consumo"].dropna()
    if len(cons) > 0:
        bins = [0, 1, 5, 10, 20, 50, 100, max(cons.max(), 100)]
        labels = [f"{bins[i]}–{bins[i+1]}" for i in range(len(bins)-1)]
        hist_counts = pd.cut(cons, bins=bins, labels=labels, include_lowest=True).value_counts().reindex(labels, fill_value=0)
        hist_values = hist_counts.tolist()
    else:
        labels, hist_values = [], []

    charts = {
        "dias_labels": serie_dias_labels,
        "dias_values": serie_dias_values,
        "stacked_meses": stacked_meses,
        "stacked_recursos": stacked_recursos,
        "stacked_data": stacked_data,
        "dona_labels": dona_labels,
        "dona_values": dona_values,
        "top_deptos_labels": [d["departamento"] for d in top_deptos] if top_deptos else [],
        "top_deptos_values": [d["consumo"] for d in top_deptos] if top_deptos else [],
        "hist_labels": labels,
        "hist_values": hist_values,
    }

    # === 9) Alertas y recomendaciones (sin ML) ===
    alertas = []
    n_picos = int((por_dia > p95_consumo).sum()) if len(por_dia) else 0
    if n_picos >= 3:
        alertas.append({"nivel": "warning", "mensaje": f"{n_picos} días superaron el P95 de consumo. Revisa posibles fugas o picos anómalos."})
    if cons_mes_anterior and growth_mes > 10:
        alertas.append({"nivel": "warning", "mensaje": f"El consumo del mes subió {growth_mes:.1f}% vs. el mes anterior."})
    if cons_mes_anterior and growth_mes < -20:
        alertas.append({"nivel": "info", "mensaje": f"El consumo del mes cayó {abs(growth_mes):.1f}% vs. el mes anterior. Verifica sensores y calendario."})
    if p95_consumo > (mediana * 2 if mediana else 0):
        alertas.append({"nivel": "info", "mensaje": "Distribución muy sesgada: hay lecturas muy altas respecto a la mediana."})
    if dff["_consumo"].isna().sum() > 0 or dff["_fecha"].isna().sum() > 0:
        alertas.append({"nivel": "danger", "mensaje": "Existen lecturas con fecha/consumo inválido. Limpia el dataset."})

    recomendaciones = []
    if n_picos >= 1:
        recomendaciones.append("Programa inspección en las unidades con picos y revisa fugas (agua) o sobrecargas (luz).")
    if cons_mes_anterior and growth_mes > 10:
        recomendaciones.append("Envía buenas prácticas de ahorro a residentes con crecimiento mayor al promedio.")
    if cons_mes_anterior and growth_mes < -20:
        recomendaciones.append("Contrasta con ocupación/feriados; valida sensores (batería, conexión).")
    if not recomendaciones:
        recomendaciones.append("Consumo estable. Mantén el plan de mantenimiento y lecturas periódicas.")

        # ... (cálculos previos)
    # Si tienes columna de costo, calcula; si no, deja en None
    costo_total    = float(dff["_costo"].sum()) if ("_costo" in dff.columns and not dff["_costo"].isna().all()) else None
    costo_prom_dia = float(dff.groupby("_dia")["_costo"].sum().mean()) if ("_costo" in dff.columns and not dff["_costo"].isna().all()) else None

    resumen = {
        "total_registros": total_registros,
        "total_consumo": round(total_consumo, 2),
        "consumo_prom_dia": round(consumo_prom_dia, 2),
        "consumo_max_dia": round(consumo_max_dia, 2),
        "dia_pico": dia_pico,
        "cons_mes_actual": round(cons_mes_actual, 2),
        "cons_mes_anterior": round(cons_mes_anterior, 2),
        "growth_mes": round(growth_mes, 1),
        "p95_consumo": round(p95_consumo, 2),
        "mediana": round(mediana, 2),
        "recursos": sorted(dff["_recurso"].dropna().unique().tolist()),
        # >>> claves nuevas/aseguradas <<<
        "costo_total": round(costo_total, 2) if costo_total is not None else None,
        "costo_prom_dia": round(costo_prom_dia, 2) if costo_prom_dia is not None else None,
    }


    recursos_unicos = resumen["recursos"]
    deptos_unicos  = sorted(set(dff["_depto"].dropna().tolist())) if col_depto else []

    tablas = {
        "picos_recientes": picos_recientes,
        "top_deptos": top_deptos,
        "lecturas_recientes": lecturas_recientes
    }

    return render_template("dashboardconsumo.html",
                           resumen=resumen,
                           charts=charts,
                           alertas=alertas,
                           recomendaciones=recomendaciones,
                           tablas=tablas,
                           filtros={
                               "fecha_inicio": q_fecha_inicio or "",
                               "fecha_fin": q_fecha_fin or "",
                               "recurso": q_recurso or "",
                               "departamento": q_depto or ""
                           },
                           opciones={
                               "recursos": recursos_unicos,
                               "departamentos": deptos_unicos
                           })

def _admin_consumo_view_data():
    """
    Lee dataset_consumo (.csv/.xlsx/.xls), aplica la misma normalización/“melt” y filtros
    que el dashboard de admin, y devuelve DataFrames listos para export + KPIs.
    """
    import pandas as pd, os
    from datetime import datetime

    # ------- filtros actuales (idénticos al dashboard) -------
    file_path = "dataset_consumo.csv"   # cambia si lo moviste
    q_fecha_inicio = request.args.get("fecha_inicio", "").strip() or None
    q_fecha_fin    = request.args.get("fecha_fin", "").strip() or None
    q_recurso      = request.args.get("recurso", "").strip() or None
    q_depto        = request.args.get("departamento", "").strip() or None

    # ------- lectura simple/tolerante -------
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".xlsx", ".xls"):
        df = pd.read_excel(file_path)
    else:
        df = pd.read_csv(file_path, encoding="utf-8", sep=None, engine="python")
    df.columns = [str(c).strip() for c in df.columns]
    original_cols = df.columns.tolist()
    norm = {c: c.lower().strip().replace(" ", "").replace("_", "") for c in original_cols}

    def pick_col(cands):
        for cand in cands:
            key = cand.lower().replace(" ", "").replace("_", "")
            for orig, n in norm.items():
                if n == key: return orig
        keys = set(k for cand in cands for k in cand.lower().replace("_", " ").split())
        for orig in original_cols:
            low = orig.lower()
            if any(k in low for k in keys): return orig
        return None

    col_fecha   = pick_col(["fecha", "fecha_lectura", "date", "timestamp", "dia"])
    col_recurso = pick_col(["recurso", "tipo", "servicio", "variable", "medida"])
    col_cant    = pick_col(["consumo", "cantidad", "kwh", "m3", "lectura", "valor"])
    col_depto   = pick_col(["departamento", "id_departamento", "nro_departamento", "unidad"])
    col_hora    = pick_col(["hora", "time", "hh", "horario"])
    col_costo   = pick_col(["costo", "monto", "importe", "costo_estimado"])

    # ancho -> largo
    consumo_cols = []
    for c in original_cols:
        low = c.lower()
        if ("consumo" in low) and any(k in low for k in ["agua", "electric", "luz", "gas"]):
            consumo_cols.append(c)
    if (col_recurso is None or col_cant is None) and consumo_cols:
        base_cols = [x for x in [col_fecha, col_depto, col_hora, col_costo] if x]
        df_long = df[base_cols + consumo_cols].copy() if base_cols else df[consumo_cols].copy()
        df_long = df_long.melt(id_vars=base_cols, value_vars=consumo_cols,
                               var_name="_recurso_col", value_name="_consumo_raw")
        def map_rec(s):
            s = str(s).lower()
            if "agua" in s: return "Agua"
            if "electric" in s or "luz" in s: return "Luz"
            if "gas" in s: return "Gas"
            return s.replace("consumo", "").replace("_", " ").strip().title()
        df_long["_recurso"] = df_long["_recurso_col"].apply(map_rec)
        df = df_long
        col_recurso = "_recurso"
        col_cant    = "_consumo_raw"

    # validación mínima
    if not col_fecha or not col_recurso or not col_cant:
        raise ValueError("dataset_consumo: faltan columnas de fecha/recurso/consumo para export.")

    # tipos y normalización
    df["_fecha"]   = pd.to_datetime(df[col_fecha], errors="coerce", dayfirst=True)
    df["_recurso"] = df[col_recurso].astype(str).str.strip().str.title()
    s = df[col_cant].astype(str).str.replace(r"[^\d,.\-]", "", regex=True)
    s = s.str.replace(".", "", regex=False).str.replace(",", ".", regex=False)
    df["_consumo"] = pd.to_numeric(s, errors="coerce")
    df["_depto"]   = df[col_depto].astype(str).str.strip() if col_depto else None
    df["_dia"]     = df["_fecha"].dt.date
    df["_mes"]     = df["_fecha"].dt.to_period("M")

    # filtros
    mask = pd.Series(True, index=df.index)
    if q_fecha_inicio:
        try: fi = pd.to_datetime(q_fecha_inicio).date(); mask &= df["_dia"] >= fi
        except: pass
    if q_fecha_fin:
        try: ff = pd.to_datetime(q_fecha_fin).date(); mask &= df["_dia"] <= ff
        except: pass
    if q_recurso:
        mask &= df["_recurso"].str.contains(q_recurso, case=False, na=False)
    if q_depto and col_depto:
        mask &= (df["_depto"] == q_depto)
    dff = df.loc[mask].copy()

    # DataFrames de export
    df_lecturas = dff.copy()
    df_lecturas_export = pd.DataFrame({
        "Fecha": df_lecturas["_fecha"].dt.strftime("%Y-%m-%d"),
        "Recurso": df_lecturas["_recurso"],
        "Consumo": df_lecturas["_consumo"].round(2),
        **({"Departamento": df_lecturas["_depto"]} if col_depto else {})
    })

    por_dia = dff.dropna(subset=["_dia","_consumo"]).groupby("_dia")["_consumo"].sum().sort_index()
    df_diario = pd.DataFrame({"Fecha": [d.strftime("%Y-%m-%d") for d in por_dia.index],
                              "Consumo": por_dia.values.round(2)})

    stacked = (dff.dropna(subset=["_mes","_recurso","_consumo"])
                 .groupby(["_mes","_recurso"])["_consumo"].sum().unstack(fill_value=0).sort_index())
    df_mensual_recurso = stacked.round(2).reset_index().rename(columns={"_mes": "Mes"})
    df_mensual_recurso["Mes"] = df_mensual_recurso["Mes"].astype(str)

    # KPIs
    hoy = datetime.now().date()
    mes_actual   = pd.Period(hoy, freq="M")
    mes_anterior = mes_actual - 1
    consumo_mensual = dff.dropna(subset=["_mes","_consumo"]).groupby("_mes")["_consumo"].sum().sort_index()
    cons_mes_actual   = float(consumo_mensual.get(mes_actual, 0.0))
    cons_mes_anterior = float(consumo_mensual.get(mes_anterior, 0.0))
    growth_mes = ((cons_mes_actual - cons_mes_anterior)/cons_mes_anterior*100) if cons_mes_anterior else (100.0 if cons_mes_actual>0 else 0.0)
    p95 = float(dff["_consumo"].quantile(0.95)) if len(dff) else 0.0
    med = float(dff["_consumo"].median()) if len(dff) else 0.0
    kpis = pd.DataFrame([
        {"KPI":"Total registros", "Valor": int(dff["_consumo"].notna().sum())},
        {"KPI":"Consumo total", "Valor": round(float(dff["_consumo"].sum()),2)},
        {"KPI":"Consumo prom. diario", "Valor": round(float(por_dia.mean() if len(por_dia) else 0),2)},
        {"KPI":"Mes actual", "Valor": round(cons_mes_actual,2)},
        {"KPI":"Mes anterior", "Valor": round(cons_mes_anterior,2)},
        {"KPI":"Variación %", "Valor": round(growth_mes,1)},
        {"KPI":"P95", "Valor": round(p95,2)},
        {"KPI":"Mediana", "Valor": round(med,2)},
    ])

    return df_lecturas_export, df_diario, df_mensual_recurso, kpis

@app.route('/admin/dashboardconsumo/export/excel')
@login_required
@role_required(['administrador'])
def admin_consumo_export_excel():
    import io, pandas as pd
    from flask import send_file

    try:
        df_lecturas, df_diario, df_mensual_rec, df_kpis = _admin_consumo_view_data()
    except Exception as e:
        flash(f"No se pudo preparar datos para Excel: {e}", "danger")
        return redirect(url_for('dashboardconsumo',
                                fecha_inicio=request.args.get('fecha_inicio'),
                                fecha_fin=request.args.get('fecha_fin'),
                                recurso=request.args.get('recurso'),
                                departamento=request.args.get('departamento')))

    output = io.BytesIO()

    # engine dinámico
    try:
        import xlsxwriter  # noqa
        engine = "xlsxwriter"
    except Exception:
        try:
            import openpyxl  # noqa
            engine = "openpyxl"
        except Exception:
            flash("No hay motor Excel disponible. Instala 'openpyxl' o 'xlsxwriter'.", "danger")
            return redirect(url_for('dashboardconsumo'))

    with pd.ExcelWriter(output, engine=engine) as writer:
        df_kpis.to_excel(writer, index=False, sheet_name="KPIs")
        df_lecturas.to_excel(writer, index=False, sheet_name="Lecturas")
        df_diario.to_excel(writer, index=False, sheet_name="Consumo_Diario")
        df_mensual_rec.to_excel(writer, index=False, sheet_name="Mensual_por_Recurso")

    output.seek(0)
    return send_file(output,
                     as_attachment=True,
                     download_name="consumo_admin_export.xlsx",
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

@app.route('/admin/dashboardconsumo/export/pdf')
@login_required
@role_required(['administrador'])
def admin_consumo_export_pdf():
    # importar reportlab con manejo de ausencia
    try:
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
    except ModuleNotFoundError:
        flash("PDF no disponible: instala 'reportlab' (pip install reportlab).", "danger")
        return redirect(url_for('dashboardconsumo',
                                fecha_inicio=request.args.get('fecha_inicio'),
                                fecha_fin=request.args.get('fecha_fin'),
                                recurso=request.args.get('recurso'),
                                departamento=request.args.get('departamento')))

    from flask import send_file
    import io, pandas as pd
    from datetime import datetime

    try:
        df_lecturas, df_diario, df_mensual_rec, df_kpis = _admin_consumo_view_data()

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, title="Consumo - Resumen Administrativo")
        styles = getSampleStyleSheet()
        story = []

        title = f"Resumen de Consumo (Admin) — {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        story.append(Paragraph(title, styles['Title']))
        story.append(Spacer(1, 10))

        # KPIs
        story.append(Paragraph("KPIs", styles['Heading2']))
        kpi_rows = [["KPI","Valor"]] + [[str(r["KPI"]), str(r["Valor"])] for _, r in df_kpis.iterrows()]
        tk = Table(kpi_rows, hAlign='LEFT')
        tk.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0), colors.lightgrey),
                                ('GRID',(0,0),(-1,-1), 0.5, colors.grey)]))
        story.append(tk)
        story.append(Spacer(1, 10))

        # Consumo diario (primeros 25)
        story.append(Paragraph("Consumo Diario (muestra)", styles['Heading2']))
        di_rows = [["Fecha","Consumo"]]
        for _, r in df_diario.head(25).iterrows():
            di_rows.append([r["Fecha"], f"{r['Consumo']:.2f}"])
        td = Table(di_rows, hAlign='LEFT')
        td.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0), colors.lightgrey),
                                ('GRID',(0,0),(-1,-1), 0.25, colors.grey)]))
        story.append(td)
        story.append(Spacer(1, 10))

        # Lecturas (muestra 30)
        story.append(Paragraph("Lecturas (muestra)", styles['Heading2']))
        le_rows = [["Fecha","Recurso","Consumo"] + (["Departamento"] if "Departamento" in df_lecturas.columns else [])]
        for _, r in df_lecturas.sort_values("Fecha", ascending=False).head(30).iterrows():
            base = [r["Fecha"], r["Recurso"], f"{r['Consumo']:.2f}"]
            if "Departamento" in df_lecturas.columns: base += [r["Departamento"]]
            le_rows.append(base)
        tl = Table(le_rows, hAlign='LEFT')
        tl.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0), colors.lightgrey),
                                ('GRID',(0,0),(-1,-1), 0.25, colors.grey)]))
        story.append(tl)

        doc.build(story)
        buf.seek(0)
        return send_file(buf, as_attachment=True,
                         download_name="consumo_admin_resumen.pdf",
                         mimetype="application/pdf")
    except Exception as e:
        flash(f"No se pudo generar el PDF: {e}", "danger")
        return redirect(url_for('dashboardconsumo'))

# --------------------------
# DASHBOARD DEL RESIDENTE (BD)
# --------------------------
@app.route('/usuario/dashboard')
@login_required
@role_required(['residente'])
def usuario_dashboard():
    import psycopg2, psycopg2.extras
    from datetime import date, datetime, timedelta
    from collections import defaultdict
    from math import isfinite

    # --- 0) Identificación robusta ---
    q_id_residente = request.args.get('id_residente', type=int)
    id_usuario = session.get('id_usuario') or session.get('user_id')

    # Si no hay id_usuario en sesión y no pasaron id_residente, no podemos seguir
    if not id_usuario and not q_id_residente:
        flash("No se pudo identificar al usuario. Inicia sesión o usa ?id_residente=17 para probar.", "warning")
        return render_template(
            "usuario/dashboard_residente.html",
            resumen={"saldo_pendiente":0,"total_pagado_mes":0,"cons_mes_actual":0,"growth_mes":0,"p95_consumo":0,"mediana":0},
            charts={"dias_labels":[],"dias_values":[],"stacked_meses":[],"stacked_recursos":[],"stacked_data":{},
                    "dona_labels":[],"dona_values":[],"pagos_meses":[],"pagos_values":[]},
            alertas=[{"nivel":"info","mensaje":"Sin datos: falta id de sesión o parámetro de prueba."}],
            tablas={"pagos":[],"lecturas":[]}
        )

    # --- 1) Conexión y consultas ---
    try:
        with psycopg2.connect(**DB_CONFIG) as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:

            # a) CONSUMO
            if q_id_residente:
                # Filtra por id_residente directo (pruebas o si ya lo tienes mapeado)
                cur.execute("""
                    SELECT c.id_consumo, c.tipo, c.alerta, c.id_residente,
                           h.id_histo_consumo, h.fecha_lectura,
                           COALESCE(h.consumo_agua,0)          AS consumo_agua,
                           COALESCE(h.consumo_electricidad,0)  AS consumo_electricidad,
                           COALESCE(h.consumo_gas,0)           AS consumo_gas
                    FROM consumo c
                    JOIN histo_consumo h ON h.id_consumo = c.id_consumo
                    WHERE c.id_residente = %s
                    ORDER BY h.fecha_lectura ASC;
                """, (q_id_residente,))
            else:
                # Filtra por id_usuario haciendo JOIN con residente (mapea usuario→residente)
                cur.execute("""
                    SELECT c.id_consumo, c.tipo, c.alerta, c.id_residente,
                           h.id_histo_consumo, h.fecha_lectura,
                           COALESCE(h.consumo_agua,0)          AS consumo_agua,
                           COALESCE(h.consumo_electricidad,0)  AS consumo_electricidad,
                           COALESCE(h.consumo_gas,0)           AS consumo_gas
                    FROM residente r
                    JOIN consumo c       ON c.id_residente = r.id_residente
                    JOIN histo_consumo h ON h.id_consumo   = c.id_consumo
                    WHERE r.id_usuario = %s
                    ORDER BY h.fecha_lectura ASC;
                """, (id_usuario,))
            consumo_rows = cur.fetchall()

            # b) PAGOS
            if q_id_residente:
                cur.execute("""
                    SELECT p.id_pago, p.monto AS monto_pago, p.tipo AS tipo_pago,
                           p.estado AS estado_registro, p.fecha AS fecha_registro,
                           hp.id_historial, hp.fecha_pago, hp.fecha_vencimiento,
                           hp.retraso_dias, hp.estado_pago, hp.monto AS monto_historial
                    FROM pago p
                    LEFT JOIN historial_pagos hp ON hp.id_pago = p.id_pago
                    WHERE p.id_residente = %s
                    ORDER BY COALESCE(hp.fecha_pago, p.fecha) DESC, p.id_pago DESC;
                """, (q_id_residente,))
            else:
                cur.execute("""
                    SELECT p.id_pago, p.monto AS monto_pago, p.tipo AS tipo_pago,
                           p.estado AS estado_registro, p.fecha AS fecha_registro,
                           hp.id_historial, hp.fecha_pago, hp.fecha_vencimiento,
                           hp.retraso_dias, hp.estado_pago, hp.monto AS monto_historial
                    FROM residente r
                    JOIN pago p ON p.id_residente = r.id_residente
                    LEFT JOIN historial_pagos hp ON hp.id_pago = p.id_pago
                    WHERE r.id_usuario = %s
                    ORDER BY COALESCE(hp.fecha_pago, p.fecha) DESC, p.id_pago DESC;
                """, (id_usuario,))
            pago_rows = cur.fetchall()

    except Exception as e:
        flash(f"Error al leer datos del residente: {e}", "danger")
        return render_template(
            "usuario/dashboard_residente.html",
            resumen={"saldo_pendiente":0,"total_pagado_mes":0,"cons_mes_actual":0,"growth_mes":0,"p95_consumo":0,"mediana":0},
            charts={"dias_labels":[],"dias_values":[],"stacked_meses":[],"stacked_recursos":[],"stacked_data":{},
                    "dona_labels":[],"dona_values":[],"pagos_meses":[],"pagos_values":[]},
            alertas=[{"nivel":"danger","mensaje":"No se pudieron cargar tus datos."}],
            tablas={"pagos":[],"lecturas":[]}
        )

    # Si no hay datos, render amigable
    if (not consumo_rows) and (not pago_rows):
        msg = "No se encontraron registros para tu cuenta."
        if q_id_residente:
            msg += f" (id_residente={q_id_residente})"
        flash(msg, "info")
        return render_template(
            "usuario/dashboard_residente.html",
            resumen={"saldo_pendiente":0,"total_pagado_mes":0,"cons_mes_actual":0,"growth_mes":0,"p95_consumo":0,"mediana":0},
            charts={"dias_labels":[],"dias_values":[],"stacked_meses":[],"stacked_recursos":[],"stacked_data":{},
                    "dona_labels":[],"dona_values":[],"pagos_meses":[],"pagos_values":[]},
            alertas=[{"nivel":"info","mensaje":msg}],
            tablas={"pagos":[],"lecturas":[]}
        )

    # --- 2) Transformaciones de consumo (largo) ---
    consumo_largo = []
    for r in consumo_rows:
        f = r['fecha_lectura']
        if isinstance(f, str):
            try: f = datetime.fromisoformat(f).date()
            except Exception: f = None

        if r['consumo_agua'] and r['consumo_agua'] > 0:
            consumo_largo.append({"fecha": f, "recurso": "Agua", "consumo": float(r['consumo_agua'])})
        if r['consumo_electricidad'] and r['consumo_electricidad'] > 0:
            consumo_largo.append({"fecha": f, "recurso": "Luz", "consumo": float(r['consumo_electricidad'])})
        if r['consumo_gas'] and r['consumo_gas'] > 0:
            consumo_largo.append({"fecha": f, "recurso": "Gas", "consumo": float(r['consumo_gas'])})

    consumo_por_dia = defaultdict(float)
    for it in consumo_largo:
        if it["fecha"]:
            consumo_por_dia[it["fecha"]] += it["consumo"]
    consumo_por_dia = dict(sorted(consumo_por_dia.items()))

    def yyyymm(d: date): return f"{d.year}-{d.month:02d}"

    consumo_mes_recurso = defaultdict(lambda: defaultdict(float))
    consumo_total_mes   = defaultdict(float)
    total_por_recurso   = defaultdict(float)

    for it in consumo_largo:
        if it["fecha"]:
            ym = yyyymm(it["fecha"])
            r  = it["recurso"]
            v  = it["consumo"] or 0.0
            consumo_mes_recurso[ym][r] += v
            consumo_total_mes[ym] += v
            total_por_recurso[r]  += v

    hoy = date.today()
    ym_actual   = f"{hoy.year}-{hoy.month:02d}"
    ym_anterior = f"{hoy.year-1}-12" if hoy.month == 1 else f"{hoy.year}-{hoy.month-1:02d}"

    cons_mes_actual   = float(consumo_total_mes.get(ym_actual, 0.0))
    cons_mes_anterior = float(consumo_total_mes.get(ym_anterior, 0.0))
    growth_mes = ((cons_mes_actual - cons_mes_anterior)/cons_mes_anterior*100.0) if cons_mes_anterior else (100.0 if cons_mes_actual>0 else 0.0)

    total_consumo = sum(x["consumo"] for x in consumo_largo)
    if consumo_por_dia:
        consumo_prom_dia = sum(consumo_por_dia.values()) / len(consumo_por_dia)
        dia_pico, max_val = max(consumo_por_dia.items(), key=lambda kv: kv[1])
    else:
        consumo_prom_dia, dia_pico, max_val = 0.0, None, 0.0

    sorted_vals = sorted([v for v in consumo_por_dia.values() if v is not None])
    def percentile(arr, p):
        if not arr: return 0.0
        k = (len(arr)-1) * (p/100.0)
        f = int(k); c = min(f+1, len(arr)-1)
        if f == c: return float(arr[int(k)])
        return float(arr[f] + (arr[c]-arr[f])*(k-f))
    p95 = percentile(sorted_vals, 95)
    mediana = percentile(sorted_vals, 50)

    # --- 3) Transformaciones de pagos ---
    pagos_hist = []
    total_pagado_mes = 0.0
    saldo_pendiente  = 0.0
    proximo_vencimiento = None

    for r in pago_rows:
        fp = r['fecha_pago']; fv = r['fecha_vencimiento']; fr = r['fecha_registro']
        todate = lambda x: datetime.fromisoformat(x).date() if isinstance(x, str) else (x.date() if isinstance(x, datetime) else x)
        fp = todate(fp); fv = todate(fv); fr = todate(fr)

        monto = r['monto_historial'] if r['monto_historial'] is not None else r['monto_pago']
        estado = (r['estado_pago'] or r['estado_registro'] or "").strip().title()

        pagos_hist.append({
            "id_pago": r['id_pago'],
            "tipo": (r['tipo_pago'] or "").strip(),
            "monto": float(monto or 0.0),
            "estado": estado or "Desconocido",
            "fecha_pago": fp,
            "fecha_vencimiento": fv,
            "retraso_dias": r['retraso_dias'] if r['retraso_dias'] is not None else 0
        })

        if fp and fp.year == hoy.year and fp.month == hoy.month and estado.lower() == "pagado":
            total_pagado_mes += float(monto or 0.0)
        if estado.lower() not in ("pagado","paid"):
            saldo_pendiente += float(monto or 0.0)
            if fv and (proximo_vencimiento is None or fv < proximo_vencimiento):
                proximo_vencimiento = fv

    pagos_hist_orden = sorted(pagos_hist, key=lambda x: (x["fecha_pago"] or x["fecha_vencimiento"] or date.min), reverse=True)
    lecturas_recientes = sorted(consumo_largo, key=lambda x: (x["fecha"] or date.min), reverse=True)[:20]

    # --- 4) KPIs resumen ---
    resumen = {
        "saldo_pendiente": round(saldo_pendiente, 2) if isfinite(saldo_pendiente) else 0.0,
        "total_pagado_mes": round(total_pagado_mes, 2),
        "proximo_vencimiento": proximo_vencimiento.strftime("%d/%m/%Y") if proximo_vencimiento else None,
        "total_consumo": round(total_consumo, 2),
        "consumo_prom_dia": round(consumo_prom_dia, 2),
        "consumo_max_dia": round(max_val, 2),
        "dia_pico": dia_pico.strftime("%d/%m/%Y") if dia_pico else None,
        "cons_mes_actual": round(cons_mes_actual, 2),
        "cons_mes_anterior": round(cons_mes_anterior, 2),
        "growth_mes": round(growth_mes, 1),
        "p95_consumo": round(p95, 2),
        "mediana": round(mediana, 2),
    }

    # --- 5) Series para gráficos ---
    serie_dias_labels = [d.strftime("%d/%m/%Y") for d in consumo_por_dia.keys()]
    serie_dias_values = [round(v, 2) for v in consumo_por_dia.values()]

    meses_orden = sorted(consumo_mes_recurso.keys())
    recursos = sorted(set(r for m in meses_orden for r in consumo_mes_recurso[m].keys()))
    stacked_data = {r: [round(consumo_mes_recurso[m].get(r, 0.0), 2) for m in meses_orden] for r in recursos}

    dona_labels  = list(sorted(total_por_recurso.keys()))
    dona_values  = [round(total_por_recurso[k], 2) for k in dona_labels]

    pagos_por_mes = defaultdict(float)
    def yyyymm(d: date): return f"{d.year}-{d.month:02d}"
    for p in pagos_hist:
        fref = p["fecha_pago"] or p["fecha_vencimiento"]
        if fref:
            pagos_por_mes[yyyymm(fref)] += p["monto"] if p["estado"].lower()=="pagado" else 0.0
    pagos_meses  = sorted(pagos_por_mes.keys())
    pagos_values = [round(pagos_por_mes[m], 2) for m in pagos_meses]

    charts = {
        "dias_labels": serie_dias_labels,
        "dias_values": serie_dias_values,
        "stacked_meses": meses_orden,
        "stacked_recursos": recursos,
        "stacked_data": stacked_data,
        "dona_labels": dona_labels,
        "dona_values": dona_values,
        "pagos_meses": pagos_meses,
        "pagos_values": pagos_values
    }

    # --- 6) Alertas personales ---
    alertas = []
    if resumen["saldo_pendiente"] > 0:
        alertas.append({"nivel":"warning", "mensaje": f"Tienes saldo pendiente: Bs {resumen['saldo_pendiente']:.2f}."})
    if proximo_vencimiento and proximo_vencimiento <= (hoy + timedelta(days=7)):
        alertas.append({"nivel":"info", "mensaje": f"Tu próximo vencimiento es el {proximo_vencimiento.strftime('%d/%m/%Y')} (≤7 días)."})
    if cons_mes_anterior and resumen["growth_mes"] > 20:
        alertas.append({"nivel":"warning", "mensaje": f"Tu consumo del mes subió {resumen['growth_mes']:.1f}% vs. el mes anterior."})
    if resumen["p95_consumo"] > (resumen["mediana"] * 2 if resumen["mediana"] else 0):
        alertas.append({"nivel":"info", "mensaje": "Detectamos picos de consumo muy por encima de tu mediana."})

    # --- 7) Render ---
    return render_template(
        "usuario/dashboard_residente.html",
        resumen=resumen,
        charts=charts,
        alertas=alertas,
        tablas={
            "pagos": pagos_hist_orden[:12],
            "lecturas": lecturas_recientes
        }
    )

def _resolver_id_residente_y_datos(id_usuario, q_id_residente=None):
    import psycopg2, psycopg2.extras
    from datetime import date, datetime

    def todate(x):
        if isinstance(x, str):
            try: 
                return datetime.fromisoformat(x).date()
            except Exception:
                return None
        return x.date() if isinstance(x, datetime) else x

    with psycopg2.connect(**DB_CONFIG) as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # --- consumo
        if q_id_residente:
            cur.execute("""
                SELECT c.id_consumo, c.tipo, c.alerta, c.id_residente,
                       h.id_histo_consumo, h.fecha_lectura,
                       COALESCE(h.consumo_agua,0)          AS consumo_agua,
                       COALESCE(h.consumo_electricidad,0)  AS consumo_electricidad,
                       COALESCE(h.consumo_gas,0)           AS consumo_gas
                FROM consumo c
                JOIN histo_consumo h ON h.id_consumo = c.id_consumo
                WHERE c.id_residente = %s
                ORDER BY h.fecha_lectura ASC;
            """, (q_id_residente,))
        else:
            cur.execute("""
                SELECT c.id_consumo, c.tipo, c.alerta, c.id_residente,
                       h.id_histo_consumo, h.fecha_lectura,
                       COALESCE(h.consumo_agua,0)          AS consumo_agua,
                       COALESCE(h.consumo_electricidad,0)  AS consumo_electricidad,
                       COALESCE(h.consumo_gas,0)           AS consumo_gas
                FROM residente r
                JOIN consumo c       ON c.id_residente = r.id_residente
                JOIN histo_consumo h ON h.id_consumo   = c.id_consumo
                WHERE r.id_usuario = %s
                ORDER BY h.fecha_lectura ASC;
            """, (id_usuario,))
        consumo_rows = cur.fetchall()

        # --- pagos
        if q_id_residente:
            cur.execute("""
                SELECT p.id_pago, p.monto AS monto_pago, p.tipo AS tipo_pago,
                       p.estado AS estado_registro, p.fecha AS fecha_registro,
                       hp.id_historial, hp.fecha_pago, hp.fecha_vencimiento,
                       hp.retraso_dias, hp.estado_pago, hp.monto AS monto_historial
                FROM pago p
                LEFT JOIN historial_pagos hp ON hp.id_pago = p.id_pago
                WHERE p.id_residente = %s
                ORDER BY COALESCE(hp.fecha_pago, p.fecha) DESC, p.id_pago DESC;
            """, (q_id_residente,))
        else:
            cur.execute("""
                SELECT p.id_pago, p.monto AS monto_pago, p.tipo AS tipo_pago,
                       p.estado AS estado_registro, p.fecha AS fecha_registro,
                       hp.id_historial, hp.fecha_pago, hp.fecha_vencimiento,
                       hp.retraso_dias, hp.estado_pago, hp.monto AS monto_historial
                FROM residente r
                JOIN pago p ON p.id_residente = r.id_residente
                LEFT JOIN historial_pagos hp ON hp.id_pago = p.id_pago
                WHERE r.id_usuario = %s
                ORDER BY COALESCE(hp.fecha_pago, p.fecha) DESC, p.id_pago DESC;
            """, (id_usuario,))
        pago_rows = cur.fetchall()

    # Normaliza a dataframes para export
    # Consumo largo
    consumo_largo = []
    for r in consumo_rows:
        f = todate(r['fecha_lectura'])
        if r['consumo_agua'] and r['consumo_agua'] > 0:
            consumo_largo.append({"Fecha": f, "Recurso": "Agua", "Consumo": float(r['consumo_agua'])})
        if r['consumo_electricidad'] and r['consumo_electricidad'] > 0:
            consumo_largo.append({"Fecha": f, "Recurso": "Luz", "Consumo": float(r['consumo_electricidad'])})
        if r['consumo_gas'] and r['consumo_gas'] > 0:
            consumo_largo.append({"Fecha": f, "Recurso": "Gas", "Consumo": float(r['consumo_gas'])})
    df_consumo = pd.DataFrame(consumo_largo, columns=["Fecha","Recurso","Consumo"])

    # Pagos
    pagos = []
    for r in pago_rows:
        fecha_pago = todate(r['fecha_pago'])
        fecha_venc = todate(r['fecha_vencimiento'])
        monto = r['monto_historial'] if r['monto_historial'] is not None else r['monto_pago']
        estado = (r['estado_pago'] or r['estado_registro'] or "").strip().title()
        pagos.append({
            "ID Pago": r['id_pago'],
            "Tipo": (r['tipo_pago'] or "").strip(),
            "Monto (Bs)": float(monto or 0.0),
            "Estado": estado or "Desconocido",
            "Fecha de Pago": fecha_pago,
            "Fecha de Vencimiento": fecha_venc,
            "Retraso (días)": r['retraso_dias'] if r['retraso_dias'] is not None else 0
        })
    df_pagos = pd.DataFrame(pagos, columns=["ID Pago","Tipo","Monto (Bs)","Estado","Fecha de Pago","Fecha de Vencimiento","Retraso (días)"])
    return df_consumo, df_pagos


@app.route('/usuario/export/excel')
@login_required
@role_required(['residente'])
def usuario_export_excel():
    from datetime import datetime
    id_usuario = session.get('id_usuario') or session.get('user_id')
    q_id_residente = request.args.get('id_residente', type=int)

    try:
        df_consumo, df_pagos = _resolver_id_residente_y_datos(id_usuario, q_id_residente)
        # KPIs sencillos (por si quieres una pestaña KPIs)
        kpis = []
        if not df_consumo.empty:
            cons_por_dia = df_consumo.groupby('Fecha')['Consumo'].sum()
            cons_mes = df_consumo.assign(Mes=df_consumo['Fecha'].astype('datetime64[ns]').dt.to_period('M')) \
                                  .groupby('Mes')['Consumo'].sum()
            hoy = datetime.now().date()
            mes_actual = f"{hoy.year}-{hoy.month:02d}"
            mes_anterior = f"{hoy.year-1}-12" if hoy.month == 1 else f"{hoy.year}-{hoy.month-1:02d}"
            # convertir Period('YYYY-MM') a cadena
            cons_mes = cons_mes.rename(index=lambda p: str(p))
            a = float(cons_mes.get(mes_actual, 0.0)); b = float(cons_mes.get(mes_anterior, 0.0))
            growth = ((a-b)/b*100) if b else (100.0 if a>0 else 0.0)
            kpis.append({"KPI":"Consumo total","Valor": round(df_consumo['Consumo'].sum(),2)})
            kpis.append({"KPI":"Promedio por día","Valor": round(cons_por_dia.mean() if len(cons_por_dia)>0 else 0,2)})
            kpis.append({"KPI":"Consumo mes actual","Valor": round(a,2)})
            kpis.append({"KPI":"Variación vs mes anterior (%)","Valor": round(growth,1)})
        if not df_pagos.empty:
            pagado_mes = df_pagos[df_pagos['Estado'].str.lower()=="pagado"]
            kpis.append({"KPI":"Pagos registrados","Valor": int(len(df_pagos))})
            kpis.append({"KPI":"Pagado este mes (Bs)","Valor": round(pagado_mes[pagado_mes['Fecha de Pago'].astype('datetime64[ns]').dt.to_period('M') \
                                     == pd.Period(datetime.now().date(), freq='M')]['Monto (Bs)'].sum(),2)})
        df_kpis = pd.DataFrame(kpis) if kpis else pd.DataFrame(columns=["KPI","Valor"])

        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            df_consumo.to_excel(writer, index=False, sheet_name="Consumo")
            df_pagos.to_excel(writer, index=False, sheet_name="Pagos")
            df_kpis.to_excel(writer, index=False, sheet_name="KPIs")
        output.seek(0)

        filename = f"residente_export_{q_id_residente or id_usuario}.xlsx"
        return send_file(output,
                         as_attachment=True,
                         download_name=filename,
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    except Exception as e:
        flash(f"No se pudo generar el Excel: {e}", "danger")
        return redirect(url_for('usuario_dashboard'))

@app.route('/usuario/export/pdf')
@login_required
@role_required(['residente'])
def usuario_export_pdf():
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from datetime import datetime

    id_usuario = session.get('id_usuario') or session.get('user_id')
    q_id_residente = request.args.get('id_residente', type=int)

    try:
        df_consumo, df_pagos = _resolver_id_residente_y_datos(id_usuario, q_id_residente)

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, title="Resumen de Pagos y Consumo")
        styles = getSampleStyleSheet()
        story = []

        title = f"Resumen del residente ({q_id_residente or 'por sesión'}) — {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        story.append(Paragraph(title, styles['Title']))
        story.append(Spacer(1, 12))

        # KPIs básicos
        if not df_consumo.empty:
            cons_total = df_consumo['Consumo'].sum()
            cons_por_dia = df_consumo.groupby('Fecha')['Consumo'].sum()
            kpi_tbl = [["KPI","Valor"],
                       ["Consumo total", f"{cons_total:.2f}"],
                       ["Promedio por día", f"{(cons_por_dia.mean() if len(cons_por_dia)>0 else 0):.2f}"]]
            t = Table(kpi_tbl, hAlign='LEFT')
            t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0), colors.lightgrey),
                                   ('GRID',(0,0),(-1,-1), 0.5, colors.grey)]))
            story.append(Paragraph("KPIs de consumo", styles['Heading2']))
            story.append(t)
            story.append(Spacer(1, 12))

        # Tabla consumo (primeras 30 filas)
        story.append(Paragraph("Consumo (últimos registros)", styles['Heading2']))
        cons_rows = [["Fecha","Recurso","Consumo"]]
        for _, row in df_consumo.sort_values("Fecha", ascending=False).head(30).iterrows():
            cons_rows.append([row["Fecha"].strftime("%d/%m/%Y") if pd.notna(row["Fecha"]) else "-", row["Recurso"], f"{row['Consumo']:.2f}"])
        tcons = Table(cons_rows, hAlign='LEFT')
        tcons.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0), colors.lightgrey),
                                   ('GRID',(0,0),(-1,-1), 0.25, colors.grey)]))
        story.append(tcons)
        story.append(Spacer(1, 12))

        # Tabla pagos (primeras 30 filas)
        story.append(Paragraph("Historial de pagos", styles['Heading2']))
        pagos_rows = [["Fecha pago","Vencimiento","Tipo","Monto (Bs)","Estado"]]
        for _, row in df_pagos.sort_values("Fecha de Pago", ascending=False).head(30).iterrows():
            pagos_rows.append([
                row["Fecha de Pago"].strftime("%d/%m/%Y") if pd.notna(row["Fecha de Pago"]) else "-",
                row["Fecha de Vencimiento"].strftime("%d/%m/%Y") if pd.notna(row["Fecha de Vencimiento"]) else "-",
                row["Tipo"],
                f"{row['Monto (Bs)']:.2f}",
                row["Estado"]
            ])
        tpag = Table(pagos_rows, hAlign='LEFT', colWidths=[80,80,120,80,80])
        tpag.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0), colors.lightgrey),
                                  ('GRID',(0,0),(-1,-1), 0.25, colors.grey)]))
        story.append(tpag)

        doc.build(story)
        buf.seek(0)
        filename = f"residente_resumen_{q_id_residente or id_usuario}.pdf"
        return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/pdf")
    except Exception as e:
        flash(f"No se pudo generar el PDF: {e}", "danger")
        return redirect(url_for('usuario_dashboard'))

# ===============================================================
# -------- ASIGNAR DEPARTAMENTO A RESIDENTE (USANDO id_residente) --------
# ===============================================================
@app.route('/admin/asignar_departamento', methods=['GET', 'POST'])
@role_required(['administrador'])
def asignar_departamento():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'POST':
        id_residente = request.form.get('id_residente')
        id_depto = request.form.get('id_depto')

        try:
            # Verificar si el depto está disponible
            cur.execute("SELECT estado FROM departamento WHERE id_depto = %s;", (id_depto,))
            depto = cur.fetchone()
            if not depto:
                flash("❌ Departamento no encontrado.", "danger")
                return redirect(url_for('asignar_departamento'))

            if depto['estado'].lower() != 'disponible':
                flash("⚠️ El departamento no está disponible.", "warning")
                return redirect(url_for('asignar_departamento'))

            # Asignar residente al departamento
            cur.execute("""
                UPDATE departamento
                SET id_residente = %s, estado = 'ocupado'
                WHERE id_depto = %s;
            """, (id_residente, id_depto))

            conn.commit()
            flash("✅ Departamento asignado correctamente.", "success")

        except Exception as e:
            conn.rollback()
            flash(f"❌ Error al asignar: {e}", "danger")

        finally:
            cur.close()
            conn.close()

        return redirect(url_for('gestion_residentes'))

    # Si es GET → mostrar formulario
    cur.execute("""
        SELECT id_residente, nombre, apellido
        FROM residente
        ORDER BY nombre;
    """)
    residentes = cur.fetchall()

    cur.execute("""
        SELECT id_depto, numero, piso
        FROM departamento
        WHERE estado ILIKE 'disponible'
        ORDER BY numero;
    """)
    departamentos = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('administrador/asignar_departamento.html',
                           residentes=residentes, departamentos=departamentos)


if __name__ == '__main__':
    app.run(debug=True)

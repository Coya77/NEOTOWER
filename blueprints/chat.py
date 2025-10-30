# blueprints/chat.py (fix endpoints: 'chat.chat_comunitario' consistente)
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from utils.database import get_db_connection
from functools import wraps
import psycopg2.extras  # Para RealDictCursor

chat_bp = Blueprint('chat', __name__, url_prefix='/chat')  # Nombre 'chat' – Endpoint 'chat.*'

# Decoradores
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Debes iniciar sesión para acceder al chat.', 'warning')
            return redirect(url_for('auth.login'))  # Ajusta a tu ruta de login
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_rol' not in session or session['user_rol'] != 'administrador':
            flash('Acceso denegado. Solo para administradores.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@chat_bp.route('/comunitario', methods=['GET', 'POST'])
@login_required
def chat_comunitario():
    if request.method == 'POST':
        mensaje = request.form.get('mensaje', '').strip()
        if not mensaje:
            flash('❌ El mensaje no puede estar vacío.', 'danger')
        elif len(mensaje) > 500:
            flash('❌ El mensaje es demasiado largo (máx. 500 caracteres).', 'danger')
        else:
            user_id = session['user_id']
            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute(
                    "INSERT INTO mensaje_chat (id_usuario, mensaje) VALUES (%s, %s)",
                    (user_id, mensaje)
                )
                conn.commit()
                flash('✅ Mensaje enviado y visible en el chat.', 'success')
            except Exception as e:
                conn.rollback()
                flash(f'❌ Error al enviar mensaje: {str(e)}', 'danger')
            finally:
                cur.close()
                conn.close()
            
            # FIX: Endpoint correcto – 'chat.chat_comunitario' (blueprint 'chat' + función)
            return redirect(url_for('chat.chat_comunitario'))

    # Cargar mensajes visibles
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT m.*, u.nombre || ' ' || u.apellido AS nombre_usuario
            FROM mensaje_chat m
            JOIN usuario u ON m.id_usuario = u.id_usuario
            WHERE m.estado = 'visible' OR m.estado IS NULL
            ORDER BY m.fecha_envio DESC
            LIMIT 50
        """)
        mensajes = cur.fetchall()
    except Exception as e:
        flash(f'❌ Error al cargar chat: {str(e)}', 'danger')
        mensajes = []
    finally:
        cur.close()
        conn.close()

    return render_template('chat/comunitario.html', mensajes=mensajes)

@chat_bp.route('/admin/moderar')
@admin_required
def moderar_chat():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            SELECT m.*, u.nombre || ' ' || u.apellido AS nombre_usuario
            FROM mensaje_chat m
            JOIN usuario u ON m.id_usuario = u.id_usuario
            ORDER BY m.fecha_envio DESC
        """)
        mensajes = cur.fetchall()
    except Exception as e:
        flash(f'❌ Error al cargar moderación: {str(e)}', 'danger')
        mensajes = []
    finally:
        cur.close()
        conn.close()

    return render_template('administrador/moderar_chat.html', mensajes=mensajes)

@chat_bp.route('/admin/<int:id_mensaje>/eliminar', methods=['POST'])
@admin_required
def eliminar_mensaje(id_mensaje):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE mensaje_chat SET estado = 'eliminado' WHERE id_mensaje = %s",
            (id_mensaje,)
        )
        conn.commit()
        if cur.rowcount > 0:
            flash('🗑️ Mensaje eliminado (no visible en chat).', 'success')
        else:
            flash('❌ Mensaje no encontrado.', 'danger')
    except Exception as e:
        conn.rollback()
        flash(f'❌ Error al eliminar: {str(e)}', 'danger')
    finally:
        cur.close()
        conn.close()
    
    # FIX: Endpoint correcto – 'chat.moderar_chat'
    return redirect(url_for('chat.moderar_chat'))
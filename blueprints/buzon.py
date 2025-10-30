# blueprints/buzon.py (versión completa corregida: syntax fix + helper email autónomo)
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from flask_mail import Message
from utils.database import get_db_connection
from functools import wraps
from datetime import datetime
import psycopg2.extras  # Para RealDictCursor
import re  # Para validar emails
import logging  # Para logs (opcional)

buzon_bp = Blueprint('buzon', __name__, url_prefix='/quejas')  # Prefijo /quejas

# ================= HELPER ENVIAR_EMAIL AUTÓNOMO (para trigger en respuestas) =================
def enviar_email(destinatarios, asunto, cuerpo_texto, remitente=None):
    """
    Helper local: Envía email HTML con diseño NEOTOWER.
    - destinatarios: Lista [email].
    - asunto: String.
    - cuerpo_texto: Texto plano (convierte \n a <br>, envuelve en HTML colores).
    Retorna True si OK.
    """
    if not destinatarios:
        flash('⚠️ No hay destinatarios.', 'warning')
        return False

    # Validar emails (regex simple)
    email_regex = re.compile(r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$')
    valid_emails = [e for e in destinatarios if email_regex.match(e.strip().lower())]
    if not valid_emails:
        flash('❌ Emails inválidos.', 'danger')
        return False

    try:
        # Convertir texto a HTML (saltos de línea)
        cuerpo_html = cuerpo_texto.replace('\n', '<br>')

        # Wrapper HTML completo con colores NEOTOWER (azul #0e648b a verde #209278)
        html_final = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; background-color: #f8f9fa; line-height: 1.6;">
                <!-- Header: Gradiente Azul-Verde -->
                <div style="background: linear-gradient(135deg, #0e648b 0%, #209278 100%); padding: 20px; text-align: center; border-radius: 0 0 10px 10px;">
                    <h1 style="color: white; margin: 0; font-size: 24px;">NEOTOWER - {asunto}</h1>
                </div>
                
                <!-- Body: Contenido Principal -->
                <div style="padding: 20px; background-color: white; border-radius: 10px; margin: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    {cuerpo_html}
                    <p style="color: #666; font-size: 14px; margin-top: 20px;">
                        <em>Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M')}</em>
                    </p>
                    <p style="color: #209278; font-weight: bold;">
                        ¡Gracias por ser parte de NEOTOWER! Si necesitas ayuda, contacta al administrador.
                    </p>
                </div>
                
                <!-- Footer: Gris con enlace -->
                <div style="background-color: #e9ecef; padding: 15px; text-align: center; border-radius: 10px 10px 0 0; margin: 0 20px 20px;">
                    <hr style="border: none; border-top: 1px solid #dee2e6; margin: 10px 0;">
                    <p style="color: #666; font-size: 12px; margin: 0;">
                        Este es un mensaje automático de NEOTOWER. No respondas directamente.
                    </p>
                    <a href="http://127.0.0.1:5000/dashboard" style="color: #209278; text-decoration: none; font-weight: bold;">
                        Ir al Dashboard
                    </a>
                </div>
            </body>
        </html>
        """

        # Crear y enviar Message (FIX: Acceso corregido a Mail via extensions)
        msg = Message(
            subject=asunto,
            recipients=valid_emails,
            html=html_final,
            sender=remitente or current_app.config['MAIL_DEFAULT_SENDER']
        )
        mail_instance = current_app.extensions['mail']
        mail_instance.send(msg)

        print(f"✅ Email enviado exitosamente a {len(valid_emails)} destinatarios: {valid_emails}")
        flash(f'✅ Email enviado correctamente.', 'success')
        return True

    except Exception as e:
        error_msg = str(e)
        print(f"❌ Error al enviar email: {error_msg}")
        logging.error(f"Flask-Mail Error en buzon: {error_msg}")
        flash(f'⚠️ Email falló: {error_msg}', 'warning')
        return False

# Decoradores (reutiliza de anuncios.py si no los tienes)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Debes iniciar sesión para acceder.', 'warning')
            return redirect(url_for('login'))  # Ajusta a tu ruta de login
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_rol' not in session or session['user_rol'] != 'administrador':
            flash('Acceso denegado. Solo administradores.', 'danger')
            return redirect(url_for('dashboard'))  # Ajusta a tu dashboard
        return f(*args, **kwargs)
    return decorated_function

@buzon_bp.route('/mis_quejas')
@login_required
def mis_quejas():
    """Lista quejas del usuario (con JOIN para nombre_usuario, como dicts)."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # Asegura dicts
    user_id = session['user_id']
    cur.execute("""
        SELECT q.*, u.nombre || ' ' || u.apellido AS nombre_usuario
        FROM queja q
        JOIN usuario u ON q.id_usuario = u.id_usuario
        WHERE q.id_usuario = %s
        ORDER BY q.fecha_creacion DESC
    """, (user_id,))
    quejas = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('quejas/mis_quejas.html', quejas=quejas)

@buzon_bp.route('/nueva_queja', methods=['GET', 'POST'])
@login_required
def nueva_queja():
    """Form para nueva queja (maneja tipo, prioridad, anonimo)."""
    if request.method == 'POST':
        tipo = request.form['tipo']
        prioridad = request.form['prioridad']
        asunto = request.form['asunto']
        descripcion = request.form['descripcion']
        anonimo = 'anonimo' in request.form
        user_id = session['user_id']
        
        conn = get_db_connection()
        cur = conn.cursor()  # Cursor normal para INSERT
        try:
            cur.execute("""
                INSERT INTO queja (id_usuario, tipo, prioridad, asunto, descripcion, anonimo, estado)
                VALUES (%s, %s, %s, %s, %s, %s, 'pendiente')
            """, (user_id, tipo, prioridad, asunto, descripcion, anonimo))
            conn.commit()
            flash('✅ Mensaje enviado correctamente. Será revisado pronto.', 'success')
            return redirect(url_for('buzon.mis_quejas'))
        except Exception as e:
            flash(f'❌ Error al enviar: {str(e)}', 'danger')
            conn.rollback()
        finally:
            cur.close()
            conn.close()
    
    return render_template('quejas/nueva_queja.html')

@buzon_bp.route('/<int:id_queja>/detalle')
@login_required
def detalle_queja(id_queja):
    """Detalle de una queja (para usuario o admin, como dict)."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT q.*, u.nombre || ' ' || u.apellido AS nombre_usuario
        FROM queja q
        JOIN usuario u ON q.id_usuario = u.id_usuario
        WHERE q.id_queja = %s
    """, (id_queja,))
    queja = cur.fetchone()
    cur.close()
    conn.close()
    
    if not queja:
        flash('❌ Queja no encontrada.', 'danger')
        return redirect(url_for('buzon.mis_quejas'))
    
    # Si es admin, permite responder
    puede_responder = session.get('user_rol') == 'administrador'
    return render_template('quejas/detalle_queja.html', queja=queja, puede_responder=puede_responder)

# Rutas Admin
@buzon_bp.route('/admin/gestion')
@admin_required
def gestion_quejas():
    """Gestión de todas las quejas (admin: filtrar por estado/tipo, como dicts)."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    estado_filtro = request.args.get('estado', 'todos')
    tipo_filtro = request.args.get('tipo', 'todos')
    query = """
        SELECT q.*, u.nombre || ' ' || u.apellido AS nombre_usuario
        FROM queja q
        JOIN usuario u ON q.id_usuario = u.id_usuario
    """
    params = []
    
    where_clauses = []
    if estado_filtro != 'todos':
        where_clauses.append("q.estado = %s")
        params.append(estado_filtro)
    if tipo_filtro != 'todos':
        where_clauses.append("q.tipo = %s")
        params.append(tipo_filtro)
    
    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)
    
    query += " ORDER BY q.fecha_creacion DESC"
    cur.execute(query, params)
    quejas = cur.fetchall()
    cur.close()
    conn.close()
    
    return render_template('administrador/gestion_quejas.html', 
                          quejas=quejas, filtro_estado_actual=estado_filtro, filtro_tipo_actual=tipo_filtro)

@buzon_bp.route('/admin/<int:id_queja>/responder', methods=['POST'])
@admin_required
def responder_queja(id_queja):
    """Admin responde queja (actualiza respuesta, estado a 'respondida' + email automático)."""
    respuesta = request.form.get('respuesta', '').strip()  # Usa .get() para evitar KeyError si form vacío
    if not respuesta:
        flash('❌ Respuesta requerida.', 'danger')
        return redirect(url_for('buzon.detalle_queja', id_queja=id_queja))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Primero: Verifica si queja existe (evita UPDATE 0)
        cur.execute("SELECT id_queja, estado FROM queja WHERE id_queja = %s", (id_queja,))
        queja_check = cur.fetchone()
        if not queja_check:
            flash('❌ Queja no encontrada.', 'danger')
            return redirect(url_for('buzon.gestion_quejas'))

        # UPDATE
        cur.execute("""
            UPDATE queja 
            SET estado = 'respondida', respuesta = %s, fecha_respuesta = CURRENT_TIMESTAMP
            WHERE id_queja = %s
        """, (respuesta, id_queja))
        
        if cur.rowcount > 0:
            conn.commit()
            flash('✅ Queja respondida correctamente.', 'success')

            # TRIGGER AUTOMÁTICO: Enviar email al usuario de la queja
            cur2 = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            try:
                cur2.execute("""
                    SELECT u.email, u.nombre || ' ' || u.apellido AS nombre_residente 
                    FROM queja q 
                    JOIN usuario u ON q.id_usuario = u.id_usuario 
                    WHERE q.id_queja = %s
                """, (id_queja,))
                result = cur2.fetchone()
                email_usuario = result['email'] if result and result['email'] else None
                nombre_residente = result['nombre_residente'] if result else 'Residente'
                
                # Log temporal para debug (quita después de test)
                print(f"DEBUG: Intentando enviar a {email_usuario} (Nombre: {nombre_residente}) para queja {id_queja}")
                
            except Exception as email_e:
                print(f"DEBUG: Error en query email: {email_e}")
                email_usuario = None
                nombre_residente = 'Residente'
            finally:
                cur2.close()

            if email_usuario:
                # Preparar cuerpo texto (solo contenido, helper envuelve en HTML)
                fecha_actual = datetime.now().strftime('%d/%m/%Y %H:%M')
                cuerpo_texto = f"""
Hola {nombre_residente},

Hemos respondido a tu queja/reclamo (ID: {id_queja}).

Respuesta del Administrador:
{respuesta}

Fecha de respuesta: {fecha_actual}

Si necesitas más detalles, contacta al admin.
¡Gracias por usar NEOTOWER!
                """
                
                # Enviar usando helper local (pasa texto, no HTML completo)
                asunto = f"Respuesta a tu Queja #{id_queja} - NEOTOWER"
                email_enviado = enviar_email([email_usuario], asunto, cuerpo_texto)
                
                if email_enviado:
                    flash(f'✅ Queja respondida y email enviado a {nombre_residente}.', 'success')
                else:
                    flash(f'⚠️ Queja respondida, pero email falló (ver logs).', 'warning')
            else:
                flash('⚠️ Queja respondida, pero email no enviado (usuario sin email registrado).', 'warning')
        else:
            flash('❌ No se pudo actualizar la queja (posible error de DB).', 'danger')
    except Exception as e:
        conn.rollback()
        error_msg = str(e)
        print(f"DEBUG: Error completo en responder_queja: {error_msg} (ID: {id_queja})")  # Log temporal
        flash(f'❌ Error al responder: {error_msg}', 'danger')
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for('buzon.detalle_queja', id_queja=id_queja))

@buzon_bp.route('/admin/<int:id_queja>/eliminar', methods=['POST'])
@admin_required
def eliminar_queja(id_queja):
    """Admin elimina queja."""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM queja WHERE id_queja = %s", (id_queja,))
        
        if cur.rowcount > 0:
            conn.commit()
            flash('🗑️ Queja eliminada.', 'success')
        else:
            flash('❌ Queja no encontrada.', 'danger')
    except Exception as e:
        conn.rollback()
        flash(f'❌ Error al eliminar: {str(e)}', 'danger')
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for('buzon.gestion_quejas'))
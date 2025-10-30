# blueprints/correos.py (versión corregida: + import psycopg2 para cursor DB)
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_mail import Message
import re
import psycopg2  # FIX: Import agregado para cursor_factory=psycopg2.extras.RealDictCursor
from utils.database import get_db_connection  # Asume que existe para query emails
from functools import wraps
from flask import session
from datetime import datetime  # Para fecha en email

correos_bp = Blueprint('correos', __name__, url_prefix='/correos')

# Decorator simple para admin (ajusta si tienes @admin_required en app.py)
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_rol' not in session or session['user_rol'] != 'administrador':
            flash('Acceso denegado: Solo para administradores.', 'danger')
            return redirect(url_for('index'))  # Ajusta a tu ruta principal
        return f(*args, **kwargs)
    return decorated_function

def enviar_email(destinatarios, asunto, cuerpo_html, remitente=None):
    """
    Helper reutilizable: Envía email HTML con diseño NEOTOWER.
    - destinatarios: Lista de emails (ej. ['user@test.com']).
    - asunto: String (ej. "Nuevo Anuncio").
    - cuerpo_html: HTML o texto (convierte \n a <br> si texto).
    - remitente: Opcional (usa MAIL_DEFAULT_SENDER si None).
    Retorna True si OK, False si falla.
    """
    if not destinatarios:
        flash('⚠️ No hay destinatarios válidos.', 'warning')
        return False

    # Validar y filtrar emails (regex simple)
    email_regex = re.compile(r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$')
    valid_emails = [email for email in destinatarios if email_regex.match(email.strip().lower())]
    invalid_count = len(destinatarios) - len(valid_emails)
    
    if not valid_emails:
        flash('❌ Todos los emails son inválidos.', 'danger')
        return False
    
    if invalid_count > 0:
        print(f"⚠️ {invalid_count} emails inválidos ignorados.")

    try:
        # Si cuerpo_html es texto plano, convertir \n a <br>
        if not cuerpo_html.startswith('<'):  # Si no es HTML
            cuerpo_html = cuerpo_html.replace('\n', '<br>')

        # Plantilla HTML base con colores NEOTOWER
        html_final = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; background-color: #f8f9fa; line-height: 1.6;">
                <div style="background: linear-gradient(135deg, #0e648b 0%, #209278 100%); padding: 20px; text-align: center; border-radius: 0 0 10px 10px;">
                    <h1 style="color: white; margin: 0; font-size: 24px;">NEOTOWER - {asunto}</h1>
                </div>
                <div style="padding: 20px; background-color: white; border-radius: 10px; margin: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    {cuerpo_html}
                    <p style="color: #666; font-size: 14px; margin-top: 20px;">
                        <em>Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M')}</em>
                    </p>
                </div>
                <div style="background-color: #e9ecef; padding: 15px; text-align: center; border-radius: 10px 10px 0 0; margin: 0 20px 20px;">
                    <p style="color: #666; font-size: 12px; margin: 0;">
                        Este es un mensaje automático de NEOTOWER.
                    </p>
                </div>
            </body>
        </html>
        """

        # Crear Message
        msg = Message(
            subject=asunto,
            recipients=valid_emails,
            html=html_final,
            sender=remitente or current_app.config['MAIL_DEFAULT_SENDER']
        )

        # ✅ Forma correcta de acceder a Flask-Mail (usando extensions)
        mail_instance = current_app.extensions.get('mail')
        if mail_instance:
            mail_instance.send(msg)
        else:
            print("❌ Error: instancia de Flask-Mail no encontrada en current_app.extensions")
            flash("⚠️ Error interno: no se encontró configuración de correo.", "warning")
            return False

        print(f"✅ Email enviado exitosamente a {len(valid_emails)} destinatarios: {valid_emails[:3]}...")
        flash(f'✅ Email enviado a {len(valid_emails)} destinatarios.', 'success')
        return True

    except Exception as e:
        error_msg = str(e)
        print(f"❌ Error al enviar email: {error_msg}")
        flash(f'❌ Error al enviar email: {error_msg}', 'danger')
        return False


# Ruta para enviar masivo (solo admin)
@correos_bp.route('/admin/enviar-masivo', methods=['GET', 'POST'])
@admin_required
def enviar_masivo():
    """Form para admin: Envía email masivo a todos o residentes."""
    if request.method == 'POST':
        asunto = request.form.get('asunto', '').strip()
        cuerpo = request.form.get('cuerpo', '').strip()
        tipo_destinatarios = request.form.get('tipo_destinatarios', 'todos')  # 'todos' o 'residentes'

        if not asunto or not cuerpo:
            flash('❌ Asunto y cuerpo son requeridos.', 'danger')
            return render_template('correos/enviar_masivo.html')

        # Obtener emails de DB
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # FIX: Ahora psycopg2 definido
        try:
            if tipo_destinatarios == 'residentes':
                cur.execute("SELECT email FROM usuario WHERE rol = 'residente' AND email IS NOT NULL")
            else:
                cur.execute("SELECT email FROM usuario WHERE email IS NOT NULL")  # Todos (incluye admins)
            
            usuarios = cur.fetchall()
            destinatarios = [u['email'] for u in usuarios if u['email']]

            print(f"📧 Query ejecutada: {len(usuarios)} usuarios encontrados, {len(destinatarios)} emails válidos.")  # Log para debug

            if not destinatarios:
                flash('⚠️ No hay usuarios con email en la DB.', 'warning')
                return render_template('correos/enviar_masivo.html')

            # Enviar usando helper
            if enviar_email(destinatarios, asunto, cuerpo):
                flash(f'✅ Masivo enviado a {len(destinatarios)} usuarios ({tipo_destinatarios}).', 'success')
            else:
                flash('⚠️ Masivo procesado, pero algunos emails fallaron (ver logs).', 'warning')

        except Exception as e:
            print(f"❌ Error DB en masivo: {str(e)}")  # Log adicional para debug
            flash(f'❌ Error al obtener emails: {str(e)}', 'danger')
        finally:
            cur.close()
            conn.close()

        return render_template('correos/enviar_masivo.html')

    return render_template('correos/enviar_masivo.html')
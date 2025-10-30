# blueprints/anuncios.py (versión con paths absolutos - SIN template_folder)
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, session
from functools import wraps
from datetime import date, datetime
from psycopg2.extras import RealDictCursor

# IMPORT DESDE UTILS
from utils.database import get_db_connection

# Import del helper de correos para trigger automático
from blueprints.correos import enviar_email

# Crear el blueprint SIN template_folder (busca en templates/ global)
anuncios_bp = Blueprint('anuncios', __name__, url_prefix='/anuncios')  # ¡QUITA template_folder!

# Decoradores (igual)
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

# Ruta para usuarios: Muro de anuncios (usa path absoluto)
@anuncios_bp.route('/')
@login_required
def muro_anuncios():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        filtro_tipo = request.args.get('tipo', 'todos')
        
        query = """
            SELECT a.id_anuncio, a.titulo, a.contenido, a.tipo, a.fecha_publicacion, 
                   a.fecha_expiracion, a.estado, u.nombre || ' ' || u.apellido AS autor
            FROM anuncio a
            JOIN usuario u ON a.id_usuario = u.id_usuario
            WHERE a.estado = 'activo' 
            AND (a.fecha_expiracion IS NULL OR a.fecha_expiracion >= CURRENT_DATE)
        """
        
        params = []
        if filtro_tipo != 'todos':
            query += " AND a.tipo = %s"
            params.append(filtro_tipo)
            
        query += " ORDER BY a.fecha_publicacion DESC"
        
        cur.execute(query, tuple(params))
        anuncios = cur.fetchall()
        
    except Exception as e:
        flash(f"Error cargando anuncios: {e}", "danger")
        anuncios = []
        filtro_tipo = 'todos'
    finally:
        cur.close()
        conn.close()
    
    # Path absoluto: asume que está en templates/anuncios/ o templates/
    return render_template('anuncios/muro_anuncios.html',  # Cambia a 'muro_anuncios.html' si está en templates/
                         anuncios=anuncios, 
                         hoy=date.today(),
                         filtro_actual=filtro_tipo)

# Rutas para admins: Gestión de anuncios (path absoluto a administrador/)
@anuncios_bp.route('/admin/gestion')
@login_required
@role_required(['administrador'])
def gestion_anuncios():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        filtro_tipo = request.args.get('tipo', 'todos')
        filtro_estado = request.args.get('estado', 'todos')
        
        query = """
            SELECT a.*, u.nombre || ' ' || u.apellido AS autor
            FROM anuncio a
            JOIN usuario u ON a.id_usuario = u.id_usuario
            WHERE 1=1
        """
        
        params = []
        if filtro_tipo != 'todos':
            query += " AND a.tipo = %s"
            params.append(filtro_tipo)
            
        if filtro_estado != 'todos':
            query += " AND a.estado = %s"
            params.append(filtro_estado)
            
        query += " ORDER BY a.fecha_publicacion DESC"
        
        cur.execute(query, tuple(params))
        anuncios = cur.fetchall()
        
    except Exception as e:
        flash(f"Error cargando anuncios: {e}", "danger")
        anuncios = []
        filtro_tipo = 'todos'
        filtro_estado = 'todos'
    finally:
        cur.close()
        conn.close()
    
    # Path absoluto: usa tu template original en templates/administrador/
    return render_template('anuncios/gestion_anuncios.html',  # ¡Esto debe existir de tu código original!
                         anuncios=anuncios, 
                         hoy=date.today(),
                         filtro_tipo_actual=filtro_tipo,
                         filtro_estado_actual=filtro_estado)

@anuncios_bp.route('/admin/nuevo', methods=['GET', 'POST'])
@login_required
@role_required(['administrador'])
def nuevo_anuncio():
    if request.method == 'POST':
        titulo = request.form.get('titulo')
        contenido = request.form.get('contenido')
        tipo = request.form.get('tipo')
        fecha_expiracion = request.form.get('fecha_expiracion') or None
        estado = request.form.get('estado', 'activo')
        
        print(f"📝 Creando anuncio: {titulo}")
        
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            # Insertar anuncio
            cur.execute("""
                INSERT INTO anuncio (id_usuario, titulo, contenido, tipo, fecha_expiracion, estado, fecha_publicacion)
                VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id_anuncio
            """, (session['user_id'], titulo, contenido, tipo, fecha_expiracion, estado, datetime.now()))
            
            # Obtener el ID del anuncio creado - MÉTODO COMPATIBLE
            result = cur.fetchone()
            print(f"🔍 Resultado del INSERT: {result}")
            
            if result:
                # Método compatible con ambos tipos de cursor
                if isinstance(result, dict):
                    id_anuncio = result['id_anuncio']
                else:
                    id_anuncio = result[0]
                
                print(f"✅ Anuncio creado con ID: {id_anuncio}")
            else:
                flash("❌ Error: No se pudo obtener el ID del anuncio creado", "danger")
                return render_template('anuncios/nuevo_anuncio.html')
            
            conn.commit()
            flash("✅ Anuncio creado correctamente", "success")

            # CREAR NOTIFICACIONES SOLAMENTE
            try:
                mensaje_notificacion = f"Nuevo {tipo}: {titulo}"
                if crear_notificacion_anuncio(id_anuncio, f"📢 Nuevo Anuncio", mensaje_notificacion, 'anuncio'):
                    print(f"🔔 Notificaciones creadas para anuncio {id_anuncio}")
                    flash('🔔 Notificaciones enviadas a los residentes', 'success')
                else:
                    flash('⚠️ Anuncio creado, pero error creando notificaciones', 'warning')
            except Exception as notif_error:
                print(f"⚠️ Error en notificaciones: {notif_error}")
                flash('⚠️ Anuncio creado, pero error en notificaciones', 'warning')

            print("🎉 Redirigiendo a gestión de anuncios...")
            return redirect(url_for('anuncios.gestion_anuncios'))
            
        except Exception as e:
            conn.rollback()
            print(f"💥 ERROR en nuevo_anuncio: {str(e)}")
            import traceback
            traceback.print_exc()
            flash(f"❌ Error al crear anuncio: {str(e)}", "danger")
        finally:
            cur.close()
            conn.close()
    
    return render_template('anuncios/nuevo_anuncio.html')

def crear_notificacion_anuncio(id_anuncio, titulo, mensaje, tipo='anuncio'):
    """Crear notificación para todos los usuarios residentes"""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Obtener todos los residentes
        cur.execute("SELECT id_usuario FROM usuario WHERE rol = 'residente'")
        residentes = cur.fetchall()
        
        print(f"👥 Creando notificaciones para {len(residentes)} residentes")
        
        # Crear notificación para cada residente
        for residente in residentes:
            # Método compatible
            if isinstance(residente, dict):
                id_usuario = residente['id_usuario']
            else:
                id_usuario = residente[0]
                
            cur.execute("""
                INSERT INTO notificaciones (id_usuario, tipo, titulo, mensaje, id_referencia, fecha_creacion)
                VALUES (%s, %s, %s, %s, %s, NOW())
            """, (id_usuario, tipo, titulo, mensaje, id_anuncio))
        
        conn.commit()
        print(f"✅ Notificaciones creadas para {len(residentes)} residentes")
        return True
    except Exception as e:
        print(f"❌ Error creando notificaciones: {e}")
        conn.rollback()
        return False
    finally:
        cur.close()
        conn.close()


@anuncios_bp.route('/admin/<int:id_anuncio>/editar', methods=['GET', 'POST'])
@login_required
@role_required(['administrador'])
def editar_anuncio(id_anuncio):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    if request.method == 'POST':
        titulo = request.form.get('titulo')
        contenido = request.form.get('contenido')
        tipo = request.form.get('tipo')
        fecha_expiracion = request.form.get('fecha_expiracion') or None
        estado = request.form.get('estado')
        
        try:
            cur.execute("""
                UPDATE anuncio 
                SET titulo = %s, contenido = %s, tipo = %s, 
                    fecha_expiracion = %s, estado = %s
                WHERE id_anuncio = %s
            """, (titulo, contenido, tipo, fecha_expiracion, estado, id_anuncio))
            conn.commit()
            flash("✏️ Anuncio actualizado correctamente", "success")
            return redirect(url_for('anuncios.gestion_anuncios'))
        except Exception as e:
            conn.rollback()
            flash(f"❌ Error al actualizar anuncio: {e}", "danger")
            cur.close()
            conn.close()
            return render_template('anuncios/editar_anuncio.html', anuncio=None)
    else:
        cur.execute("SELECT * FROM anuncio WHERE id_anuncio = %s", (id_anuncio,))
        anuncio = cur.fetchone()
        if not anuncio:
            flash("Anuncio no encontrado", "warning")
            return redirect(url_for('anuncios.gestion_anuncios'))
        cur.close()
        conn.close()
        return render_template('anuncios/editar_anuncio.html', anuncio=anuncio)

@anuncios_bp.route('/admin/<int:id_anuncio>/eliminar')
@login_required
@role_required(['administrador'])
def eliminar_anuncio(id_anuncio):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM anuncio WHERE id_anuncio = %s", (id_anuncio,))
        conn.commit()
        flash("🗑️ Anuncio eliminado correctamente", "info")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Error al eliminar anuncio: {e}", "danger")
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for('anuncios.gestion_anuncios'))
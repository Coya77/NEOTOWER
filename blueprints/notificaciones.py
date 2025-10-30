# blueprints/notificaciones.py
from flask import Blueprint, request, jsonify, session
from utils.database import get_db_connection
from psycopg2.extras import RealDictCursor
from functools import wraps

notificaciones_bp = Blueprint('notificaciones', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'No autorizado'}), 401
        return f(*args, **kwargs)
    return decorated_function

@notificaciones_bp.route('/notificaciones/obtener')
@login_required
def obtener_notificaciones():
    """Obtener notificaciones no leídas del usuario"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Obtener notificaciones no leídas
        cur.execute("""
            SELECT id_notificacion, tipo, titulo, mensaje, fecha_creacion, leida, id_referencia
            FROM notificaciones 
            WHERE id_usuario = %s AND leida = FALSE
            ORDER BY fecha_creacion DESC
            LIMIT 10
        """, (session['user_id'],))
        
        notificaciones = cur.fetchall()
        
        # Contar total no leídas
        cur.execute("""
            SELECT COUNT(*) as total
            FROM notificaciones 
            WHERE id_usuario = %s AND leida = FALSE
        """, (session['user_id'],))
        
        total_no_leidas = cur.fetchone()['total']
        
        return jsonify({
            'notificaciones': notificaciones,
            'total_no_leidas': total_no_leidas
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@notificaciones_bp.route('/notificaciones/marcar-leida/<int:id_notificacion>', methods=['POST'])
@login_required
def marcar_notificacion_leida(id_notificacion):
    """Marcar una notificación como leída y obtener datos para redirección"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Primero obtener la notificación para saber a dónde redirigir
        cur.execute("""
            SELECT tipo, id_referencia FROM notificaciones 
            WHERE id_notificacion = %s AND id_usuario = %s
        """, (id_notificacion, session['user_id']))
        
        notificacion = cur.fetchone()
        
        if not notificacion:
            return jsonify({'error': 'Notificación no encontrada'}), 404
        
        # Marcar como leída
        cur.execute("""
            UPDATE notificaciones 
            SET leida = TRUE, fecha_lectura = NOW()
            WHERE id_notificacion = %s AND id_usuario = %s
        """, (id_notificacion, session['user_id']))
        
        conn.commit()
        
        # Determinar la URL de redirección basada en el tipo
        url_redireccion = determinar_url_redireccion(notificacion['tipo'], notificacion['id_referencia'])
        
        return jsonify({
            'success': True, 
            'redirect_url': url_redireccion
        })
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

def determinar_url_redireccion(tipo_notificacion, id_referencia):
    """Determinar a dónde redirigir basado en el tipo de notificación"""
    if tipo_notificacion == 'anuncio' and id_referencia:
        return f"/anuncios/#anuncio-{id_referencia}"
    elif tipo_notificacion == 'pago':
        return "/mis_pagos"
    elif tipo_notificacion == 'incidente':
        return "/buzon/mis_quejas"
    else:
        return "/dashboard"  # URL por defecto

@notificaciones_bp.route('/notificaciones/marcar-todas-leidas', methods=['POST'])
@login_required
def marcar_todas_leidas():
    """Marcar todas las notificaciones como leídas"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            UPDATE notificaciones 
            SET leida = TRUE, fecha_lectura = NOW()
            WHERE id_usuario = %s AND leida = FALSE
        """, (session['user_id'],))
        
        conn.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()
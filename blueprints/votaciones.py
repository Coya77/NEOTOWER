# blueprints/votaciones.py (módulo completo para encuestas/votaciones internas)
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from utils.database import get_db_connection
from functools import wraps
from datetime import datetime, date
import psycopg2.extras
from datetime import date, timedelta  
import psycopg2.extras  # Para RealDictCursor




# Import helper email si quieres notificaciones (opcional, usa de buzon/correos)
try:
    from blueprints.buzon import enviar_email  # O de correos si lo tienes
except ImportError:
    enviar_email = None  # Si no, salta emails

votaciones_bp = Blueprint('votaciones', __name__, url_prefix='/votaciones')

# Decoradores (reutiliza de buzon.py)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Debes iniciar sesión para acceder.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_rol' not in session or session['user_rol'] != 'administrador':
            flash('Acceso denegado. Solo administradores.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ================= RUTAS PARA RESIDENTES =================
@votaciones_bp.route('/mis_encuestas')
@login_required
def mis_encuestas():
    """Lista encuestas activas para el residente (puede votar – debug para error '0')."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    user_id = session['user_id']
    try:
        print(f"DEBUG mis_encuestas: user_id={user_id}, hoy={date.today()}")  # Start

        # Query principal – Test paso a paso
        print("DEBUG: Ejecutando query principal encuestas...")
        cur.execute("""
            SELECT e.*, COUNT(o.id_opcion) AS total_opciones
            FROM encuesta e
            LEFT JOIN opcion o ON e.id_encuesta = o.id_encuesta
            WHERE e.activa = TRUE AND CURRENT_DATE BETWEEN e.fecha_inicio AND e.fecha_fin
            GROUP BY e.id_encuesta
            ORDER BY e.fecha_inicio DESC
        """)
        encuestas = cur.fetchall()
        print(f"DEBUG: Query principal OK – Encontradas {len(encuestas)} encuestas")  # Si 0, filtro excluye

        # Loop ha_votado
        for i, e in enumerate(encuestas):
            print(f"DEBUG: Verificando voto para encuesta {e['id_encuesta']}...")
            cur.execute("""
                SELECT COUNT(*) FROM voto v 
                WHERE v.id_encuesta = %s AND v.id_usuario = %s
            """, (e['id_encuesta'], user_id))
            count_result = cur.fetchone()
            ha_votado = count_result['count'] > 0 if count_result else False  # Safe dict
            e['ha_votado'] = ha_votado
            print(f"DEBUG: Encuesta {e['id_encuesta']} ha_votado={ha_votado}")

        # Loop opciones
        for i, e in enumerate(encuestas):
            print(f"DEBUG: Cargando opciones para encuesta {e['id_encuesta']}...")
            cur.execute("""
                SELECT id_opcion, texto 
                FROM opcion 
                WHERE id_encuesta = %s 
                ORDER BY id_opcion ASC
            """, (e['id_encuesta'],))
            e['opciones'] = cur.fetchall()
            print(f"DEBUG: Encuesta {e['id_encuesta']} tiene {len(e['opciones'])} opciones")

        print(f"DEBUG Final: Pasando {len(encuestas)} encuestas al template")

    except Exception as e:
        error_type = type(e).__name__
        error_msg = str(e)
        print(f"DEBUG ERROR mis_encuestas: Type={error_type}, Msg='{error_msg}'")  # Full error
        print(f"DEBUG: Error en query – Verifica tablas opcion/voto")  # Hint
        flash(f'❌ Error cargando encuestas: {error_type} - {error_msg}', 'danger')
        encuestas = []
    finally:
        cur.close()
        conn.close()

    return render_template('votaciones/mis_encuestas.html', encuestas=encuestas)

@votaciones_bp.route('/votar/<int:id_encuesta>', methods=['POST'])
@login_required
def votar(id_encuesta):
    """Registra voto del residente (una vez por encuesta – fix double fetchone)."""
    user_id = session['user_id']
    id_opcion = request.form.get('opcion')

    print(f"DEBUG votar: id_encuesta={id_encuesta}, user_id={user_id}, id_opcion='{id_opcion}'")

    if not id_opcion:
        flash('❌ Debes seleccionar una opción.', 'danger')
        print("DEBUG: Falló - id_opcion vacío")
        return redirect(url_for('votaciones.mis_encuestas'))

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # 1. Ver si ya votó
        print("DEBUG: Verificando voto existente...")
        cur.execute("SELECT COUNT(*) AS count FROM voto WHERE id_encuesta = %s AND id_usuario = %s", (id_encuesta, user_id))
        count_result = cur.fetchone()
        count = count_result['count'] if count_result else 0
        print(f"DEBUG: Votos existentes = {count}")
        if count > 0:
            flash('⚠️ Ya has votado en esta encuesta.', 'warning')
            return redirect(url_for('votaciones.mis_encuestas'))

        # 2. Ver si encuesta activa
        print("DEBUG: Verificando encuesta activa...")
        cur.execute("SELECT activa, fecha_fin FROM encuesta WHERE id_encuesta = %s", (id_encuesta,))
        encuesta_result = cur.fetchone()
        print(f"DEBUG: Encuesta result = {encuesta_result}")
        if not encuesta_result:
            flash('❌ Encuesta no encontrada.', 'danger')
            return redirect(url_for('votaciones.mis_encuestas'))

        activa = encuesta_result['activa']
        fecha_fin = encuesta_result['fecha_fin']
        if not activa or date.today() > fecha_fin:
            flash('❌ Encuesta no activa.', 'danger')
            print(f"DEBUG: Encuesta no activa - activa={activa}, hoy={date.today()} > fin={fecha_fin}")
            return redirect(url_for('votaciones.mis_encuestas'))

        # 3. Ver si id_opcion válida para encuesta
        print("DEBUG: Verificando id_opcion válida...")
        cur.execute("SELECT id_opcion FROM opcion WHERE id_encuesta = %s AND id_opcion = %s", (id_encuesta, id_opcion))
        opcion_result = cur.fetchone()
        if not opcion_result:
            flash('❌ Opción inválida para esta encuesta.', 'danger')
            print(f"DEBUG: id_opcion {id_opcion} no existe para encuesta {id_encuesta}")
            return redirect(url_for('votaciones.mis_encuestas'))

        # 4. Registrar voto
        print("DEBUG: Insertando voto...")
        cur.execute("""
            INSERT INTO voto (id_encuesta, id_usuario, id_opcion) 
            VALUES (%s, %s, %s) RETURNING id_voto
        """, (id_encuesta, user_id, id_opcion))
        print(f"DEBUG: INSERT voto rowcount={cur.rowcount}")
        voto_result = cur.fetchone()
        if not voto_result:
            raise Exception("INSERT voto no retornó ID")

        id_voto = voto_result['id_voto']
        print(f"DEBUG: Voto insertado ID={id_voto}")

        # 5. Incrementar contador votos en opcion – FIX: fetchone una vez
        print("DEBUG: Actualizando votos en opcion...")
        cur.execute("UPDATE opcion SET votos = votos + 1 WHERE id_opcion = %s RETURNING votos", (id_opcion,))
        print(f"DEBUG: UPDATE opcion rowcount={cur.rowcount}")
        result_update = cur.fetchone()  # Una llamada
        new_votos = result_update['votos'] if result_update else 'N/A'
        print(f"DEBUG: New votos = {new_votos}")

        if result_update is None:
            raise Exception("UPDATE opcion no retornó row (raro, rowcount=1)")

        conn.commit()
        print("DEBUG: Commit OK - Voto registrado")
        flash('✅ ¡Voto registrado! Gracias por participar.', 'success')

    except Exception as e:
        conn.rollback()
        error_type = type(e).__name__
        error_msg = str(e)
        print(f"DEBUG ERROR votar: Type={error_type}, Msg='{error_msg}'")
        print(f"DEBUG: rowcount after error={cur.rowcount if 'cur' in locals() else 'N/A'}")
        flash(f'❌ Error al votar: {error_type} - {error_msg}', 'danger')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('votaciones.mis_encuestas'))

# ================= RUTAS PARA ADMIN =================
@votaciones_bp.route('/admin/gestion')
@admin_required
def admin_gestion_encuestas():
    """Admin: Lista todas las encuestas (activas/finalizadas)."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Todas las encuestas con stats (total votos, % por opción) – TU CÓDIGO INTACTO
        cur.execute("""
            SELECT e.*, 
                   COUNT(DISTINCT v.id_usuario) AS total_votos,
                   COUNT(o.id_opcion) AS total_opciones,
                   e.fecha_inicio, e.fecha_fin
            FROM encuesta e
            LEFT JOIN voto v ON e.id_encuesta = v.id_encuesta
            LEFT JOIN opcion o ON e.id_encuesta = o.id_encuesta
            GROUP BY e.id_encuesta
            ORDER BY e.fecha_creacion DESC
        """)
        encuestas = cur.fetchall()

        # Para cada encuesta, obtener opciones con votos – FIX: Query con cast numeric para ROUND
        for e in encuestas:
            cur.execute("""
                SELECT o.texto, o.votos, 
                       ROUND( ((o.votos::numeric / GREATEST(SUM(o2.votos)::numeric, 1::numeric)) * 100)::numeric, 1 ) AS porcentaje
                FROM opcion o
                LEFT JOIN opcion o2 ON o.id_encuesta = o2.id_encuesta
                WHERE o.id_encuesta = %s
                GROUP BY o.id_opcion, o.texto, o.votos
                ORDER BY o.votos DESC
            """, (e['id_encuesta'],))
            e['opciones'] = cur.fetchall()

    except Exception as e:
        error_msg = str(e)
        print(f"DEBUG SQL Error en admin_gestion_encuestas: {error_msg}")  # Temporal: Ver terminal
        flash(f'❌ Error cargando encuestas: {error_msg}', 'danger')
        encuestas = []
    finally:
        cur.close()
        conn.close()

    return render_template('administrador/gestion_encuestas.html', encuestas=encuestas)

@votaciones_bp.route('/admin/nueva_encuesta', methods=['GET', 'POST'])
@admin_required
def admin_nueva_encuesta():
    """Admin crea nueva encuesta (fix cursor dict + verifica usuario)."""
    if request.method == 'POST':
        titulo = request.form.get('titulo', '').strip()
        descripcion = request.form.get('descripcion', '').strip()
        fecha_inicio = request.form.get('fecha_inicio')
        fecha_fin = request.form.get('fecha_fin')
        opciones = [opt.strip() for opt in request.form.getlist('opciones') if opt.strip()]

        print(f"DEBUG POST: titulo='{titulo}', desc='{descripcion[:20]}...', inicio='{fecha_inicio}', fin='{fecha_fin}', opciones={opciones} (len={len(opciones)})")

        if not titulo or not opciones or len(opciones) < 2:
            flash('❌ Título y al menos 2 opciones requeridas.', 'danger')
            print(f"DEBUG: Falló validación - len(opciones)={len(opciones)}")
            today = date.today()
            end_date = today + timedelta(days=7)
            return render_template('administrador/nueva_encuesta.html', today=today, end_date=end_date)

        if not fecha_inicio or not fecha_fin:
            flash('❌ Fechas requeridas.', 'danger')
            today = date.today()
            end_date = today + timedelta(days=7)
            return render_template('administrador/nueva_encuesta.html', today=today, end_date=end_date)

        try:
            inicio_date = date.fromisoformat(fecha_inicio)
            fin_date = date.fromisoformat(fecha_fin)
            if inicio_date >= fin_date:
                flash('❌ Fecha fin debe ser después de inicio.', 'danger')
                today = date.today()
                end_date = today + timedelta(days=7)
                return render_template('administrador/nueva_encuesta.html', today=today, end_date=end_date)
        except ValueError as ve:
            flash('❌ Formato fechas inválido.', 'danger')
            print(f"DEBUG: Error parse fecha: {ve}")
            today = date.today()
            end_date = today + timedelta(days=7)
            return render_template('administrador/nueva_encuesta.html', today=today, end_date=end_date)

        print("DEBUG: Validación OK - Conectando DB")

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # FIX: RealDictCursor para dict access
        try:
            # NUEVO: Verifica usuario existe antes INSERT (evita FK violation)
            user_id = session.get('user_id')
            if not user_id:
                flash('❌ Error sesión: No user_id.', 'danger')
                print("DEBUG: Falló - user_id None")
                return redirect(url_for('login'))

            cur.execute("SELECT COUNT(*) FROM usuario WHERE id_usuario = %s", (user_id,))
            user_count = cur.fetchone()['count']  # Dict access
            if user_count == 0:
                flash('❌ Usuario no encontrado en DB (verifica ID).', 'danger')
                print(f"DEBUG: Falló - usuario id={user_id} no existe")
                return render_template('administrador/nueva_encuesta.html', today=date.today(), end_date=date.today() + timedelta(days=7))

            print(f"DEBUG: Usuario id={user_id} existe - Insertando encuesta")

            # Test tabla (opcional, ya que accesible)
            cur.execute("SELECT 1")  # Simple test
            print("DEBUG: Conexión OK")

            # Insert encuesta
            cur.execute("""
                INSERT INTO encuesta (titulo, descripcion, fecha_inicio, fecha_fin, id_usuario_creador)
                VALUES (%s, %s, %s, %s, %s) RETURNING id_encuesta
            """, (titulo, descripcion, fecha_inicio, fecha_fin, user_id))
            print(f"DEBUG: Execute INSERT encuesta - rowcount={cur.rowcount}")  # Debe 1

            result = cur.fetchone()
            print(f"DEBUG: fetchone result type={type(result)}, value={result}")  # Revela None/dict

            if result is None or not result:
                raise Exception("INSERT encuesta no retornó ID (posible constraint violation)")

            id_encuesta = result['id_encuesta']  # FIX: Dict access para RealDictCursor
            print(f"DEBUG: Encuesta insertada ID={id_encuesta}")

            # Insert opciones
            for i, texto in enumerate(opciones, 1):
                cur.execute("INSERT INTO opcion (id_encuesta, texto) VALUES (%s, %s) RETURNING id_opcion", (id_encuesta, texto))
                print(f"DEBUG: Execute INSERT opcion {i} - rowcount={cur.rowcount}")

                result_op = cur.fetchone()
                print(f"DEBUG: fetchone opcion {i} type={type(result_op)}, value={result_op}")

                if result_op is None or not result_op:
                    raise Exception(f"INSERT opcion {i} no retornó ID")

                id_opcion = result_op['id_opcion']  # FIX: Dict access
                print(f"DEBUG: Opción {i} '{texto}' ID={id_opcion}")

            conn.commit()
            print("DEBUG: Commit OK - Redirect a gestión")

            flash('✅ Encuesta creada exitosamente. ID: ' + str(id_encuesta), 'success')
            return redirect(url_for('votaciones.admin_gestion_encuestas'))

        except Exception as e:
            conn.rollback()
            error_type = type(e).__name__
            error_msg = str(e)
            print(f"DEBUG ERROR DB: Type={error_type}, Full Msg='{error_msg}'")  # Full msg
            print(f"DEBUG: rowcount after error={cur.rowcount if 'cur' in locals() else 'N/A'}")  # Extra info
            flash(f'❌ Error DB ({error_type}): {error_msg}', 'danger')
        finally:
            if 'cur' in locals():
                cur.close()
            conn.close()

    # GET: Defaults
    today = date.today()
    end_date = today + timedelta(days=7)
    print(f"DEBUG GET: Form today={today}, end_date={end_date}")
    return render_template('administrador/nueva_encuesta.html', today=today, end_date=end_date)

@votaciones_bp.route('/admin/<int:id_encuesta>/editar', methods=['GET', 'POST'])
@admin_required
def admin_editar_encuesta(id_encuesta):
    """Admin edita encuesta (título, fechas, opciones)."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        if request.method == 'POST':
            titulo = request.form.get('titulo', '').strip()
            descripcion = request.form.get('descripcion', '').strip()
            fecha_inicio = request.form.get('fecha_inicio')
            fecha_fin = request.form.get('fecha_fin')
            opciones = [opt.strip() for opt in request.form.getlist('opciones') if opt.strip()]

            if not titulo or len(opciones) < 2:
                flash('❌ Título y al menos 2 opciones requeridas.', 'danger')
                return render_template('administrador/editar_encuesta.html', encuesta=encuesta, opciones=opciones)

            # Update encuesta
            cur.execute("""
                UPDATE encuesta SET titulo = %s, descripcion = %s, fecha_inicio = %s, fecha_fin = %s
                WHERE id_encuesta = %s
            """, (titulo, descripcion, fecha_inicio, fecha_fin, id_encuesta))

            # Borrar opciones viejas y agregar nuevas
            cur.execute("DELETE FROM opcion WHERE id_encuesta = %s", (id_encuesta,))
            for texto in opciones:
                cur.execute("INSERT INTO opcion (id_encuesta, texto) VALUES (%s, %s)", (id_encuesta, texto))

            conn.commit()
            flash('✅ Encuesta actualizada.', 'success')
            return redirect(url_for('votaciones.admin_gestion_encuestas'))

        # GET: Cargar encuesta y opciones
        cur.execute("SELECT * FROM encuesta WHERE id_encuesta = %s", (id_encuesta,))
        encuesta = cur.fetchone()
        if not encuesta:
            flash('❌ Encuesta no encontrada.', 'danger')
            return redirect(url_for('votaciones.admin_gestion_encuestas'))

        cur.execute("SELECT * FROM opcion WHERE id_encuesta = %s", (id_encuesta,))
        opciones = cur.fetchall()

    except Exception as e:
        flash(f'❌ Error: {str(e)}', 'danger')
        encuesta, opciones = None, []
    finally:
        cur.close()
        conn.close()

    return render_template('administrador/editar_encuesta.html', encuesta=encuesta, opciones=opciones)

@votaciones_bp.route('/admin/<int:id_encuesta>/eliminar', methods=['POST'])
@admin_required
def admin_eliminar_encuesta(id_encuesta):
    """Admin elimina encuesta (cascada borra opciones/votos)."""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM encuesta WHERE id_encuesta = %s", (id_encuesta,))
        if cur.rowcount > 0:
            conn.commit()
            flash('🗑️ Encuesta eliminada.', 'success')
        else:
            flash('❌ Encuesta no encontrada.', 'danger')
    except Exception as e:
        conn.rollback()
        flash(f'❌ Error al eliminar: {str(e)}', 'danger')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('votaciones.admin_gestion_encuestas'))

@votaciones_bp.route('/admin/<int:id_encuesta>/resultados')
@admin_required
def admin_resultados_encuesta(id_encuesta):
    """Admin ve resultados detallados (porcentajes, gráficos simples)."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Obtener encuesta
        cur.execute("SELECT * FROM encuesta WHERE id_encuesta = %s", (id_encuesta,))
        encuesta = cur.fetchone()
        if not encuesta:
            flash('❌ Encuesta no encontrada.', 'danger')
            return redirect(url_for('votaciones.admin_gestion_encuestas'))

        # Obtener opciones con votos
        cur.execute("""
            SELECT o.id_opcion, o.texto, o.votos
            FROM opcion o
            WHERE o.id_encuesta = %s
            ORDER BY o.votos DESC
        """, (id_encuesta,))
        opciones = cur.fetchall()

        # Calcular total_votos y porcentajes
        total_votos = sum(o['votos'] for o in opciones) if opciones else 0
        opciones_con_stats = []
        for o in opciones:
            porcentaje = round((o['votos'] / total_votos * 100), 1) if total_votos > 0 else 0.0
            opciones_con_stats.append({
                'id_opcion': o['id_opcion'],
                'texto': o['texto'],
                'votos': o['votos'],
                'porcentaje': porcentaje
            })

        # Datos para stats generales
        stats = {
            'total_votos': total_votos,
            'total_opciones': len(opciones),
            'participacion': round((total_votos / 100) * 100, 1) if total_votos > 0 else 0  # Asume ~100 residentes, ajusta
        }

    except Exception as e:
        flash(f'❌ Error cargando resultados: {str(e)}', 'danger')
        encuesta, opciones_con_stats, stats = None, [], {}
    finally:
        cur.close()
        conn.close()

    return render_template('administrador/resultados_encuesta.html', 
                          encuesta=encuesta, 
                          opciones=opciones_con_stats, 
                          stats=stats)

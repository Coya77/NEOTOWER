# utils/database.py
import psycopg2
import psycopg2.extras

# Configuración de la base de datos (movida desde app.py)
DB_CONFIG = {
    'host': 'localhost',
    'database': 'NEOTOWER',
    'user': 'postgres',
    'password': '12345'
}

def get_db_connection():
    """Obtiene una conexión a la base de datos con cursor RealDictCursor"""
    return psycopg2.connect(**DB_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)
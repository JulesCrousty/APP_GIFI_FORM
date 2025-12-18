from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import os
from urllib.parse import urlparse
from datetime import datetime, timedelta
from functools import wraps
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Clé secrète pour JWT (en production, utiliser une variable d'environnement)
SECRET_KEY = os.environ.get('SECRET_KEY', 'gifi-stock-secret-key-2024')

def get_db_connection():
    """Établit une connexion à la base de données MySQL"""
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        raise ValueError("DATABASE_URL n'est pas défini")
    
    parsed = urlparse(db_url)
    database = (parsed.path or '').lstrip('/')
    if not database:
        raise ValueError("DATABASE_URL doit contenir le nom de la base")
    
    return mysql.connector.connect(
        host=parsed.hostname or 'localhost',
        port=parsed.port or 3306,
        user=parsed.username,
        password=parsed.password,
        database=database,
        charset='utf8mb4',
        autocommit=False,
        use_pure=True
    )

def token_required(f):
    """Décorateur pour protéger les routes avec JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token manquant'}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            conn = get_db_connection()
            cur = conn.cursor(dictionary=True)
            cur.execute('SELECT id, username, role FROM users WHERE id = %s', (data['user_id'],))
            current_user = cur.fetchone()
            cur.close()
            conn.close()
            
            if not current_user:
                return jsonify({'error': 'Utilisateur non trouvé'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expiré'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token invalide'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    """Décorateur pour les routes réservées aux administrateurs"""
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user['role'] != 'admin':
            return jsonify({'error': 'Accès réservé aux administrateurs'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# ==================== AUTHENTIFICATION ====================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Connexion utilisateur"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username et password requis'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    
    cur.execute('SELECT * FROM users WHERE username = %s', (data['username'],))
    user = cur.fetchone()
    
    cur.close()
    conn.close()
    
    if not user or not check_password_hash(user['password_hash'], data['password']):
        return jsonify({'error': 'Identifiants incorrects'}), 401
    
    # Générer le token JWT
    token = jwt.encode({
        'user_id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')
    
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    })

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    """Récupère les informations de l'utilisateur connecté"""
    return jsonify({
        'id': current_user['id'],
        'username': current_user['username'],
        'role': current_user['role']
    })

# ==================== GESTION DES UTILISATEURS (ADMIN) ====================

@app.route('/api/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user):
    """Récupère la liste des utilisateurs (admin uniquement)"""
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    
    cur.execute('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC')
    users = cur.fetchall()
    
    cur.close()
    conn.close()
    
    result = []
    for user in users:
        user_dict = dict(user)
        user_dict['created_at'] = user_dict['created_at'].isoformat() if user_dict['created_at'] else None
        result.append(user_dict)
    
    return jsonify(result)

@app.route('/api/users', methods=['POST'])
@token_required
@admin_required
def create_user(current_user):
    """Crée un nouvel utilisateur (admin uniquement)"""
    data = request.get_json()
    
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username et password requis'}), 400
    
    role = data.get('role', 'user')
    if role not in ['admin', 'user']:
        return jsonify({'error': 'Le rôle doit être "admin" ou "user"'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    
    # Vérifier si l'utilisateur existe déjà
    cur.execute('SELECT id FROM users WHERE username = %s', (data['username'],))
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({'error': 'Cet utilisateur existe déjà'}), 409
    
    password_hash = generate_password_hash(data['password'])
    
    cur.execute(
        '''INSERT INTO users (username, password_hash, role, created_at)
           VALUES (%s, %s, %s, CURRENT_TIMESTAMP)''',
        (data['username'], password_hash, role)
    )

    new_user_id = cur.lastrowid
    conn.commit()

    cur.execute('SELECT id, username, role, created_at FROM users WHERE id = %s', (new_user_id,))
    new_user = cur.fetchone()
    cur.close()
    conn.close()
    
    user_dict = dict(new_user)
    user_dict['created_at'] = user_dict['created_at'].isoformat() if user_dict['created_at'] else None
    
    return jsonify(user_dict), 201

@app.route('/api/users/<int:id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(current_user, id):
    """Supprime un utilisateur (admin uniquement)"""
    if current_user['id'] == id:
        return jsonify({'error': 'Vous ne pouvez pas supprimer votre propre compte'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    
    cur.execute('SELECT id FROM users WHERE id = %s', (id,))
    if not cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({'error': 'Utilisateur non trouvé'}), 404
    
    cur.execute('DELETE FROM users WHERE id = %s', (id,))
    conn.commit()
    cur.close()
    conn.close()
    
    return jsonify({'message': 'Utilisateur supprimé avec succès'})

# ==================== ARTICLES ====================

@app.route('/api/articles', methods=['GET'])
@token_required
def list_articles(current_user):
    """Retourne la liste des articles disponibles"""
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute('SELECT id, name FROM articles ORDER BY name ASC')
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ==================== GESTION DU STOCK ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Vérifie que l'API est opérationnelle"""
    return jsonify({'status': 'ok', 'message': 'API is running'})

@app.route('/api/stock', methods=['GET'])
@token_required
def get_all_stock(current_user):
    """Récupère toutes les entrées de stock"""
    type_stock = request.args.get('type_stock')
    
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    
    if type_stock:
        cur.execute(
            'SELECT * FROM stock WHERE type_stock = %s ORDER BY created_at DESC',
            (type_stock,)
        )
    else:
        cur.execute('SELECT * FROM stock ORDER BY created_at DESC')
    
    stocks = cur.fetchall()
    cur.close()
    conn.close()
    
    result = []
    for stock in stocks:
        stock_dict = dict(stock)
        stock_dict['created_at'] = stock_dict['created_at'].isoformat() if stock_dict['created_at'] else None
        stock_dict['updated_at'] = stock_dict['updated_at'].isoformat() if stock_dict['updated_at'] else None
        result.append(stock_dict)
    
    return jsonify(result)

@app.route('/api/stock/<int:id>', methods=['GET'])
@token_required
def get_stock(current_user, id):
    """Récupère une entrée de stock par son ID"""
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    
    cur.execute('SELECT * FROM stock WHERE id = %s', (id,))
    stock = cur.fetchone()
    
    cur.close()
    conn.close()
    
    if stock is None:
        return jsonify({'error': 'Stock non trouvé'}), 404
    
    stock_dict = dict(stock)
    stock_dict['created_at'] = stock_dict['created_at'].isoformat() if stock_dict['created_at'] else None
    stock_dict['updated_at'] = stock_dict['updated_at'].isoformat() if stock_dict['updated_at'] else None
    
    return jsonify(stock_dict)

@app.route('/api/stock', methods=['POST'])
@token_required
def create_stock(current_user):
    """Crée une nouvelle entrée de stock"""
    data = request.get_json()
    
    base_fields = ['sn', 'article', 'etat', 'type_stock']
    for field in base_fields:
        if field not in data or not data[field]:
            return jsonify({'error': f'Le champ {field} est requis'}), 400
    
    if data['type_stock'] not in ['input', 'output']:
        return jsonify({'error': 'type_stock doit être "input" ou "output"'}), 400

    notes = data.get('notes')
    ticket_bmc = data.get('ticket_bmc')
    nom_prenom = data.get('nom_prenom')
    cause_installation = data.get('cause_installation_materiel')
    produits_installes = data.get('produits_installes')
    cause_recuperation = data.get('cause_recuperation_materiel')
    produits_recuperes = data.get('produits_recuperes')
    
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    # Vérifier que l'article existe dans la table articles
    cur.execute('SELECT id FROM articles WHERE name = %s', (data['article'],))
    article_row = cur.fetchone()
    if not article_row:
        cur.close()
        conn.close()
        return jsonify({'error': "L'article n'existe pas. Ajoutez-le d'abord dans la table articles."}), 400
    
    cur.execute(
        '''INSERT INTO stock (
               sn, article, etat, type_stock, tag_integration,
               notes, ticket_bmc, nom_prenom,
               cause_installation_materiel, produits_installes,
               cause_recuperation_materiel, produits_recuperes,
               created_at, updated_at
           )
           VALUES (%s, %s, %s, %s, 'x',
                   %s, %s, %s,
                   %s, %s,
                   %s, %s,
                   CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)''',
        (
            data['sn'], data['article'], data['etat'], data['type_stock'],
            notes, ticket_bmc, nom_prenom,
            cause_installation, produits_installes,
            cause_recuperation, produits_recuperes
        )
    )

    new_stock_id = cur.lastrowid
    conn.commit()

    cur.execute('SELECT * FROM stock WHERE id = %s', (new_stock_id,))
    new_stock = cur.fetchone()
    cur.close()
    conn.close()
    
    stock_dict = dict(new_stock)
    stock_dict['created_at'] = stock_dict['created_at'].isoformat() if stock_dict['created_at'] else None
    stock_dict['updated_at'] = stock_dict['updated_at'].isoformat() if stock_dict['updated_at'] else None
    
    return jsonify(stock_dict), 201

@app.route('/api/stock/<int:id>', methods=['PUT'])
@token_required
def update_stock(current_user, id):
    """Met à jour une entrée de stock (sauf le S/N)"""
    data = request.get_json()
    
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    
    cur.execute('SELECT * FROM stock WHERE id = %s', (id,))
    existing = cur.fetchone()
    
    if existing is None:
        cur.close()
        conn.close()
        return jsonify({'error': 'Stock non trouvé'}), 404
    
    article = data.get('article', existing['article'])
    if not article:
        cur.close()
        conn.close()
        return jsonify({'error': "L'article est requis"}), 400

    # Vérifier que l'article existe dans la table articles
    cur.execute('SELECT id FROM articles WHERE name = %s', (article,))
    if not cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({'error': "L'article n'existe pas. Ajoutez-le d'abord dans la table articles."}), 400
    etat = data.get('etat', existing['etat'])
    notes = data.get('notes', existing.get('notes'))
    ticket_bmc = data.get('ticket_bmc', existing.get('ticket_bmc'))
    nom_prenom = data.get('nom_prenom', existing.get('nom_prenom'))

    if existing['type_stock'] == 'output':
        cause_installation = data.get('cause_installation_materiel', existing.get('cause_installation_materiel'))
        produits_installes = data.get('produits_installes', existing.get('produits_installes'))
        cause_recuperation = existing.get('cause_recuperation_materiel')
        produits_recuperes = existing.get('produits_recuperes')
    else:
        cause_installation = existing.get('cause_installation_materiel')
        produits_installes = existing.get('produits_installes')
        cause_recuperation = data.get('cause_recuperation_materiel', existing.get('cause_recuperation_materiel'))
        produits_recuperes = data.get('produits_recuperes', existing.get('produits_recuperes'))
    
    cur.execute(
        '''UPDATE stock 
           SET article = %s,
               etat = %s,
               notes = %s,
               ticket_bmc = %s,
               nom_prenom = %s,
               cause_installation_materiel = %s,
               produits_installes = %s,
               cause_recuperation_materiel = %s,
               produits_recuperes = %s,
               tag_integration = 'x',
               updated_at = CURRENT_TIMESTAMP
           WHERE id = %s''',
        (
            article,
            etat,
            notes,
            ticket_bmc,
            nom_prenom,
            cause_installation,
            produits_installes,
            cause_recuperation,
            produits_recuperes,
            id
        )
    )
    
    conn.commit()

    cur.execute('SELECT * FROM stock WHERE id = %s', (id,))
    updated_stock = cur.fetchone()
    cur.close()
    conn.close()
    
    stock_dict = dict(updated_stock)
    stock_dict['created_at'] = stock_dict['created_at'].isoformat() if stock_dict['created_at'] else None
    stock_dict['updated_at'] = stock_dict['updated_at'].isoformat() if stock_dict['updated_at'] else None
    
    return jsonify(stock_dict)

@app.route('/api/stock/<int:id>', methods=['DELETE'])
@token_required
def delete_stock(current_user, id):
    """Supprime une entrée de stock (seulement si tag_integration = 'x')"""
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    
    cur.execute('SELECT * FROM stock WHERE id = %s', (id,))
    existing = cur.fetchone()
    
    if existing is None:
        cur.close()
        conn.close()
        return jsonify({'error': 'Stock non trouvé'}), 404
    
    if existing['tag_integration'] != 'x':
        cur.close()
        conn.close()
        return jsonify({'error': 'Cette donnée est déjà intégrée et ne peut pas être supprimée'}), 403
    
    cur.execute('DELETE FROM stock WHERE id = %s', (id,))
    conn.commit()
    cur.close()
    conn.close()
    
    return jsonify({'message': 'Stock supprimé avec succès'}), 200

def init_admin_user():
    """Crée l'utilisateur admin par défaut s'il n'existe pas"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        
        # Vérifier si l'admin existe
        cur.execute('SELECT id FROM users WHERE username = %s', ('admin',))
        if not cur.fetchone():
            # Créer l'admin avec le mot de passe 'admin123'
            password_hash = generate_password_hash('admin123')
            cur.execute(
                '''INSERT INTO users (username, password_hash, role, created_at)
                   VALUES (%s, %s, %s, CURRENT_TIMESTAMP)''',
                ('admin', password_hash, 'admin')
            )
            conn.commit()
            print("✅ Utilisateur admin créé avec succès (mot de passe: admin123)")
        else:
            print("ℹ️ Utilisateur admin déjà existant")
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"⚠️ Erreur lors de la création de l'admin: {e}")

# Initialiser l'admin lors du chargement du module (utile avec gunicorn)
init_admin_user()

if __name__ == '__main__':
    # Initialiser l'admin au démarrage en mode debug local
    import time
    time.sleep(2)  # Attendre que la base de données soit prête
    init_admin_user()
    app.run(host='0.0.0.0', port=5000, debug=True)

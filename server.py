import sqlite3
from flask import Flask, request, jsonify, g, send_file
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import enum
from marshmallow import Schema, fields, validate, ValidationError, EXCLUDE
import traceback
import os
from datetime import datetime
import io
from openpyxl import Workbook


# --- App Initialization ---
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', '!@#$%^&*()1234567890qwertyUIOP')

app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True
)

CORS(app)
# CORS(app, supports_credentials=True, origins=["https://lasued-ticketer.vercel.app", "http://localhost:5173"])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_login'

DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), "app.db")


# --- Database helpers ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# --- Enum ---
class UsageEnum(enum.Enum):
    available = 'available'
    assigned = 'assigned'


# --- Marshmallow Schemas (same as before) ---
class ReceiptRegSchema(Schema):
    first_name = fields.Str(required=True, validate=validate.Length(min=1))
    last_name = fields.Str(required=True, validate=validate.Length(min=1))
    other_name = fields.Str()
    matric_number = fields.Str(required=True, validate=validate.Length(min=1))
    email = fields.Email(required=True)
    phone_number = fields.Str(required=True, validate=validate.Length(min=7))


class UserLoginSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    role = fields.Str(required=True)


class RecordUpdateSchema(Schema):
    id = fields.Int(required=True)
    first_name = fields.Str()
    last_name = fields.Str()
    other_name = fields.Str(allow_none=True)
    matric_number = fields.Str()
    email = fields.Email()
    phone_number = fields.Str()
    faculty = fields.Str(allow_none=True)
    department = fields.Str(allow_none=True)
    level = fields.Str(allow_none=True)
    token_id = fields.Str(allow_none=True)
    token = fields.Str(allow_none=True)
    usage = fields.Str(allow_none=True)
    source = fields.Str(allow_none=True)

    class Meta:
        unknown = EXCLUDE


# --- User class for flask-login ---
class User(UserMixin):
    def __init__(self, id_, username, password_hash, role):
        self.id = id_
        self.username = username
        self.password_hash = password_hash
        self.role = role

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if user:
        return User(user['id'], user['username'], user['password_hash'], user['role'])
    return None


@login_manager.unauthorized_handler
def unauthorized_callback():
    return jsonify({'error': 'Authentication required'}), 401


# --- Routes ---
@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Welcome to the Flask API home page", "status": "API is running"}), 200


@app.route('/api/receipt_reg', methods=['POST'])
def receipt_registration():
    json_data = request.get_json()
    try:
        validated_data = ReceiptRegSchema().load(json_data)
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

    db = get_db()
    exists = db.execute('SELECT id FROM receipt_reg WHERE matric_number=?',
                        (validated_data['matric_number'],)).fetchone()
    if exists:
        return jsonify({'error': 'Matric number already registered.'}), 409

    try:
        db.execute(
            'INSERT INTO receipt_reg (first_name, last_name, other_name, matric_number, email, phone_number) VALUES (?, ?, ?, ?, ?, ?)',
            (validated_data['first_name'], validated_data['last_name'], validated_data.get('other_name', ''),
             validated_data['matric_number'], validated_data['email'], validated_data['phone_number']))
        db.execute(
            'INSERT INTO record (first_name, last_name, other_name, matric_number, email, phone_number, source) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (validated_data['first_name'], validated_data['last_name'], validated_data.get('other_name', ''),
             validated_data['matric_number'], validated_data['email'], validated_data['phone_number'], 'receipt_reg'))
        db.commit()

        reg = db.execute('SELECT * FROM receipt_reg WHERE matric_number=?',
                         (validated_data['matric_number'],)).fetchone()

        return jsonify({
            'message': 'Registration successful!',
            'receipt': {
                'id': reg['id'],
                'first_name': reg['first_name'],
                'last_name': reg['last_name'],
                'other_name': reg['other_name'],
                'matric_number': reg['matric_number'],
                'email': reg['email'],
                'phone_number': reg['phone_number']
            }
        }), 201
    except Exception as e:
        db.rollback()
        app.logger.error(f"Database operation failed: {e}")
        return jsonify({'error': 'Database operation failed.'}), 500


@app.route('/api/login', methods=['POST'])
def user_login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No input data provided'}), 400

    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if not username or not password or not role:
        return jsonify({'error': 'Username, password and role are required'}), 400

    db = get_db()
    user_row = db.execute('SELECT * FROM users WHERE username=? AND role=?', (username, role)).fetchone()

    if user_row:
        user = User(user_row['id'], user_row['username'], user_row['password_hash'], user_row['role'])
        if user.check_password(password):
            login_user(user)
            return jsonify({
                'message': 'Login successful',
                'username': user.username,
                'role': user.role
            }), 200

    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200


@app.route('/api/receipt_records', methods=['GET'])
@login_required
def get_receipt_records():
    db = get_db()
    try:
        rows = db.execute('SELECT * FROM receipt_reg').fetchall()
        result = [dict(row) for row in rows]
        return jsonify(result), 200
    except Exception as e:
        app.logger.error(f"Error fetching receipts: {e}")
        return jsonify({'error': 'Failed to retrieve receipt records.'}), 500


@app.route('/api/download_receipt_records', methods=['GET'])
@login_required
def download_receipt_records():
    db = get_db()
    try:
        rows = db.execute('SELECT * FROM receipt_reg').fetchall()

        wb = Workbook()
        ws = wb.active
        ws.title = "Receipt Records"

        if rows:
            # Write header dynamically from row keys (column names)
            headers = rows[0].keys()
            ws.append(headers)

            # Write data rows
            for row in rows:
                ws.append([row[col] for col in headers])
        else:
            # No records - add a placeholder header
            ws.append(['No records found'])

        # Save workbook to a bytes buffer
        excel_stream = io.BytesIO()
        wb.save(excel_stream)
        excel_stream.seek(0)

        return send_file(
            excel_stream,
            as_attachment=True,
            attachment_filename='receipt_records.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    except Exception as e:
        app.logger.error(f"Failed to create Excel file: {e}")
        return jsonify({'error': 'Failed to generate Excel file.'}), 500


@app.route('/api/record', methods=['GET'])
@login_required
def handle_record_log():
    page = max(1, int(request.args.get('page', 1)))
    per_page = max(1, int(request.args.get('per_page', 20)))
    source = request.args.get('source')

    db = get_db()
    try:
        params = []
        query = 'SELECT * FROM record'
        if source:
            query += ' WHERE source=?'
            params.append(source)
        query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
        params.extend([per_page, (page - 1) * per_page])

        records = db.execute(query, params).fetchall()

        total_query = 'SELECT COUNT(*) FROM record' + (' WHERE source=?' if source else '')
        total = db.execute(total_query, ([source] if source else [])).fetchone()[0]

        data = [dict(row) for row in records]

        return jsonify({
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page,
            'records': data
        }), 200
    except Exception as e:
        app.logger.error(f'Failed to retrieve record log: {e}')
        return jsonify({'error': 'Failed to retrieve record log.'}), 500


@app.route('/api/record/update_metadata', methods=['PUT'])
@login_required
def update_record_metadata():
    json_data = request.get_json()
    try:
        validated = RecordUpdateSchema().load(json_data)
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

    db = get_db()
    rec = db.execute('SELECT * FROM record WHERE id=?', (validated['id'],)).fetchone()
    if not rec:
        return jsonify({'error': f'Record with id {validated["id"]} not found.'}), 404

    try:
        fields = [k for k in validated if k != 'id']
        values = [validated[k] for k in fields]
        set_clause = ', '.join(f"{field}=?" for field in fields)

        db.execute(f'UPDATE record SET {set_clause} WHERE id=?', values + [validated['id']])
        db.commit()
    except Exception as e:
        db.rollback()
        app.logger.error(f"Failed to update record metadata: {e}")
        return jsonify({'error': 'Failed to update record metadata.'}), 500

    updated_record = db.execute('SELECT * FROM record WHERE id=?', (validated['id'],)).fetchone()
    return jsonify({
        'message': 'Record updated successfully.',
        'updated_record': dict(updated_record)
    }), 200


class UploadTicketItemSchema(Schema):
    token_id = fields.Str(required=True)
    token = fields.Str(required=True)
    usage = fields.Str(required=True, validate=validate.OneOf([e.value for e in UsageEnum]))


@app.route('/api/upload', methods=['POST'])
@login_required
def handle_upload_json_array():
    json_data = request.get_json()
    if not isinstance(json_data, list):
        return jsonify({'error': 'Request body must be a JSON array.'}), 400
    schema = UploadTicketItemSchema()
    errors = []
    valid_items = []
    for idx, item in enumerate(json_data):
        try:
            validated = schema.load(item)
            valid_items.append(validated)
        except ValidationError as e:
            errors.append({'index': idx, 'errors': e.messages})
    if errors:
        return jsonify({'validation_errors': errors}), 400
    db = get_db()
    try:
        saved_tickets = []
        for item in valid_items:
            db.execute('INSERT INTO ticket (token_id, token, usage) VALUES (?, ?, ?)',
                       (item['token_id'], item['token'], item['usage']))
            saved_tickets.append(item)
        db.commit()
    except Exception as e:
        db.rollback()
        app.logger.error(f"Upload error: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to save data.'}), 500
    return jsonify({
        'message': f'Successfully saved {len(saved_tickets)} tickets!',
        'tickets': saved_tickets
    }), 201


@app.route('/api/tickets', methods=['GET'])
@login_required
def get_tickets():
    db = get_db()
    try:
        tickets = db.execute('SELECT * FROM ticket').fetchall()
        data = []
        for t in tickets:
            matric_number = ''
            if t['usage'] == UsageEnum.assigned.value:
                record = db.execute('SELECT matric_number FROM record WHERE token=?', (t['token'],)).fetchone()
                if record:
                    matric_number = record['matric_number']
            data.append({
                'token_id': t['token_id'],
                'token': t['token'],
                'usage': t['usage'],
                'matric_number': matric_number
            })
        return jsonify(data), 200
    except Exception as e:
        app.logger.error(f"Ticket fetch error: {e}")
        return jsonify({'error': 'Failed to retrieve tickets.'}), 500


class AssignTokenSchema(Schema):
    matric_number = fields.Str(required=True)
    token = fields.Str(required=True)


@app.route('/api/assign', methods=['POST'])
@login_required
def assign_token_to_matric():
    json_data = request.get_json()
    try:
        validated = AssignTokenSchema().load(json_data)
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

    matric_number = validated['matric_number']
    token_value = validated['token']

    db = get_db()
    ticket = db.execute('SELECT * FROM ticket WHERE token=?', (token_value,)).fetchone()
    if not ticket:
        return jsonify({'error': f'Token "{token_value}" not found.'}), 404
    if ticket['usage'] == UsageEnum.assigned.value:
        return jsonify({'error': f'Token "{token_value}" is already assigned.'}), 409

    records_for_matric = db.execute('SELECT * FROM record WHERE matric_number=? ORDER BY id ASC',
                                    (matric_number,)).fetchall()
    if not records_for_matric:
        return jsonify({'error': f'No record found for matric number "{matric_number}". Assignment failed.'}), 404

    main_fields = ['first_name', 'last_name', 'email', 'phone_number', 'faculty', 'department', 'level']

    all_incomplete = True
    for rec in records_for_matric:
        if any(rec[field] not in [None, ''] and str(rec[field]).strip() != '' for field in main_fields):
            all_incomplete = False
            break
    if all_incomplete:
        return jsonify({
            'error': 'Assignment denied. All records for this matric number have incomplete required fields.'
        }), 400

    all_complete_and_assigned = True
    for rec in records_for_matric:
        complete = all(rec[field] not in [None, ''] and str(rec[field]).strip() != '' for field in main_fields)
        token_assigned = rec['token'] not in [None, '']
        if not (complete and token_assigned):
            all_complete_and_assigned = False
            break
    if all_complete_and_assigned:
        return jsonify({
            'error': 'All records for this matric number are complete and already assigned tokens.'
        }), 409

    assignable_record = None
    for rec in records_for_matric:
        complete = all(rec[field] not in [None, ''] and str(rec[field]).strip() != '' for field in main_fields)
        has_no_token = rec['token'] in [None, '']
        if complete and has_no_token:
            assignable_record = rec
            break

    if not assignable_record:
        return jsonify({
            'error': 'No suitable record found for assignment: all available records either lack required data or already have tokens.'
        }), 400

    try:
        db.execute('UPDATE record SET token_id=?, token=?, usage=?, source=? WHERE id=?',
                   (ticket['token_id'], ticket['token'], UsageEnum.assigned.value, 'assign', assignable_record['id']))
        db.execute('UPDATE ticket SET usage=? WHERE token=?', (UsageEnum.assigned.value, ticket['token']))
        db.commit()
    except Exception as e:
        db.rollback()
        app.logger.error(f"Assign error: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to assign token.'}), 500

    updated_record = db.execute('SELECT * FROM record WHERE id=?', (assignable_record['id'],)).fetchone()

    return jsonify({
        'message': f'Token "{token_value}" assigned to matric number "{matric_number}".',
        'updated_ticket': {
            'token_id': ticket['token_id'],
            'token': ticket['token'],
            'usage': UsageEnum.assigned.value
        },
        'updated_record': dict(updated_record)
    }), 200


# --- Database initialization ---
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS receipt_reg (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        first_name TEXT NOT NULL,
                        last_name TEXT NOT NULL,
                        other_name TEXT,
                        matric_number TEXT UNIQUE NOT NULL,
                        email TEXT NOT NULL,
                        phone_number TEXT NOT NULL
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS record (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        first_name TEXT,
                        last_name TEXT,
                        other_name TEXT,
                        matric_number TEXT,
                        email TEXT,
                        phone_number TEXT,
                        faculty TEXT,
                        department TEXT,
                        level TEXT,
                        token_id TEXT,
                        token TEXT UNIQUE,
                        usage TEXT,
                        source TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS ticket (
                        token TEXT PRIMARY KEY,
                        token_id TEXT NOT NULL,
                        usage TEXT NOT NULL
                    )''')
        # Create admin user if not exists
        c.execute("SELECT * FROM users WHERE username='admin'")
        if not c.fetchone():
            admin_pass_hash = generate_password_hash('adminpassword')
            c.execute('INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)',
                      ('PF001', 'admin', admin_pass_hash, 'admin'))
        conn.commit()


if __name__ == '__main__':
    init_db()
    app.run(debug=True)

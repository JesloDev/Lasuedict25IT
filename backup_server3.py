from flask import Flask, request, jsonify, g, send_file
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import enum
from marshmallow import Schema, fields, validate, ValidationError, EXCLUDE
import traceback
import os
import io
from openpyxl import Workbook
from flask_mysqldb import MySQL

# --- App Initialization ---
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', '!@#$%^&*()1234567890qwertyUIOP')

app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    MYSQL_HOST=os.getenv('MYSQL_HOST', 'localhost'),
    MYSQL_USER=os.getenv('MYSQL_USER', 'root'),
    MYSQL_PASSWORD=os.getenv('MYSQL_PASSWORD', 'password'),
    MYSQL_DB=os.getenv('MYSQL_DB', 'ticketer_db'),
    MYSQL_CURSORCLASS='DictCursor',  # To get dict-like cursor result
)

CORS(app, supports_credentials=True, origins=["https://lasued-ticketer.vercel.app", "http://localhost:5173"])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_login'

mysql = MySQL(app)

# --- Enum ---
class UsageEnum(enum.Enum):
    available = 'available'
    assigned = 'assigned'

# --- Marshmallow Schemas ---
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
    token_usage = fields.Str(allow_none=True)
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
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM users WHERE id=%s', (user_id,))
    user = cur.fetchone()
    cur.close()
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

    cur = mysql.connection.cursor()
    cur.execute('SELECT id FROM receipt_reg WHERE matric_number=%s', (validated_data['matric_number'],))
    exists = cur.fetchone()
    if exists:
        cur.close()
        return jsonify({'error': 'Matric number already registered.'}), 409

    try:
        cur.execute(
            'INSERT INTO receipt_reg (first_name, last_name, other_name, matric_number, email, phone_number) VALUES (%s, %s, %s, %s, %s, %s)',
            (
                validated_data['first_name'],
                validated_data['last_name'],
                validated_data.get('other_name', ''),
                validated_data['matric_number'],
                validated_data['email'],
                validated_data['phone_number']
            )
        )
        cur.execute(
            'INSERT INTO record (first_name, last_name, other_name, matric_number, email, phone_number, source) VALUES (%s, %s, %s, %s, %s, %s, %s)',
            (
                validated_data['first_name'],
                validated_data['last_name'],
                validated_data.get('other_name', ''),
                validated_data['matric_number'],
                validated_data['email'],
                validated_data['phone_number'],
                'receipt_reg'
            )
        )
        mysql.connection.commit()

        cur.execute('SELECT * FROM receipt_reg WHERE matric_number=%s', (validated_data['matric_number'],))
        reg = cur.fetchone()
        cur.close()

        return jsonify({
            'message': 'Registration successful!',
            'receipt': reg
        }), 201
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
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

    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM users WHERE username=%s AND role=%s', (username, role))
    user_row = cur.fetchone()

    if user_row:
        user = User(user_row['id'], user_row['username'], user_row['password_hash'], user_row['role'])
        if user.check_password(password):
            login_user(user)
            cur.close()
            return jsonify({
                'message': 'Login successful',
                'username': user.username,
                'role': user.role
            }), 200

    cur.close()
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/receipt_records', methods=['GET'])
@login_required
def get_receipt_records():
    cur = mysql.connection.cursor()
    try:
        cur.execute('SELECT * FROM receipt_reg')
        rows = cur.fetchall()
        cur.close()
        return jsonify(rows), 200
    except Exception as e:
        cur.close()
        app.logger.error(f"Error fetching receipts: {e}")
        return jsonify({'error': 'Failed to retrieve receipt records.'}), 500

@app.route('/api/download_receipt_records', methods=['GET'])
@login_required
def download_receipt_records():
    cur = mysql.connection.cursor()
    try:
        cur.execute('SELECT * FROM receipt_reg')
        rows = cur.fetchall()
        cur.close()

        wb = Workbook()
        ws = wb.active
        ws.title = "Receipt Records"

        if rows:
            headers = rows[0].keys()
            ws.append(headers)
            for row in rows:
                ws.append([row[h] for h in headers])
        else:
            ws.append(['No records found'])

        excel_stream = io.BytesIO()
        wb.save(excel_stream)
        excel_stream.seek(0)

        return send_file(
            excel_stream,
            as_attachment=True,
            download_name='receipt_records.xlsx',
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

    cur = mysql.connection.cursor()
    try:
        params = []
        query = 'SELECT * FROM record'
        if source:
            query += ' WHERE source=%s'
            params.append(source)
        query += ' ORDER BY timestamp DESC LIMIT %s OFFSET %s'
        params.extend([per_page, (page - 1) * per_page])
        cur.execute(query, tuple(params))

        records = cur.fetchall()

        count_query = 'SELECT COUNT(*) AS total FROM record' + (' WHERE source=%s' if source else '')
        cur.execute(count_query, (source,) if source else ())
        total = cur.fetchone()['total']
        cur.close()

        return jsonify({
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page,
            'records': records
        }), 200
    except Exception as e:
        cur.close()
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

    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM record WHERE id=%s', (validated['id'],))
    rec = cur.fetchone()
    if not rec:
        cur.close()
        return jsonify({'error': f'Record with id {validated["id"]} not found.'}), 404

    try:
        fields = [k for k in validated if k != 'id']
        values = [validated[k] for k in fields]
        set_clause = ', '.join(f"{field}=%s" for field in fields)

        cur.execute(f'UPDATE record SET {set_clause} WHERE id=%s', values + [validated['id']])
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        app.logger.error(f"Failed to update record metadata: {e}")
        return jsonify({'error': 'Failed to update record metadata.'}), 500

    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM record WHERE id=%s', (validated['id'],))
    updated_record = cur.fetchone()
    cur.close()
    return jsonify({
        'message': 'Record updated successfully.',
        'updated_record': updated_record
    }), 200

class UploadTicketItemSchema(Schema):
    token_id = fields.Str(required=True)
    token = fields.Str(required=True)
    token_usage = fields.Str(required=True, validate=validate.OneOf([e.value for e in UsageEnum]))

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
    cur = mysql.connection.cursor()
    try:
        for item in valid_items:
            cur.execute('INSERT INTO ticket (token_id, token, token_usage) VALUES (%s, %s, %s)',
                        (item['token_id'], item['token'], item['token_usage']))
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        app.logger.error(f"Upload error: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to save data.'}), 500
    return jsonify({
        'message': f'Successfully saved {len(valid_items)} tickets!',
        'tickets': valid_items
    }), 201

@app.route('/api/tickets', methods=['GET'])
@login_required
def get_tickets():
    cur = mysql.connection.cursor()
    try:
        cur.execute('SELECT * FROM ticket')
        tickets = cur.fetchall()
        data = []
        for t in tickets:
            matric_number = ''
            if t['token_usage'] == UsageEnum.assigned.value:
                cur.execute('SELECT matric_number FROM record WHERE token=%s', (t['token'],))
                record = cur.fetchone()
                matric_number = record['matric_number'] if record else ''
            data.append({
                'token_id': t['token_id'],
                'token': t['token'],
                'token_usage': t['token_usage'],
                'matric_number': matric_number
            })
        cur.close()
        return jsonify(data), 200
    except Exception as e:
        cur.close()
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

    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM ticket WHERE token=%s', (token_value,))
    ticket = cur.fetchone()
    if not ticket:
        cur.close()
        return jsonify({'error': f'Token "{token_value}" not found.'}), 404
    if ticket['token_usage'] == UsageEnum.assigned.value:
        cur.close()
        return jsonify({'error': f'Token "{token_value}" is already assigned.'}), 409

    cur.execute('SELECT * FROM record WHERE matric_number=%s ORDER BY id ASC', (matric_number,))
    records_for_matric = cur.fetchall()
    if not records_for_matric:
        cur.close()
        return jsonify({'error': f'No record found for matric number "{matric_number}". Assignment failed.'}), 404

    main_fields = ['first_name', 'last_name', 'email', 'phone_number', 'faculty', 'department', 'level']

    all_incomplete = True
    for rec in records_for_matric:
        if any(rec[field] not in [None, ''] and str(rec[field]).strip() != '' for field in main_fields):
            all_incomplete = False
            break
    if all_incomplete:
        cur.close()
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
        cur.close()
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
        cur.close()
        return jsonify({
            'error': 'No suitable record found for assignment: all available records either lack required data or already have tokens.'
        }), 400

    try:
        cur.execute('UPDATE record SET token_id=%s, token=%s, token_usage=%s, source=%s WHERE id=%s',
                    (ticket['token_id'], ticket['token'], UsageEnum.assigned.value, 'assign', assignable_record['id']))
        cur.execute('UPDATE ticket SET token_usage=%s WHERE token=%s', (UsageEnum.assigned.value, ticket['token']))
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        app.logger.error(f"Assign error: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to assign token.'}), 500

    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM record WHERE id=%s', (assignable_record['id'],))
    updated_record = cur.fetchone()
    cur.close()

    return jsonify({
        'message': f'Token "{token_value}" assigned to matric number "{matric_number}".',
        'updated_ticket': {
            'token_id': ticket['token_id'],
            'token': ticket['token'],
            'token_usage': UsageEnum.assigned.value
        },
        'updated_record': updated_record
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

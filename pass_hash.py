from werkzeug.security import generate_password_hash

admin = generate_password_hash('admin')
registrar = generate_password_hash('register')
uploader = generate_password_hash('upload')

print(admin)
print(registrar)
print(uploader)
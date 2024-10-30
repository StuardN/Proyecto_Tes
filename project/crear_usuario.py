from werkzeug.security import generate_password_hash
from app import db, Usuario, app  # Importa la instancia de db y Usuario de app.py

def crear_usuarios():
    with app.app_context():  # Usa el contexto de la aplicación
        # Crear usuario RRHH
        nombre_rrhh = "Erlyn"
        apellidos_rrhh = "Naranjo"
        email_rrhh = "erlyn.naranjo@ejemplo.com"
        contrasena_rrhh = "contraseña_rrhh"  # Contraseña para RRHH
        direccion_rrhh = "Calle B 45 y 46"
        celular_rrhh = "0958598"
        id_rol_rrhh = 2  # Rol para RRHH

        # Hashear la contraseña
        contrasena_hash_rrhh = generate_password_hash(contrasena_rrhh)

        # Crear usuario RRHH en la base de datos
        nuevo_usuario_rrhh = Usuario(
            nombre_usuario=nombre_rrhh,
            apellidos=apellidos_rrhh,
            email=email_rrhh,
            contraseña=contrasena_hash_rrhh,
            direccion=direccion_rrhh,
            celular=celular_rrhh,
            id_rol=id_rol_rrhh
        )

        # Crear usuario Administrador
        nombre_admin = "Admin"
        apellidos_admin = "Usuario"
        email_admin = "admin@ejemplo.com"
        contrasena_admin = ""  # Contraseña para Administrador
        direccion_admin = "Av. Admin 123"
        celular_admin = "1234567890"
        id_rol_admin = 1  # Rol para Administrador

        # Hashear la contraseña
        contrasena_hash_admin = generate_password_hash(contrasena_admin)

        # Crear usuario Administrador en la base de datos
        nuevo_usuario_admin = Usuario(
            nombre_usuario=nombre_admin,
            apellidos=apellidos_admin,
            email=email_admin,
            contraseña=contrasena_hash_admin,
            direccion=direccion_admin,
            celular=celular_admin,
            id_rol=id_rol_admin
        )

        # Crear las tablas si no existen
        db.create_all()  

        # Agregar usuarios a la sesión y confirmar
        db.session.add(nuevo_usuario_rrhh)
        db.session.add(nuevo_usuario_admin)
        db.session.commit()
        print("Usuarios creados exitosamente.")

if __name__ == "__main__":
    crear_usuarios()

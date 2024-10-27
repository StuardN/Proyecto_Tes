from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)

# Configuraciones de la aplicación
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://tesis:123456@DESKTOP-SAV0H0J\\SQLExpress/RecursosHumanos3?driver=ODBC+Driver+17+for+SQL+Server'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialización de la base de datos
db = SQLAlchemy(app)

# Inicialización del administrador de inicio de sesión
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class Usuario(db.Model, UserMixin):
    __tablename__ = 'Usuarios'
    
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre_usuario = db.Column(db.String(100), nullable=False)
    apellidos = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    contraseña = db.Column(db.String(500), nullable=False)
    direccion = db.Column(db.String(200))
    celular = db.Column(db.String(15))
    id_rol = db.Column(db.Integer, nullable=False)
    fecha_registro = db.Column(db.Date, default=datetime.datetime.utcnow)
    estado = db.Column(db.String(50), default='Activo')

    def set_password(self, password):
        """Cifra la contraseña usando un hash seguro."""
        self.contraseña = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        """Verifica que la contraseña ingresada coincida con el hash almacenado."""
        return check_password_hash(self.contraseña, password)

    def get_id(self):
        return str(self.id_usuario)

# Función para cargar el usuario en la sesión
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Ruta principal redirige al login
@app.route('/')
def home():
    return redirect(url_for('login'))

# Ruta de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = Usuario.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            if user.id_rol == 1:  # Administrador
                return redirect(url_for('admin_dashboard'))
            elif user.id_rol == 2:  # RRHH
                return redirect(url_for('rrhh_dashboard'))
            elif user.id_rol == 3:  # Postulante
                return redirect(url_for('postulante_dashboard'))
        else:
            flash('Login incorrecto. Verifica tus credenciales.')

    return render_template('login.html')

# Ruta de registro de usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nombre_usuario = request.form.get('nombre_usuario')
        apellidos = request.form.get('apellidos')
        email = request.form.get('email')
        password = request.form.get('password')
        direccion = request.form.get('direccion')
        celular = request.form.get('celular')
        id_rol = 3  # Rol por defecto para nuevos usuarios: Postulante

        # Verificar si el usuario ya existe
        existing_user = Usuario.query.filter_by(email=email).first()
        if existing_user:
            flash('El usuario ya existe. Intenta con otro correo electrónico.')
            return redirect(url_for('register'))

        # Crear un nuevo usuario
        new_user = Usuario(
            nombre_usuario=nombre_usuario,
            apellidos=apellidos,
            email=email,
            direccion=direccion,
            celular=celular,
            id_rol=id_rol
        )
        new_user.set_password(password)  # Asignar la contraseña

        db.session.add(new_user)

        try:
            db.session.commit()
            flash('Usuario registrado correctamente.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al registrar el usuario: {str(e)}')

    return render_template('register.html')

# Rutas para los diferentes dashboards
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.id_rol == 1:
        return render_template('admin_dashboard.html')
    return redirect(url_for('login'))

@app.route('/rrhh_dashboard')
@login_required
def rrhh_dashboard():
    if current_user.id_rol == 2:
        return render_template('rrhh_dashboard.html')
    return redirect(url_for('login'))

@app.route('/postulante_dashboard')
@login_required
def postulante_dashboard():
    if current_user.id_rol == 3:
        return render_template('postulante_dashboard.html')
    return redirect(url_for('login'))

# Ruta para cerrar sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(debug=True)

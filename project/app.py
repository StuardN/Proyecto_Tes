from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)

# Configuración de la aplicación
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

class Categoria(db.Model):
    __tablename__ = 'Categorias'
    id_categoria = db.Column(db.Integer, primary_key=True)
    descripcion = db.Column(db.String(100), nullable=False)
    estado = db.Column(db.String(50), default='Activo')
    # relación inversa
    puestos = db.relationship('Puesto', backref='categoria', lazy=True)

class Puesto(db.Model):
    __tablename__ = 'Puestos'
    id_puesto = db.Column(db.Integer, primary_key=True)
    descripcion = db.Column(db.String, nullable=False)
    perfil = db.Column(db.String)
    requisitos = db.Column(db.String)
    id_categoria = db.Column(db.Integer, db.ForeignKey('Categorias.id_categoria'), nullable=False)


@app.route('/puestos', methods=['GET', 'POST'])
@login_required
def puestos():
    if request.method == 'POST':
        # Código para crear un nuevo puesto
        descripcion = request.form.get('descripcion')
        perfil = request.form.get('perfil')
        requisitos = request.form.get('requisitos')
        id_categoria = request.form.get('id_categoria')

        nuevo_puesto = Puesto(
            descripcion=descripcion,
            perfil=perfil,
            requisitos=requisitos,
            id_categoria=id_categoria
        )
        db.session.add(nuevo_puesto)
        db.session.commit()
        flash('Puesto creado exitosamente.')
        return redirect(url_for('puestos'))

    # Traer todos los puestos y categorías
    puestos = Puesto.query.all()
    lista_categorias = Categoria.query.all()  # Cambié el nombre a 'lista_categorias'
    print(puestos)  # Esto debería mostrar la lista de puestos en la consola
    print(lista_categorias)  # Esto debería mostrar la lista de categorías en la consola
    return render_template('puestos.html', puestos=puestos, categorias=lista_categorias)


# Ruta para eliminar un puesto
@app.route('/eliminar_puesto/<int:id>', methods=['POST'])
@login_required
def eliminar_puesto(id):
    puesto = Puesto.query.get_or_404(id)
    db.session.delete(puesto)
    db.session.commit()
    flash('Puesto eliminado exitosamente.')
    return redirect(url_for('puestos'))

# Ruta para editar un puesto
@app.route('/editar_puesto/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_puesto(id):
    puesto = Puesto.query.get_or_404(id)
    if request.method == 'POST':
        puesto.descripcion = request.form.get('descripcion')
        puesto.perfil = request.form.get('perfil')
        puesto.requisitos = request.form.get('requisitos')
        puesto.id_categoria = request.form.get('id_categoria')

        db.session.commit()
        flash('Puesto actualizado exitosamente.')
        return redirect(url_for('puestos'))

    categorias = Categoria.query.all()
    return render_template('editar_puesto.html', puesto=puesto, categorias=categorias)

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
            if user.id_rol == 1:
                return redirect(url_for('admin_dashboard'))
            elif user.id_rol == 2:
                return redirect(url_for('rrhh_dashboard'))
            elif user.id_rol == 3:
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
        id_rol = 3

        existing_user = Usuario.query.filter_by(email=email).first()
        if existing_user:
            flash('El usuario ya existe. Intenta con otro correo electrónico.')
            return redirect(url_for('register'))

        new_user = Usuario(
            nombre_usuario=nombre_usuario,
            apellidos=apellidos,
            email=email,
            direccion=direccion,
            celular=celular,
            id_rol=id_rol
        )
        new_user.set_password(password)

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
        return render_template('puestos.html')
    return redirect(url_for('login'))

@app.route('/rrhh_dashboard')
@login_required
def rrhh_dashboard():
    if current_user.id_rol == 2:
        return render_template('puestos.html')
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

# CATEGORIAS
# Ruta para crear y listar categorías
@app.route('/categorias', methods=['GET', 'POST'])
@login_required
def categorias():
    if request.method == 'POST':
        descripcion = request.form.get('descripcion')
        
        # Verificación para evitar descripciones duplicadas
        if Categoria.query.filter_by(descripcion=descripcion).first():
            flash('La categoría ya existe.')
            return redirect(url_for('categorias'))
        
        nueva_categoria = Categoria(descripcion=descripcion, estado='Activo')
        db.session.add(nueva_categoria)
        db.session.commit()
        flash('Categoría creada exitosamente.')
        return redirect(url_for('categorias'))

    categorias = Categoria.query.all()
    return render_template('categorias.html', categorias=categorias)

# Ruta para editar una categoría
@app.route('/editar_categoria/<int:id_categoria>', methods=['GET', 'POST'])
@login_required
def editar_categoria(id_categoria):
    categoria = Categoria.query.get_or_404(id_categoria)
    
    if request.method == 'POST':
        categoria.descripcion = request.form.get('descripcion')
        categoria.estado = request.form.get('estado')
        
        db.session.commit()
        flash('Categoría actualizada exitosamente.')
        return redirect(url_for('categorias'))

    return render_template('editar_categoria.html', categoria=categoria)

# Ruta para eliminar una categoría
@app.route('/eliminar_categoria/<int:id_categoria>', methods=['POST'])
@login_required
def eliminar_categoria(id_categoria):
    categoria = Categoria.query.get_or_404(id_categoria)
    puestos_asociados = Puesto.query.filter_by(id_categoria=id_categoria).all()
    
    if puestos_asociados:
        mensaje = "No se puede eliminar la categoría porque está en uso. Puestos asociados:"
        puestos = [p.descripcion for p in puestos_asociados]  # Asume que `descripcion` es el campo del puesto
        return render_template("error.html", mensaje=mensaje, puestos=puestos)
    
    # Si no hay puestos asociados, procede a eliminar la categoría
    db.session.delete(categoria)
    db.session.commit()
    flash('Categoría eliminada exitosamente.')
    return redirect(url_for('categorias'))

# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(debug=True)

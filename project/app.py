from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email import encoders
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, IntegerField, FileField
from wtforms.validators import InputRequired, Length, NumberRange, Email
from flask_wtf.file import FileRequired, FileAllowed
from datetime import datetime
import os
import io


load_dotenv()

# Leer las credenciales del correo de las variables de entorno
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
TEMP_PDF_PATH = 'uploads/postulacion.pdf'
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

# Configuración de la aplicación
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://tesis:123456@DESKTOP-SAV0H0J\\SQLExpress/RecursosHumanos3?driver=ODBC+Driver+17+for+SQL+Server'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


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
    edad = db.Column(db.Integer, nullable=False)
    celular = db.Column(db.String(15))
    id_rol = db.Column(db.Integer, nullable=False)
    fecha_registro = db.Column(db.Date, default=datetime.utcnow)
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
    puestos = db.relationship('Puesto', backref='categoria', lazy=True)

class Puesto(db.Model):
    __tablename__ = 'Puestos'
    id_puesto = db.Column(db.Integer, primary_key=True)
    descripcion = db.Column(db.String, nullable=False)
    perfil = db.Column(db.String)
    requisitos = db.Column(db.String)
    id_categoria = db.Column(db.Integer, db.ForeignKey('Categorias.id_categoria'), nullable=False)
    imagen = db.Column(db.String)  
    
class Postulaciones(db.Model):
    __tablename__ = 'Postulaciones'
    id_postulacion = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('Usuarios.id_usuario'), nullable=False)
    id_puesto = db.Column(db.Integer, db.ForeignKey('Puestos.id_puesto'), nullable=False)
    fecha_postulacion = db.Column(db.Date, default=datetime.utcnow)  # Cambio aquí
    
    usuario = db.relationship('Usuario', backref='postulaciones', lazy=True)
    puesto = db.relationship('Puesto', backref='postulaciones', lazy=True)

class FormularioPostulacion(db.Model):
    __tablename__ = 'FormularioPostulacion'
    id_formulario = db.Column(db.Integer, primary_key=True)
    id_postulacion = db.Column(db.Integer, db.ForeignKey('Postulaciones.id_postulacion'), nullable=False)
    experiencia = db.Column(db.String(255))
    educacion = db.Column(db.String(255))
    habilidades = db.Column(db.String(255))
    referencias = db.Column(db.String(255))
    fecha_formulario = db.Column(db.DateTime)

    postulacion = db.relationship('Postulaciones', backref='formularios')
    # Before inserting into FormularioPostulacion, make sure the id_postulacion exists
    
class CVForm(FlaskForm):
    nombre = StringField('Nombre', validators=[InputRequired(), Length(min=2, max=50)])
    apellidos = StringField('Apellidos', validators=[InputRequired(), Length(min=2, max=50)])
    direccion = StringField('Dirección', validators=[InputRequired(), Length(min=5, max=100)])
    aspiracion_salarial = IntegerField('Aspiración Salarial', validators=[InputRequired(), NumberRange(min=100)])
    correo = EmailField('Correo Electrónico', validators=[InputRequired(), Email()])
    telefono = StringField('Teléfono', validators=[InputRequired(), Length(min=7, max=15)])
    archivos = FileField('Subir CV (máximo 3 archivos)', validators=[
        FileRequired(),  # Asegúrate de que este validador esté importado correctamente
        FileAllowed(['pdf', 'doc', 'docx'], 'Solo se permiten archivos PDF y Word.')
    ])
 

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))  # Asegúrate de convertir `user_id` a `int`

@app.route('/puestos', methods=['GET', 'POST'])
@login_required
def puestos():
    if current_user.id_rol in [1, 2]:  # Permitir acceso solo a admin (1) y rrhh (2)
        if request.method == 'POST':
            # Obtener datos del formulario y crear el puesto
            descripcion = request.form['descripcion']
            perfil = request.form.get('perfil')
            requisitos = request.form.get('requisitos')
            id_categoria = request.form.get('id_categoria')
            imagen = None  # Por defecto, sin imagen

            # Manejar la imagen si se sube
            if 'imagen' in request.files:
                file = request.files['imagen']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    imagen = os.path.join('static/uploads', filename)

            # Crear el nuevo puesto
            nuevo_puesto = Puesto(
                descripcion=descripcion,
                perfil=perfil,
                requisitos=requisitos,
                id_categoria=id_categoria,
                imagen=imagen
            )

            db.session.add(nuevo_puesto)
            db.session.commit()
            flash('Puesto creado exitosamente.')

        # Obtener todos los puestos y categorías
        puestos = Puesto.query.all()
        categorias = Categoria.query.all()
        return render_template('puestos.html', puestos=puestos, categorias=categorias)
    else:
        flash('No tienes permisos para acceder a esta sección.', 'danger')
        return redirect(url_for('home'))  # Redirigir a una página apropiada

# Ruta para eliminar un puesto
@app.route('/eliminar_puesto/<int:id>', methods=['POST'])
@login_required
def eliminar_puesto(id):
    puesto = Puesto.query.get_or_404(id)
    
    # Eliminar la imagen del sistema de archivos si existe
    if puesto.imagen and os.path.exists(puesto.imagen):
        os.remove(puesto.imagen)
    
    db.session.delete(puesto)
    db.session.commit()
    flash('Puesto eliminado exitosamente.')
    return redirect(url_for('puestos'))

# Función para verificar si la extensión del archivo es válida
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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

        # Manejar la nueva imagen si es que se sube una
        imagen = puesto.imagen  # Imagen existente

        if 'imagen' in request.files:
            file = request.files['imagen']
            if file and allowed_file(file.filename):
                # Si ya existe una imagen, eliminarla del sistema de archivos
                if imagen and os.path.exists(imagen):
                    os.remove(imagen)
                
                # Guardar la nueva imagen
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                imagen = os.path.join('static/uploads', filename)
            
        puesto.imagen = imagen  # Actualizar la imagen en el modelo

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
                return redirect(url_for('postulante_1'))
        else:
            flash('Login incorrecto. Verifica tus credenciales.')

    return render_template('login.html')

#Register
@app.route('/register', methods=['GET', 'POST'])
@login_required  # Asegura que solo usuarios autenticados puedan acceder
def register():
   # if current_user.id_rol != 1:  # Solo admin puede acceder
    #    flash('No tienes permisos para acceder a esta sección.', 'danger')
     #   return redirect(url_for('home'))  # Redirigir a una página apropiada

    if request.method == 'POST':
        nombre_usuario = request.form.get('nombre_usuario')
        apellidos = request.form.get('apellidos')
        email = request.form.get('email')
        edad = request.form.get('edad')
        password = request.form.get('password')
        direccion = request.form.get('direccion')
        celular = request.form.get('celular')
        id_rol = 3  # Rol predeterminado

        # Validaciones básicas
        if not all([nombre_usuario, apellidos, email, edad, password]):
            flash('Todos los campos obligatorios deben ser completados.', 'danger')
            return redirect(url_for('register'))

        # Validar que la edad sea un número entero
        try:
            edad = int(edad)  # Convierte edad a entero
        except ValueError:
            flash('La edad debe ser un número válido.', 'danger')
            return redirect(url_for('register'))

        # Verificar si el correo ya existe
        existing_user = Usuario.query.filter_by(email=email).first()
        if existing_user:
            flash('El correo electrónico ya está registrado.', 'danger')
            return redirect(url_for('register'))

        # Crear nuevo usuario
        new_user = Usuario(
            nombre_usuario=nombre_usuario,
            apellidos=apellidos,
            email=email,
            direccion=direccion,
            celular=celular,
            id_rol=id_rol,
            edad=edad
        )
        new_user.set_password(password)  # Encriptar contraseña

        # Intentar guardar el usuario en la base de datos
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Usuario registrado exitosamente. Por favor, inicia sesión.', 'success')
            return redirect(url_for('login'))  # Cambia 'login' si tu ruta de login tiene otro nombre
        except Exception as e:
            db.session.rollback()
            print(f"Error al guardar en la base de datos: {e}")
            flash(f'Hubo un error al registrar al usuario: {str(e)}', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')


# Rutas para los diferentes dashboards
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.id_rol == 1:
        return render_template('admin.html')
    return redirect(url_for('login'))

@app.route('/rrhh_dashboard')
@login_required
def rrhh_dashboard():
    if current_user.id_rol == 2:
        return render_template('rrhh_index.html')
    return redirect(url_for('login'))


# Ruta para cerrar sesión
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/postulante_1')
@login_required
def postulante_1():
    # Verifica que el usuario tenga el rol de postulante (asumiendo que el rol '3' es de postulante)
    if current_user.id_rol == 3:
        # Obtener todos los puestos y categorías
        puestos = Puesto.query.all()
        categorias = Categoria.query.all()
        
        # Crear un diccionario donde cada categoría tiene una lista de puestos asociados
        categorias_con_puestos = {
            categoria.id_categoria: [puesto for puesto in puestos if puesto.id_categoria == categoria.id_categoria]
            for categoria in categorias
        }
        
        # Renderizar la plantilla con los datos obtenidos
        return render_template(
            'postulante_1.html',
            puestos=puestos,
            categorias=categorias,
            categorias_con_puestos=categorias_con_puestos
        )
    
    # Si el usuario no tiene el rol adecuado, lo redirige a la página de login
    return redirect(url_for('login'))


@app.route('/nosotros')
def nosotros():
    return render_template('nosotros.html')

@app.route('/admin_page')
def admin_page():
    return render_template('admin.html')

@app.route('/home_user')
def admin():
    return render_template('admin.html')

@app.route('/categorias', methods=['GET', 'POST'])
@login_required  # Asegura que solo usuarios autenticados puedan acceder
def categorias():
    if current_user.id_rol not in [1, 2]:  # Solo admin (1) y RRHH (2) pueden acceder
        flash('No tienes permisos para acceder a esta sección.', 'danger')
        return redirect(url_for('home'))  # Redirigir a una página apropiada

    if request.method == 'POST':
        nombre = request.form.get('descripcion')  # Usar 'descripcion' para coincidir con el formulario

        # Validaciones básicas
        if not nombre:
            flash('El nombre de la categoría es obligatorio.', 'danger')
            return redirect(url_for('categorias'))

        # Crear nueva categoría
        nueva_categoria = Categoria(descripcion=nombre)  # Cambiar a 'descripcion'
        try:
            db.session.add(nueva_categoria)
            db.session.commit()
            flash('Categoría creada exitosamente.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Hubo un error al crear la categoría: {str(e)}', 'danger')

    # Obtener todas las categorías existentes
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


######################### Rutas usuarios #########################

# Ruta para ver todos los usuarios
@app.route('/usuarios/crud')
@login_required  # Asegura que el usuario esté autenticado
def crud_usuarios():
    if current_user.id_rol != 1:  # Solo el rol 1 (admin) tiene acceso
        flash('No tienes permisos para acceder a esta sección.', 'danger')
        return redirect(url_for('home'))  # Redirige a una página adecuada

    usuarios = Usuario.query.all()  # Obtener los datos de los usuarios
    return render_template('crud_user.html', usuarios=usuarios)

# Ruta para listar usuarios
@app.route('/usuarios', methods=['GET'])
@login_required  # Requiere autenticación
def listar_usuarios():
    if current_user.id_rol != 1:  # Solo el rol 1 (admin) tiene acceso
        flash('No tienes permisos para acceder a esta sección.', 'danger')
        return redirect(url_for('home'))  # Redirigir a una página adecuada

    usuarios = Usuario.query.all()
    return render_template('crud_user.html', usuarios=usuarios)

# Ruta para agregar un nuevo usuario
@app.route('/usuarios/nuevo', methods=['GET', 'POST'])
@login_required  # Requiere autenticación
def nuevo_usuario():
    if current_user.id_rol != 1:  # Solo el rol 1 (admin) tiene acceso
        flash('No tienes permisos para acceder a esta sección.', 'danger')
        return redirect(url_for('home'))  # Redirigir a una página adecuada

    if request.method == 'POST':
        nombre = request.form['nombre']
        apellidos = request.form['apellidos']
        email = request.form['email']
        contraseña = request.form['contraseña']
        id_rol = request.form['id_rol']

        # Hash de la contraseña
        contraseña_hash = generate_password_hash(contraseña)

        nuevo_usuario = Usuario(
            nombre_usuario=nombre,
            apellidos=apellidos,
            email=email,
            contraseña=contraseña_hash,  # Contraseña encriptada
            id_rol=id_rol,
            estado='Activo'
        )
        try:
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash('Usuario creado exitosamente.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear el usuario: {str(e)}', 'danger')

        return redirect(url_for('listar_usuarios'))

    return render_template('nuevo_usuario.html')


@app.route('/usuarios/editar/<int:id_usuario>', methods=['GET', 'POST'])
@login_required  # Requiere autenticación
def editar_usuario(id_usuario):
    if current_user.id_rol != 1:  # Solo el rol 1 (admin) tiene acceso
        flash('No tienes permisos para acceder a esta sección.', 'danger')
        return redirect(url_for('home'))  # Redirigir a una página adecuada

    usuario = Usuario.query.get_or_404(id_usuario)

    if request.method == 'POST':
        nombre = request.form['nombre_usuario']
        apellidos = request.form['apellidos']
        email = request.form['email']

        # Actualizar datos
        usuario.nombre_usuario = nombre
        usuario.apellidos = apellidos
        usuario.email = email
        try:
            db.session.commit()
            flash('Usuario actualizado exitosamente.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar el usuario: {str(e)}', 'danger')

        return redirect(url_for('listar_usuarios'))

    return render_template('editar_usuario.html', usuario=usuario)


@app.route('/usuarios/eliminar/<int:id_usuario>', methods=['POST'])
@login_required  # Requiere autenticación
def eliminar_usuario(id_usuario):
    if current_user.id_rol != 1:  # Solo el rol 1 (admin) tiene acceso
        flash('No tienes permisos para acceder a esta sección.', 'danger')
        return redirect(url_for('home'))  # Redirigir a una página adecuada

    usuario = Usuario.query.get_or_404(id_usuario)
    try:
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuario eliminado exitosamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar el usuario: {str(e)}', 'danger')

    return redirect(url_for('listar_usuarios'))

# Ejecutar la aplicación
@app.route('/postulante_dashboard')
@login_required
def postulante_dashboard():
    if current_user.id_rol == 3:
        # Obtener todos los puestos y categorías
        puestos = Puesto.query.all()
        categorias = Categoria.query.all()
        
        # Crear un diccionario donde cada categoría tiene una lista de puestos asociados
        categorias_con_puestos = {
            categoria.id_categoria: [puesto for puesto in puestos if puesto.id_categoria == categoria.id_categoria]
            for categoria in categorias
        }
        
        return render_template(
            'postulante_dashboard.html',
            puestos=puestos,
            categorias=categorias,
            categorias_con_puestos=categorias_con_puestos
        )
    
    return redirect(url_for('login'))

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
from flask import Flask, request, send_file


@app.route('/generar_pdf', methods=['POST'])
def generar_pdf():
    # Datos personales
    nombre = request.form.get('nombre')
    cargo = request.form.get('cargo')
    cargo_postular = request.form.get('cargoPostular')  # Nuevo campo para el cargo a postular
    cedula = request.form.get('cedula')
    email = request.form.get('email')
    direccion = request.form.get('direccion')
    edad = request.form.get('edad')
    telefono = request.form.get('telefono')
    descripcion = request.form.get('descripcion')
    
    # Educación
    nivel_estudio = request.form.get('nivelEstudio')
    estado_estudio = request.form.get('estadoEstudio')
    nombre_institucion = request.form.get('nombreInstitucion')

    # Habilidades Técnicas
    habilidades = request.form.getlist('habilidades[]')

    # Conocimientos
    conocimientos = request.form.getlist('conocimientos[]')

    # Cursos realizados
    cursos = list(zip(
        request.form.getlist('empresaCertificadora[]'),
        request.form.getlist('nombreCertificado[]'),
        request.form.getlist('fechaCertificado[]')
    ))

    # Experiencia laboral
    nombre_empresa = request.form.get('nombreEmpresa')
    cargo = request.form.get('cargo')
    funciones = request.form.get('funciones')

    # Generar PDF
    pdf_buffer = BytesIO()
    doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Título
    elements.append(Paragraph("Postulación de Candidato", styles['Title']))
    elements.append(Spacer(1, 12))

    # (El resto del contenido del PDF sigue igual...)
     # Información personal
    elements.append(Paragraph("Información Personal", styles['Heading2']))
    personal_data = [
        ["Nombre", nombre],
        ["Cédula", cedula],
        ["Correo", email],
        ["Dirección", direccion],
        ["Edad", edad],
        ["Teléfono", telefono],
        ["Descripción", descripcion],
    ]
    table = Table(personal_data, colWidths=[150, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f5f5f5")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#875A7B")),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
    ]))
    elements.append(table)
    elements.append(Spacer(1, 12))

    # Educación
    elements.append(Paragraph("Educación", styles['Heading2']))
    education_data = [
        ["Nivel de estudio", nivel_estudio],
        ["Estado de estudio", estado_estudio],
        ["Nombre de la institución", nombre_institucion]
    ]
    table = Table(education_data, colWidths=[150, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f5f5f5")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#875A7B")),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
    ]))
    elements.append(table)
    elements.append(Spacer(1, 12))

    # Habilidades Técnicas
    elements.append(Paragraph("Habilidades Técnicas", styles['Heading2']))
    for habilidad in habilidades:
        elements.append(Paragraph(f"- {habilidad}", styles['BodyText']))
    elements.append(Spacer(1, 12))

    # Conocimientos
    elements.append(Paragraph("Conocimientos", styles['Heading2']))
    for conocimiento in conocimientos:
        elements.append(Paragraph(f"- {conocimiento}", styles['BodyText']))
    elements.append(Spacer(1, 12))

    # Cursos realizados
    elements.append(Paragraph("Cursos Realizados", styles['Heading2']))
    for empresa, certificado, fecha in cursos:
        elements.append(Paragraph(f"- {empresa}, {certificado} ({fecha})", styles['BodyText']))
    elements.append(Spacer(1, 12))

    # Experiencia Laboral
    elements.append(Paragraph("Experiencia Laboral", styles['Heading2']))
    work_data = [
        ["Nombre de la Empresa", nombre_empresa],
        ["Cargo", cargo],
        ["Funciones", funciones],
    ]
    table = Table(work_data, colWidths=[150, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f5f5f5")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#875A7B")),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
    ]))
    elements.append(table)
    elements.append(Spacer(1, 12))



    # Construir PDF
    doc.build(elements)
    
    # Llamada corregida
    enviar_pdf_por_correo(email, pdf_buffer, cargo_postular, nombre)

    # Enviar PDF como respuesta para descargar
    pdf_buffer.seek(0)
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name="postulacion.pdf",
        mimetype='application/pdf'
    )

def enviar_pdf_por_correo(correo_destino, pdf_buffer, cargo_postular, nombre_postulante):
    remitente = os.getenv("EMAIL_USER")
    password = os.getenv("EMAIL_PASS")

    # Construcción del asunto con el cargo a postular
    asunto = f"PROCESO DE CONTRATACION - {cargo_postular} - {nombre_postulante}"

    # Configuración del mensaje de correo
    mensaje = MIMEMultipart()
    mensaje["From"] = remitente
    mensaje["To"] = correo_destino
    mensaje["Subject"] = asunto

    # Adjuntar el PDF al correo
    adjunto = MIMEApplication(pdf_buffer.getvalue(), _subtype="pdf")
    adjunto.add_header("Content-Disposition", "attachment", filename="postulacion.pdf")
    mensaje.attach(adjunto)

    # Enviar el correo con SMTP
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as servidor:
            servidor.login(remitente, password)
            servidor.sendmail(remitente, correo_destino, mensaje.as_string())
        print("Correo enviado exitosamente.")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")
 
@app.route('/postulacion_form')
@login_required
def postulacion_form():
    return render_template('postulacion_form.html')

if __name__ == '__main__':
    app.run(debug=True)


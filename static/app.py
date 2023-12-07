from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    
    username = request.form.get('username')
    password = request.form.get('password')

    
    user = User.query.filter_by(username=username, password=password).first()

    if user:
        return jsonify({'status': 'success', 'message': 'Autenticación exitosa'})
    else:
        return jsonify({'status': 'error', 'message': 'Credenciales incorrectas'})

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'status': 'error', 'message': 'El usuario ya existe'})

    
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Usuario registrado exitosamente'})

@app.route('/bdd')
def ver_base_de_datos():
    
    users = User.query.all()
    return render_template('bdd.html', users=users)

if __name__ == '__main__':
    
    static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    app._static_folder = static_folder

    app.run(debug=True)

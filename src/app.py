import bcrypt

from flask import Flask, request, jsonify
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

from models.user import User
from database.db import db

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin@127.0.0.1:3306/flask-crud'

login_manager = LoginManager()

db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({
                'message': 'Autenticado com sucesso.'
            })

    return jsonify({
        'message': 'Credenciais inválidas'
    }), 400

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())

        user = User(username=username, password=hashed_password, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({
            'message': 'Usuário criado com sucesso.'
        })

    return jsonify({
        'message': 'Dados inválidos.'
    }), 400

@app.route('/auth/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({
        'message': 'Logout realizado com sucesso.'
    })

@app.route('/user/<int:user_id>', methods=['GET'])
@login_required
def read_user(user_id):
    user = User.query.get(user_id)

    if user:
        return jsonify({
            'username': user.username
        })

    return jsonify({
        'message': 'Usuário não encontrado.'
    }), 404

@app.route('/user/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    user = User.query.get(user_id)
    data = request.json

    if user_id != current_user.id and current_user.role == 'user':
        return jsonify({
            'message': 'Operação não permitida.'
        }), 403

    if user and data.get('password'):

        user.password = data.get('password')
        db.session.commit()

        return jsonify({
            'message': 'Usuário atualizado com sucesso.'
        })
    
    return jsonify({
        'message': 'Usuário não encontrado.'
    }), 404

@app.route('/user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)

    if current_user.role != 'admin':
        return jsonify({
            'message': 'Operação não permitida.'
        }), 403

    if user_id == current_user.id:
        return jsonify({
            'message': 'Deleção não permitida.'
        }), 403

    if user:
        db.session.delete(user)
        db.session.commit()

        return jsonify({
            'message': 'Usuário excluído com sucesso.'
        })

    return jsonify({
        'message': 'Usuário não encontrado.'
    })

if __name__ == "__main__":
    app.run(debug=True)
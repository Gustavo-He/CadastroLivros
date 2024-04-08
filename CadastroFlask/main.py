from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from flask_bcrypt import generate_password_hash, check_password_hash, Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'senha_secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/livros'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class Livro(db.Model):
    id_livro = db.Column(db.Integer, primary_key=True, autoincrement=True)
    titulo = db.Column(db.String(100))
    autor = db.Column(db.String(254))
    ano_publicacao = db.Column(db.Integer)

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    senha = db.Column(db.String(30), nullable=False)


@app.route('/')
def index():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = Usuario.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.senha, password):
            session['email'] = user.email
            if 'next' in session:
                next_route = session.pop('next')
                return redirect(url_for(next_route))
            return redirect(url_for('cadastro_livros'))
        else:
            flash('Email ou senha incorretos', 'error')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')



@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not (username and email and password and confirm_password):
            error = 'Todos os campos são obrigatórios'
            return render_template('cadastro_usuario.html', error=error)

        if password != confirm_password:
            error = 'As senhas não coincidem'
            return render_template('cadastro_usuario.html', error=error)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = Usuario(nome=username, email=email, senha=hashed_password)

        existing_user = Usuario.query.filter_by(email=email).first()
        if existing_user:
            error = 'Email já está sendo utilizado'
            return render_template('cadastro_usuario.html', error=error)

        db.session.add(new_user)
        try:
            db.session.commit()
            session['email'] = new_user.email
            return redirect('/cadastro_livros')
        except SQLAlchemyError as e:
            db.session.rollback()
            error = 'Erro ao cadastrar usuário: ' + str(e)
            return render_template('cadastro_usuario.html', error=error)
    return render_template('cadastro_usuario.html')


@app.route("/cadastro_livros")
def Li():
    livros = Livro.query.all()
    return render_template('cadastro_livros.html', outro=livros)


@app.route("/novo")
def novo():
    return render_template('novo.html', titulo="Novo livro")


@app.route('/criar', methods=['POST'])
def criar():
    titulo = request.form['titulo']
    autor = request.form['autor']
    ano_publicacao = request.form['ano_publicacao']

    livro = Livro.query.filter_by(titulo=titulo).first()
    if livro:
        flash("Livro já existe")
        return redirect(url_for('novo'))

    if not (titulo and autor and ano_publicacao):
        flash("Todos os campos são obrigatórios")
        return redirect(url_for('novo'))

    novo_livro = Livro(titulo=titulo, autor=autor, ano_publicacao=ano_publicacao)
    db.session.add(novo_livro)
    db.session.commit()
    return redirect(url_for("Li"))


@app.route('/editar/<int:identifier>')
def editar(identifier):
    livro = Livro.query.filter_by(id_livro=identifier).first()
    return render_template('editar.html', titulo='Editando livro', livro=livro)


@app.route('/atualizar', methods=['POST'])
def atualizar():
    livro = Livro.query.filter_by(id_livro=request.form['id']).first()
    livro.titulo = request.form['titulo']
    livro.autor = request.form['autor']
    livro.ano_publicacao = request.form['ano_publicacao']

    db.session.add(livro)
    db.session.commit()

    return redirect(url_for('Li'))


@app.route('/deletar/<int:identifier>')
def deletar(identifier):
    Livro.query.filter_by(id_livro=identifier).delete()
    db.session.commit()
    flash('Livro excluido com sucesso.')
    return redirect(url_for('Li'))


if __name__ == "__main__":
    app.run()

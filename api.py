###################################################################
# DESENVOLVEDOR: RODRIGO RUY OLIVEIRA
# E-MAIL: rro.oliveira@gmail.com
# SKYPE: rodrigo.ruy.oliveira
##################################################################

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import feedparser

from json import loads
from dicttoxml import dicttoxml

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///D:\\Python\\Projetos\\api.noticias\\todo.db'

db = SQLAlchemy(app)

#CLASSE REFERENTE A TABELA DE USUARIOS
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

#FUNÇÃO PARA VALIDAR O TOKEN NO HEADER
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
                token = request.headers['x-access-token']

        if not token:
            return jsonify({'mensagem' : 'É necesário informar o token!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'mensagem' : 'Token inválido!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

#RETORNA TODOS OS USUÁRIOS CADASTRADOS (NECESSÁRIO INFORMAR O TOKEN)
@app.route('/users/<formato>', methods=['GET'])
@token_required
def get_all_users(current_user, formato):

    if not current_user.admin:
        return jsonify({'mensagem' : 'É necessário ter o nível de Admin'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name']       = user.name
        user_data['password']   = user.password
        user_data['admin']      = user.admin
        output.append(user_data)

    if formato == 'json':
        return jsonify({'usuarios' : output})   
    elif formato == 'xml':
        json = {'usuarios' : output}
        xml = dicttoxml(json, attr_type=False)
        return xml
    else:
        return jsonify({'mensagem' : 'É necessário informar o formato do retorno (xml ou json)'})

#RETORNA UM USUÁRIO ESPECÍFICO (NECESSÁRIO INFORMAR UM TOKEN)
@app.route('/user/<public_id>/<formato>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id, formato):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'mensagem' : 'Usuário não encontrado!'})
    
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    if formato == 'json':
        return jsonify({'usuario' : user_data})
    elif formato == 'xml':
        json = {'usuario' : user_data}
        xml = dicttoxml(json, attr_type=False)
        return xml
    else:
        return jsonify({'mensagem' : 'É necessário informar o formato do retorno (xml ou json)'})

#CRIAÇÃO DE USUÁRIO (INFORMAR USUÁRIO E SENHA VIA JSON) - NÃO APLICADO O TOKEN PARA PODER EFETUAR OS TESTES
@app.route('/user/<formato>', methods=['POST']) 
def create_user(formato):
    data = request.get_json()
    
    hashed_password = generate_password_hash(data['password'], method='sha256')
    
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=True)
    
    db.session.add(new_user)
    db.session.commit()

    if formato == 'json':
        return jsonify({'mensagem' : 'Usuário criado com sucesso'})
    elif formato == 'xml':
        json = {'mensagem' : 'Usuário criado com sucesso'}
        xml = dicttoxml(json, attr_type=False)
        return xml
    else:
        return jsonify({'mensagem' : 'É necessário informar o formato do retorno (xml ou json)'})

#ALTERAR O NÍVEL DO USUÁRIO
#PARA VISUALIZAR TODOS OS USUÁRIOS É NECESSÁRIO ESTAR NO NÍVEL ADMIN
@app.route('/user/<public_id>/<formato>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id, formato):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'mensagem' : 'Usuário não encontrado!'})

    if user.admin == False:
        user.admin = True
        msg = 'O usuário agora é administrador!'
    else:    
        user.admin = False
        msg = 'O usuário NÃO é administrador!'

    db.session.commit()

    if formato == 'json':
        return jsonify({'mensagem' : msg})
    elif formato == 'xml':
        json = {'mensagem' : msg}
        xml = dicttoxml(json, attr_type=False)
        return xml
    else:
        return jsonify({'mensagem' : 'É necessário informar o formato do retorno (xml ou json)'})

#DELETAR UM USUÁRIO
@app.route('/user/<public_id>/<formato>', methods=['DELETE'])   
@token_required
def delete_user(create_user, public_id, formato):
    
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'mensagem' : 'Usuário não encontrado!'})

    db.session.delete(user)
    db.session.commit()

    if formato == 'json':
       return jsonify({'mensagem' : 'Usuário excluído com sucesso!'})
    elif formato == 'xml':
        json = {'mensagem' : 'Usuário excluído com sucesso!'}
        xml = dicttoxml(json, attr_type=False)
        return xml
    else:
        return jsonify({'mensagem' : 'É necessário informar o formato do retorno (xml ou json)'})

#EFETUAR O LOGIN PARA RECEBER O TOKEN
@app.route('/login/<formato>', methods=['POST'])
def login(formato):
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Não foi possível logar', 401, {'WWW-Authenticate' : 'Basic realm=Informe o login"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Não foi possível logar', 401, {'WWW-Authenticate' : 'Basic realm=Informe o login"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        if formato == 'json':
            return jsonify({'token' : token.decode('UTF-8')})
        elif formato == 'xml':
            json = {'token' : token.decode('UTF-8')}
            xml = dicttoxml(json, attr_type=False)
            return xml
        else:
            return jsonify({'mensagem' : 'É necessário informar o formato do retorno (xml ou json)'})
    
    return make_response('Não foi possível logar', 401, {'WWW-Authenticate' : 'Basic realm=Informe o login"'})

#BUSCAR TODAS AS NOTÍCIAS
@app.route('/noticias/<formato>', methods=['GET'])
@token_required
def noticias(current_user, formato):
    url = "http://www.valor.com.br/rss"
    feed = feedparser.parse(url)

    data = []
    for post in feed.entries:
        titulo    = post.title
        link      = post.link
        datapub   = post.published
        urlimagem = post.urlimage

        data.append({ 'titulo'    : titulo,
                      'datapub'   : datapub,
                      'link'      : link,
                      'urlimagem' : urlimagem
                    })

    if formato == 'json':
           return jsonify({'noticias': data})
    elif formato == 'xml':
        json = {'noticias': data}
        xml = dicttoxml(json, attr_type=False)
        return xml
    else:
        return jsonify({'mensagem' : 'É necessário informar o formato do retorno (xml ou json)'})

#FILTRAR NOTÍCIAS POR PALAVRA-CHAVE NO TÍTULO
@app.route('/noticias/<filtro>/<formato>', methods=['GET'])
@token_required
def noticias_por_palavra(current_user, filtro, formato):
    url = "http://www.valor.com.br/rss"
    feed = feedparser.parse(url)

    data = []
    for post in feed.entries:
        titulo    = post.title
        link      = post.link
        datapub   = post.published
        urlimagem = post.urlimage

        if(titulo.find(filtro) > 0):

            data.append({ 'titulo'    : titulo,
                          'datapub'   : datapub,
                          'link'      : link,
                          'urlimagem' : urlimagem
                        })

    if formato == 'json':
           return jsonify({'noticias': data})
    elif formato == 'xml':
        json = {'noticias': data}
        xml = dicttoxml(json, attr_type=False)
        return xml
    else:
        return jsonify({'mensagem' : 'É necessário informar o formato do retorno (xml ou json)'})

#FILTRAR NOTÍCIAS POR DATA (INÍCIO - FIM)
@app.route('/noticias/<dt_inicio>/<dt_fim>/<formato>', methods=['GET'])
@token_required
def noticias_por_data(current_user, dt_inicio, dt_fim, formato):
    url = "http://www.valor.com.br/rss"
    feed = feedparser.parse(url)

    data = []
    for post in feed.entries:
        titulo    = post.title
        link      = post.link
        datapub   = post.published
        urlimagem = post.urlimage

        try:
            datetime.datetime.strptime(dt_inicio,'%d%m%Y')
            datetime.datetime.strptime(dt_fim,'%d%m%Y')
        except:
            return jsonify({'mensagem' : 'Formato das datas devem ser ddmmYYYY'})

        dataNoticia =  datetime.datetime.strptime(datapub, '%d %b %Y %H:%M:%S').strftime('%d%m%Y')   

        if(dataNoticia >= dt_inicio and dataNoticia <= dt_fim):

            data.append({ 'titulo'      : titulo,
                            'datapub'   : datapub,
                            'link'      : link,
                            'urlimagem' : urlimagem
                        })
    
    if formato == 'json':
           return jsonify({'noticias': data})
    elif formato == 'xml':
        json = {'noticias': data}
        xml = dicttoxml(json, attr_type=False)
        return xml
    else:
        return jsonify({'mensagem' : 'É necessário informar o formato do retorno (xml ou json)'})

#CONTAR QUANTAS NOTÍCIAS TIVERAM NA ÚLTIMA HORA
@app.route('/noticias_hora/<formato>', methods=['GET'])
@token_required
def noticias_por_hora(create_user, formato):
    url = "http://www.valor.com.br/rss"
    feed = feedparser.parse(url)
    qtd  = 0

    for post in feed.entries:
        datapub   = post.published

        ultimahora = datetime.datetime.now() - datetime.timedelta(minutes=60)
        dtHoraNews = datetime.datetime.strptime(datapub, '%d %b %Y %H:%M:%S')
        
        if(dtHoraNews >= ultimahora):
            qtd += 1

    if formato == 'json':
           return jsonify({'qtd_noticias_ultima_hora': qtd})
    elif formato == 'xml':
        json = {'qtd_noticias_ultima_hora': qtd}
        xml = dicttoxml(json, attr_type=False)
        return xml
    else:
        return jsonify({'mensagem' : 'É necessário informar o formato do retorno (xml ou json)'})

if __name__ == "__main__":
    app.run(debug=True)
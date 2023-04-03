from extensions import db
from flask_login import UserMixin


class User(UserMixin, db.Model):
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

def init_app(app):
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://boost_gpt:Workhard7!@localhost/boost_gpt'
    db.init_app(app)
    with app.app_context():
        db.create_all()
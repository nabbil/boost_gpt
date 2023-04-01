from app import db
from models import User

# Create a new user
new_user = User(username='johndoe', password='password123')
db.session.add(new_user)
db.session.commit()

# Get all users
users = User.query.all()

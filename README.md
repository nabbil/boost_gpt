"# boost_gpt" 

PostgreSQL info

psql -h localhost -U boost_gpt
Password is Workhar\d7!


\c boost_gpt

\dt # Shows the tables 

Admin User: nabbil
Password: Welcome@20@@ or $2b$12$Vk6VHG.Qq5cCIGQizdTeVOTbJoJvv2L0Ca4aqRn8PbfHUjdD0YkbS

# Promp
the form that I fill out in my register route lets me select a roll but the role is just showing up as none and giving this error:

sqlalchemy.exc.IntegrityError: (psycopg2.errors.NotNullViolation) null value in column "role" of relation "user" violates not-null constraint
DETAIL:  Failing row contains (8, nadeem, sha256$TrHVY5dqR1CFT6D1$012c3265d4c2fffce943ead3158f38a3ed139652..., null, nadee@khansortium.com).

[SQL: INSERT INTO "user" (username, password, email, role) VALUES (%(username)s, %(password)s, %(email)s, %(role)s) RETURNING "user".id]
[parameters: {'username': 'nadeem', 'password': 'sha256$TrHVY5dqR1CFT6D1$012c3265d4c2fffce943ead3158f38a3ed13965235758ec7732513ff5ebcd88f', 'email': 'nadee@khansortium.com', 'role': None}]
(Background on this error at: https://sqlalche.me/e/20/gkpj)
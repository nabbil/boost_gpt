import psycopg2

# Replace these with your actual database credentials
DB_NAME = "boost_gpt"
DB_USER = "boost_gpt"
DB_PASS = "Workhard7!"
DB_HOST = "localhost"
DB_PORT = "5432"

# Connect to the database
connection = psycopg2.connect(
    dbname=DB_NAME,
    user=DB_USER,
    password=DB_PASS,
    host=DB_HOST,
    port=DB_PORT
)

# Create a cursor
cursor = connection.cursor()

# Create the users table
cursor.execute("""
    CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL
    );
""")

# Commit the transaction
connection.commit()

# Close the connection
cursor.close()
connection.close()

print("Users table created.")

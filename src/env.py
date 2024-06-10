from dotenv import load_dotenv
from os import getenv

load_dotenv()

mysqldb_uri = getenv("MYSQLDB_URI")
secret_key = getenv("SECRET_KEY")
cors_origin = getenv("CORS_ORIGIN")
server_mode = getenv("SERVER_MODE")

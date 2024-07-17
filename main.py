from logging import basicConfig, DEBUG
from waitress import serve
from src.env import server_mode
from src.app import app


if __name__ == "__main__":
    try:
        if server_mode == "development":
            basicConfig(level=DEBUG)
            app.run(debug=True, host="localhost", port=4000)
        elif server_mode == "deployment":
            print("Running at: http://localhost:8080")
            serve(app=app)
        else:
            raise Exception("Unable to run Flask Application!")
    except Exception as e:
        print(e)
    

# >>> from server import app, db
# >>> with app.app_context():
# >>>     db.create_all()

# source .venv/Scripts/activate
 
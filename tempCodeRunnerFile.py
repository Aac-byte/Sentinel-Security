app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scanner.db")

THREAT_DB = os.path.join(BASE_DIR, "threats.db")

print(DB_PATH)
print(os.path.exists(DB_PATH))

@app.route("/")
import sqlite3
import configparser

# 설정파일 읽기
config = configparser.ConfigParser()
config.read("info.conf")

# 기본 설정
DB_PATH = config["DEFAULT"]["DB_PATH"]

# 데이터베이스 초기화
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            msp_path TEXT NOT NULL,
            fabric_id TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nfts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id TEXT NOT NULL,
            token_uri TEXT NOT NULL,
            image_uri TEXT NOT NULL,
            tx_id TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()


#conn = sqlite3.connect(DB_PATH)
#cursor = conn.cursor()
#cursor.execute("ALTER TABLE nfts ADD COLUMN tx_id TEXT;")
#conn.commit()
#conn.close()

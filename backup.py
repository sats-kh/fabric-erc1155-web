from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3
import os
import subprocess
import shutil
import json
import requests
import random
#import hashlib
from utils import convert_ipfs_to_uint64

app = Flask(__name__)
app.secret_key = 'dev_secret_key'

# 데이터베이스 경로 (회원가입 및 NFT 소유권 기록용)
DB_PATH = './user_data.db'

# Fabric 관련 설정
FABRIC_CFG_PATH = "/home/kh/Documents/github/fablo/fablo-target/fabric-config"
FABRIC_CHANNEL = "dslab"
FABRIC_CHAINCODE = "erc1155"
FABRIC_CA_TLS_CERT = "/home/kh/Documents/github/fablo/fablo-target/fabric-config/crypto-config/peerOrganizations/org1.bigdata.re.kr/ca/ca.org1.bigdata.re.kr-cert.pem"

# Stable Diffusion 서버 URL (이미지 생성)
SD_SERVER_URL = "http://gpu.bigdata.re.kr:5000/generate"

# TARGET_TLS_OPTIONS: Orderer 및 TLS 옵션 (환경에 맞게 수정 필요)
TARGET_TLS_OPTIONS = [
    "-o", "orderer0.group.bigdata.re.kr:7030",
    "--ordererTLSHostnameOverride", "orderer0.group.bigdata.re.kr",
    "--tls",
    "--cafile", os.path.join(FABRIC_CFG_PATH, "crypto-config/peerOrganizations/bigdata.re.kr/peers/orderer0.group.bigdata.re.kr/tls/ca.crt"),
    "--peerAddresses", "peer0.org1.bigdata.re.kr:7041",
    "--tlsRootCertFiles", os.path.join(FABRIC_CFG_PATH, "crypto-config/peerOrganizations/org1.bigdata.re.kr/peers/peer0.org1.bigdata.re.kr/tls/ca.crt")
]

def init_db():
    """ 데이터베이스 초기화: users 테이블과 nfts 테이블 생성 """
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
            owner_id INTEGER NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_fabric_id(msp_path):
    """
    주어진 MSP 경로에서 admincerts 디렉터리가 없거나 비어있으면
    지정된 Admin 인증서를 복사한 후, Fabric 체인코드 "ClientAccountID"를 호출하여 fabric_id를 반환합니다.
    """
    admincerts_dir = os.path.join(msp_path, "admincerts")
    if not os.path.exists(admincerts_dir):
        os.makedirs(admincerts_dir)
    if not os.listdir(admincerts_dir):
        admin_cert_source = "/home/kh/Documents/github/fablo/fablo-target/fabric-config/crypto-config/peerOrganizations/org1.bigdata.re.kr/users/Admin@org1.bigdata.re.kr/msp/signcerts/Admin@org1.bigdata.re.kr-cert.pem"
        try:
            shutil.copy(admin_cert_source, admincerts_dir)
            print(f"Copied admin cert to {admincerts_dir}")
        except Exception as e:
            print(f"Failed to copy admin certificate: {str(e)}")
            return None

    # Fabric CLI 환경 변수 설정 (사용자 MSP 적용)
    os.environ["FABRIC_CFG_PATH"] = FABRIC_CFG_PATH
    os.environ["CORE_PEER_TLS_ENABLED"] = "true"
    os.environ["CORE_PEER_LOCALMSPID"] = "Org1MSP"
    os.environ["CORE_PEER_MSPCONFIGPATH"] = msp_path
    os.environ["CORE_PEER_TLS_ROOTCERT_FILE"] = os.path.join(
        FABRIC_CFG_PATH,
        "crypto-config/peerOrganizations/org1.bigdata.re.kr/peers/peer0.org1.bigdata.re.kr/tls/ca.crt"
    )
    os.environ["CORE_PEER_ADDRESS"] = "peer0.org1.bigdata.re.kr:7041"

    query_cmd = [
        "peer", "chaincode", "query",
        "-C", FABRIC_CHANNEL,
        "-n", FABRIC_CHAINCODE,
        "-c", '{"function":"ClientAccountID","Args":[]}'
    ]
    try:
        fabric_id = subprocess.check_output(query_cmd, stderr=subprocess.STDOUT, text=True).strip()
        return fabric_id
    except subprocess.CalledProcessError as e:
        print(f"Error querying fabric_id: {e.output.strip()}")
        return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    """ 회원가입 + Fabric 사용자 등록 후 fabric_id 조회 및 DB 저장 """
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400

        user_msp_path = os.path.join(
            "/home/kh/Documents/github/fablo/fablo-target/fabric-config/crypto-config/peerOrganizations/org1.bigdata.re.kr/users",
            f"{username}@org1.bigdata.re.kr/msp"
        )

        # Fabric 사용자 등록 (register)
        register_cmd = [
            "fabric-ca-client", "register",
            "-u", "https://localhost:7040",
            "--caname", "ca.org1.bigdata.re.kr",
            "--id.name", username,
            "--id.secret", password,
            "--id.type", "client",
            "--tls.certfiles", FABRIC_CA_TLS_CERT
        ]

        # Fabric 사용자 enroll (MSP 생성)
        enroll_cmd = [
            "fabric-ca-client", "enroll",
            "-u", f"https://{username}:{password}@localhost:7040",
            "--caname", "ca.org1.bigdata.re.kr",
            "-M", user_msp_path,
            "--tls.certfiles", FABRIC_CA_TLS_CERT
        ]

        try:
            subprocess.run(register_cmd, check=True, text=True, capture_output=True)
            subprocess.run(enroll_cmd, check=True, text=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            return jsonify({"error": f"Fabric user registration failed: {e.stderr}"}), 500

        # enroll 후 fabric_id 조회 (관리자 인증서 복사 방식)
        fabric_id = get_fabric_id(user_msp_path)
        if not fabric_id:
            return jsonify({"error": "Failed to obtain fabric_id from Fabric network"}), 500

        # DB에 사용자 저장 (fabric_id 포함)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO users (username, password, msp_path, fabric_id) VALUES (?, ?, ?, ?)',
                (username, password, user_msp_path, fabric_id)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "Username already exists"}), 400
        finally:
            conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ 로그인 + 사용자 세션 유지 """
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, msp_path, fabric_id FROM users WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            session['username'] = username
            session['msp_path'] = user[1]
            return redirect(url_for('home'))
        return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/query_user', methods=['GET'])
def query_user():
    """ 현재 로그인된 사용자의 Fabric 계정을 조회 (체인코드 ClientAccountID 호출) """
    if 'username' not in session or 'msp_path' not in session:
        return jsonify({"error": "User not logged in"}), 401

    username = session['username']
    msp_path = session['msp_path']
    print("Using MSP path:", msp_path)

    # 관리자 인증서 복사 (없거나 비어있을 경우)
    admincerts_dir = os.path.join(msp_path, "admincerts")
    if not os.path.exists(admincerts_dir):
        os.makedirs(admincerts_dir)
    if not os.listdir(admincerts_dir):
        admin_cert_source = "/home/kh/Documents/github/fablo/fablo-target/fabric-config/crypto-config/peerOrganizations/org1.bigdata.re.kr/users/Admin@org1.bigdata.re.kr/msp/signcerts/Admin@org1.bigdata.re.kr-cert.pem"
        try:
            shutil.copy(admin_cert_source, admincerts_dir)
            print(f"Copied admin cert to {admincerts_dir}")
        except Exception as e:
            return jsonify({"error": f"Failed to copy admin certificate: {str(e)}"}), 500

    # Fabric 환경 변수 설정 (사용자 MSP 적용)
    os.environ["FABRIC_CFG_PATH"] = FABRIC_CFG_PATH
    os.environ["CORE_PEER_TLS_ENABLED"] = "true"
    os.environ["CORE_PEER_LOCALMSPID"] = "Org1MSP"
    os.environ["CORE_PEER_MSPCONFIGPATH"] = msp_path
    os.environ["CORE_PEER_TLS_ROOTCERT_FILE"] = os.path.join(
        FABRIC_CFG_PATH,
        "crypto-config/peerOrganizations/org1.bigdata.re.kr/peers/peer0.org1.bigdata.re.kr/tls/ca.crt"
    )
    os.environ["CORE_PEER_ADDRESS"] = "peer0.org1.bigdata.re.kr:7041"

    query_cmd = [
        "peer", "chaincode", "query",
        "-C", FABRIC_CHANNEL,
        "-n", FABRIC_CHAINCODE,
        "-c", '{"function":"ClientAccountID","Args":[]}'
    ]
    try:
        fabric_id = subprocess.check_output(query_cmd, stderr=subprocess.STDOUT, text=True).strip()
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Fabric query failed: {e.output.strip()}"}), 500

    return jsonify({
        "message": f"Logged in as {username}",
        "fabric_id": fabric_id,
        "msp_path": msp_path
    })

@app.route('/mint', methods=['GET', 'POST'])
def mint():
    """ 
    Mint: 사용자가 입력한 프롬프트로 Stable Diffusion 서버에서 이미지(IPFS URL) 생성,
          해당 IPFS URL을 기반으로 토큰 ID를 산출한 후, ERC1155 체인코드의 MintWithURI 함수를 호출하여 NFT를 발행하고,
          DB에 NFT 소유권을 기록합니다.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        prompt = request.form.get("prompt")
        if not prompt:
            return "Prompt is required.", 400

        user_id = session['user_id']
        msp_path = session['msp_path']

        # Stable Diffusion 서버에 프롬프트 전송 후 IPFS URL 획득
        try:
            sd_response = requests.post(SD_SERVER_URL, json={"prompt": prompt})
            sd_response.raise_for_status()
            sd_data = sd_response.json()
            base_token_uri = sd_data.get("ipfs_url")
            if not base_token_uri:
                return "Failed to retrieve IPFS URL from Stable Diffusion server.", 500
        except requests.RequestException as e:
            return f"Failed to communicate with Stable Diffusion server: {e}", 500

        # base_token_uri를 사용하여 NFT 토큰 ID 생성 (uint64 문자열)
        token_id = convert_ipfs_to_uint64(base_token_uri)
        
        # 각 NFT의 메타데이터 파일은 고유하므로, 예를 들어
        # base_token_uri가 디렉토리 CID라면, 해당 NFT의 메타데이터 파일 경로는
        # "base_token_uri/token_id.json" 과 같이 구성할 수 있습니다.
        full_metadata_uri = base_token_uri.rstrip("/") + "/" + token_id + ".json"
        
        # Fabric CLI 환경 변수 설정 (사용자 MSP 적용)
        os.environ["FABRIC_CFG_PATH"] = FABRIC_CFG_PATH
        os.environ["CORE_PEER_TLS_ENABLED"] = "true"
        os.environ["CORE_PEER_LOCALMSPID"] = "Org1MSP"
        os.environ["CORE_PEER_MSPCONFIGPATH"] = msp_path
        os.environ["CORE_PEER_TLS_ROOTCERT_FILE"] = os.path.join(
            FABRIC_CFG_PATH,
            "crypto-config/peerOrganizations/org1.bigdata.re.kr/peers/peer0.org1.bigdata.re.kr/tls/ca.crt"
        )
        os.environ["CORE_PEER_ADDRESS"] = "peer0.org1.bigdata.re.kr:7041"

        # Fabric 체인코드의 recipient (즉, 사용자의 Fabric ID) 조회
        recipient = get_fabric_id(msp_path)
        if not recipient:
            return "Failed to retrieve recipient Fabric ID.", 500

        # ERC1155 체인코드의 MintWithURI 함수 호출:
        # Args: [recipient, token_id, "1", full_metadata_uri]
        mint_cmd = [
            "peer", "chaincode", "invoke",
            *TARGET_TLS_OPTIONS,
            "-C", FABRIC_CHANNEL,
            "-n", FABRIC_CHAINCODE,
            "-c", json.dumps({
                "function": "MintWithURI",
                "Args": [recipient, token_id, "1", full_metadata_uri]
            }),
            "--waitForEvent"
        ]
        try:
            subprocess.check_output(mint_cmd, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            return f"Chaincode MintWithURI invocation failed: {e.output.strip()}", 500

        # DB에 NFT 소유권 기록 (여기서 token_uri은 full_metadata_uri)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO nfts (token_id, token_uri, owner_id) VALUES (?, ?, ?)',
                (token_id, full_metadata_uri, user_id)
            )
            conn.commit()
        except sqlite3.Error as e:
            return f"Failed to save NFT ownership to the database: {e}", 500
        finally:
            conn.close()

        return render_template('mint_success.html', token_id=token_id, token_uri=full_metadata_uri, prompt=prompt)

    return render_template('mint.html')

@app.route('/logout')
def logout():
    """ 로그아웃 """
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('msp_path', None)
    return redirect(url_for('login'))

@app.route('/')
def home():
    return "<h1>Welcome to the Fabric ERC1155 Web App</h1>"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=3000, debug=True)

from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3
import os
import subprocess
import shutil
import json
import requests
import random
from utils import convert_ipfs_to_uint256, get_fabric_id, create_nft_metadata, upload_metadata_to_ipfs, create_and_upload_creative_history
import configparser
import re

# 설정파일 읽기
config = configparser.ConfigParser()
config.read("info.conf")

# 기본 설정
DB_PATH = config["DEFAULT"]["DB_PATH"]
SECRET_KEY = config["DEFAULT"]["SECRET_KEY"]

# Fabric 관련 설정
FABRIC_CFG_PATH = config["FABRIC"]["FABRIC_CFG_PATH"]
FABRIC_CHANNEL = config["FABRIC"]["FABRIC_CHANNEL"]
FABRIC_CHAINCODE = config["FABRIC"]["FABRIC_CHAINCODE"]
FABRIC_CA_TLS_CERT = config["FABRIC"]["FABRIC_CA_TLS_CERT"]
USERS_PATH = config["FABRIC"]["USERS_PATH"]
PEER_TLS_CA = config["FABRIC"]["PEER_TLS_CA"] 
CA_URL = config["FABRIC"]["CA_URL"]
CA_CANAME = config["FABRIC"]["CA_CANAME"]
CORE_PEER_ADDRESS = config["FABRIC"]["CORE_PEER_ADDRESS"]

# Stable Diffusion 서버 URL
SD_SERVER_URL = config["SD"]["SD_SERVER_URL"]

# TLS 옵션: 콤마로 구분된 문자열을 리스트로 변환
TARGET_TLS_OPTIONS = config["TLS"]["TARGET_TLS_OPTIONS"].split(",")

# EXPLORER URL
EXPLORER_URL = config["EXPLORER"]["EXPLORER_URL"]

app = Flask(__name__)
app.secret_key = SECRET_KEY

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400

        # USERS_PATH를 사용하여 사용자 MSP 경로 설정
        user_msp_path = os.path.join(
            USERS_PATH,
            f"{username}@org1.bigdata.re.kr/msp"
        )

        register_cmd = [
            "fabric-ca-client", "register",
            "-u", CA_URL,
            "--caname", CA_CANAME,
            "--id.name", username,
            "--id.secret", password,
            "--id.type", "client",
            "--tls.certfiles", FABRIC_CA_TLS_CERT
        ]
        enroll_cmd = [
            "fabric-ca-client", "enroll",
            "-u", f"https://{username}:{password}@{CA_URL.split('://')[1]}",
            "--caname", CA_CANAME,
            "-M", user_msp_path,
            "--tls.certfiles", FABRIC_CA_TLS_CERT
        ]
        try:
            subprocess.run(register_cmd, check=True, text=True, capture_output=True)
            subprocess.run(enroll_cmd, check=True, text=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            return jsonify({"error": f"Fabric user registration failed: {e.stderr}"}), 500
        fabric_id = get_fabric_id(user_msp_path)
        print(fabric_id)
        if not fabric_id:
            return jsonify({"error": "Failed to obtain fabric_id from Fabric network"}), 500

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

@app.route('/mint', methods=['GET', 'POST'])
def mint():
    """ 
    Mint: 사용자가 입력한 프롬프트로 Stable Diffusion 서버에서 이미지(IPFS URL) 생성,
          해당 IPFS URL을 기반으로 토큰 ID를 산출한 후, 
          create_nft_metadata 함수를 호출하여 NFT 메타데이터 JSON 파일(tokenID.json)을 생성하고,
          upload_metadata_to_ipfs 함수를 호출하여 메타데이터 디렉토리를 IPFS에 업로드한 후,
          반환된 metadata URI를 사용하여 ERC1155 체인코드의 MintWithURI 함수를 호출, 그리고
          DB에 NFT 소유권과 트랜잭션 ID를 기록합니다.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        prompt = request.form.get("prompt")
        if not prompt:
            return "Prompt is required.", 400

        user_id = session['user_id']
        msp_path = session['msp_path']

        try:
            sd_response = requests.post(SD_SERVER_URL, json={"prompt": prompt})
            sd_response.raise_for_status()
            sd_data = sd_response.json()
            # base_token_uri는 Stable Diffusion에서 반환한 이미지 IPFS URL (이미지의 CID를 포함)
            base_token_uri = sd_data.get("ipfs_url")
            if not base_token_uri:
                return "Failed to retrieve IPFS URL from Stable Diffusion server.", 500
        except requests.RequestException as e:
            return f"Failed to communicate with Stable Diffusion server: {e}", 500

        # token_id 생성: base_token_uri를 바탕으로 고유 uint256 문자열 생성
        token_id = convert_ipfs_to_uint256(base_token_uri)

        # Fabric 환경 변수 설정
        os.environ["FABRIC_CFG_PATH"] = FABRIC_CFG_PATH
        os.environ["CORE_PEER_TLS_ENABLED"] = "true"
        os.environ["CORE_PEER_LOCALMSPID"] = "Org1MSP"
        os.environ["CORE_PEER_MSPCONFIGPATH"] = msp_path
        os.environ["CORE_PEER_TLS_ROOTCERT_FILE"] = PEER_TLS_CA
        os.environ["CORE_PEER_ADDRESS"] = CORE_PEER_ADDRESS

        # Fabric 네트워크 상의 사용자 Fabric ID 조회
        recipient = get_fabric_id(msp_path)
        if not recipient:
            return "Failed to retrieve recipient Fabric ID.", 500

        # 로컬에 NFT 메타데이터 파일 생성 (tokenID.json 형식) 
        local_metadata_dir = os.path.join("./nft", token_id)
        create_nft_metadata(token_id, session['username'], recipient, base_token_uri, prompt)
        
        # 생성된 메타데이터 디렉토리를 IPFS에 업로드하고, 반환된 메타데이터 URI 사용
        metadata_uri = upload_metadata_to_ipfs(local_metadata_dir, token_id)
        if not metadata_uri:
            return "Failed to upload metadata to IPFS.", 500

        # ERC1155 체인코드의 MintWithURI 호출: 토큰 민팅과 함께 metadata_uri를 전달
        mint_cmd = [
            "peer", "chaincode", "invoke",
            *TARGET_TLS_OPTIONS,
            "-C", FABRIC_CHANNEL,
            "-n", FABRIC_CHAINCODE,
            "-c", json.dumps({
                "function": "MintWithURI",
                "Args": [recipient, token_id, "1", metadata_uri]
            }),
            "--waitForEvent"
        ]
        try:
            tx_result = subprocess.check_output(mint_cmd, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            return f"Chaincode MintWithURI invocation failed: {e.output.strip()}", 500

        # 트랜잭션 ID 추출: 정규식을 이용해 "txid [ ... ]" 부분에서 추출
        match = re.search(r'txid \[([a-f0-9]+)\]', tx_result)
        tx_id = match.group(1) if match else "Unknown"
        explorer_url = EXPLORER_URL + tx_id
        # DB에 NFT 소유권 및 트랜잭션 ID 기록
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO nfts (token_id, token_uri, image_uri, owner_id, tx_id) VALUES (?, ?, ?, ?, ?)',
                (token_id, metadata_uri, base_token_uri, user_id, tx_id)
            )
            conn.commit()
        except sqlite3.Error as e:
            return f"Failed to save NFT ownership to the database: {e}", 500
        finally:
            conn.close()

        return render_template('mint_success.html', token_id=token_id, token_uri=metadata_uri, prompt=prompt, image_uri=base_token_uri, tx_id=tx_id, explorer_url=explorer_url)

    return render_template('mint.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('msp_path', None)
    return redirect(url_for('login'))

@app.route('/')
def home():
    user_logged_in = 'user_id' in session

    all_nfts = []
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 데이터베이스에서 NFT 레코드 전체 조회 (token_id, token_uri, owner_id)
    cursor.execute("SELECT token_id, token_uri, image_uri, owner_id, tx_id FROM nfts")
    nft_rows = cursor.fetchall()

    for row in nft_rows:
        token_id, token_uri, image_uri, owner_id, tx_id = row

        # 데이터베이스에서 owner_id를 통해 사용자 이름 조회
        cursor.execute('''
            SELECT username
            FROM users
            WHERE id = ?
        ''', (owner_id,))
        owner = cursor.fetchone()
        owner_username = owner[0] if owner else "Unknown"

        # 최종 NFT 데이터 구성
        all_nfts.append({
            "tokenId": token_id,
            "tokenURI": token_uri,
            "imageURI": image_uri,
            "owner": owner_username,
            "txId": tx_id,
            "txIdURL": EXPLORER_URL + tx_id
        })

    # tokenId가 매우 큰 정수일 수 있으므로 int() 변환 시 주의
    all_nfts = sorted(all_nfts, key=lambda x: int(x["tokenId"]), reverse=True)

    conn.close()

    return render_template('home.html', user_logged_in=user_logged_in, all_nfts=all_nfts)

# My NFTs 페이지
@app.route('/nfts', methods=['GET'])
def view_nfts():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']  # 현재 로그인한 사용자의 ID

    # 데이터베이스에서 현재 사용자가 소유한 NFT 정보 조회
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT nfts.token_id, nfts.token_uri, nfts.image_uri, users.username, nfts.tx_id
        FROM nfts
        INNER JOIN users ON nfts.owner_id = users.id
        WHERE nfts.owner_id = ?
        ORDER BY nfts.id DESC
    ''', (user_id,))
    user_nfts = cursor.fetchall()
    conn.close()

    # NFT 데이터를 리스트로 변환
    nfts = [
        {
            "tokenId": row[0],
            "tokenURI": row[1],
            "imageURI": row[2],
            "owner": row[3], 
            "txId": row[4],
            "txIdURL": EXPLORER_URL + row[4]
        } for row in user_nfts
    ]
    return render_template('nfts.html', nfts=nfts)

@app.route('/record', methods=['GET', 'POST'])
def record():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    msp_path = session['msp_path']

    # GET 요청: 사용자의 NFT 목록을 조회하여 선택 페이지 렌더링
    if request.method == 'GET':
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT token_id, token_uri, image_uri, tx_id
            FROM nfts
            WHERE owner_id = ?
            ORDER BY id DESC
        ''', (user_id,))
        nft_rows = cursor.fetchall()
        conn.close()

        nfts = [
            {
                "tokenId": row[0],
                "tokenURI": row[1],
                "imageURI": row[2],
                "txId": row[3]
            } for row in nft_rows
        ]
        return render_template('record_history.html', nfts=nfts)

    # POST 요청: 선택된 NFT 정보를 바탕으로 창작 이력 메타파일 생성 및 업로드 후, RecordCreativeHistory 체인코드 호출
    if request.method == 'POST':
        # 폼에서 대표 NFT와 모든 선택된 NFT의 txID들을 가져옴 (대표 NFT의 txID도 포함됨)
        representative_token = request.form.get("representative_token")
        all_tx_ids_str = request.form.get("all_tx_ids")  # 콤마로 구분된 문자열 (대표 NFT 포함)
        if not representative_token or not all_tx_ids_str:
            return "대표 NFT와 기록에 포함될 NFT의 트랜잭션 ID들이 필요합니다.", 400

        # all_tx_ids를 리스트로 변환
        all_tx_ids = [tx.strip() for tx in all_tx_ids_str.split(",") if tx.strip()]
        if not all_tx_ids:
            return "기록할 NFT 트랜잭션 ID가 존재하지 않습니다.", 400

        # DB 연결: 선택한 모든 txID에 대해 token_id와 token_uri 조회하여 이전 트랜잭션 딕셔너리(참고용)를 구성 (체인코드 호출에는 사용하지 않음)
        previous_transactions = {}
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        for tx in all_tx_ids:
            cursor.execute("SELECT token_id, token_uri FROM nfts WHERE tx_id = ?", (tx,))
            row = cursor.fetchone()
            if row:
                # key: tx, value: [tokenID, tokenURI]
                previous_transactions[tx] = [row[0], row[1]]
        conn.close()
        if not previous_transactions:
            return "DB에서 이전 NFT 정보 조회에 실패했습니다.", 500

        # 대표 NFT의 token_uri 조회
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT token_uri FROM nfts WHERE token_id = ?", (representative_token,))
        row = cursor.fetchone()
        conn.close()
        if row:
            representative_uri = row[0]
        else:
            return "대표 NFT 정보를 DB에서 조회하지 못했습니다.", 500

        # 웹 사용자 ID (예: session의 username)
        web_user_id = session.get("username", "unknown")
        # Fabric ID 조회 (세션 또는 DB)
        fabric_id = session.get("fabric_id")
        if not fabric_id:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT fabric_id FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                fabric_id = row[0]
            else:
                return "Fabric ID를 찾을 수 없습니다.", 500

        # utils.py의 create_and_upload_creative_history 함수 호출하여 새로운 창작 이력 URI 생성
        from utils import create_and_upload_creative_history
        try:
            new_uri = create_and_upload_creative_history(
                representative_token=representative_token,
                representative_uri=representative_uri,
                web_user_id=web_user_id,
                previous_transactions=previous_transactions  # 메타파일 내에는 이전 트랜잭션 딕셔너리 기록됨
            )
        except Exception as e:
            return f"창작 이력 메타파일 생성 및 업로드 실패: {str(e)}", 500

        # Fabric 환경 변수 설정 (mint 함수와 동일)
        os.environ["FABRIC_CFG_PATH"] = FABRIC_CFG_PATH
        os.environ["CORE_PEER_TLS_ENABLED"] = "true"
        os.environ["CORE_PEER_LOCALMSPID"] = "Org1MSP"
        os.environ["CORE_PEER_MSPCONFIGPATH"] = msp_path
        os.environ["CORE_PEER_TLS_ROOTCERT_FILE"] = PEER_TLS_CA
        os.environ["CORE_PEER_ADDRESS"] = CORE_PEER_ADDRESS

        # 체인코드 RecordCreativeHistory 호출:
        # 인자 순서: 대표 NFT의 Token ID, Fabric ID, 새롭게 생성된 창작 이력 URI, 이전 트랜잭션의 txID 배열 (JSON 문자열)
        record_history_cmd = [
            "peer", "chaincode", "invoke",
            *TARGET_TLS_OPTIONS,
            "-C", FABRIC_CHANNEL,
            "-n", FABRIC_CHAINCODE,
            "-c", json.dumps({
                "function": "RecordCreativeHistory",
                "Args": [
                    representative_token,
                    fabric_id,
                    new_uri,
                    json.dumps(all_tx_ids)
                ]
            }),
            "--waitForEvent"
        ]
        try:
            tx_result = subprocess.check_output(record_history_cmd, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            return f"체인코드 RecordCreativeHistory 호출 실패: {e.output.strip()}", 500

        # tx_id 추출 (정규표현식을 활용)
        match = re.search(r'txid \[([a-f0-9]+)\]', tx_result)
        tx_id = match.group(1) if match else "Unknown"

        # History DB 테이블에 기록 (예: history 테이블 존재, 스키마 참고)
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            from datetime import datetime
            current_timestamp = datetime.utcnow().isoformat() + "Z"
            cursor.execute(
                "INSERT INTO history (user_id, representative_token, new_history_uri, tx_id, timestamp) VALUES (?, ?, ?, ?, ?)",
                (user_id, representative_token, new_uri, tx_id, current_timestamp)
            )
            conn.commit()
        except sqlite3.Error as e:
            return f"History DB 저장 실패: {e}", 500
        finally:
            conn.close()

        return render_template('record_history_success.html',
                               representative=representative_token,
                               history_tx_ids=all_tx_ids,
                               new_history_uri=new_uri,
                               explorer_url=EXPLORER_URL,
                               tx_id=tx_id)

@app.route('/view_record', methods=['GET'])
def view_record():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # History 테이블에서 현재 사용자의 기록을 최신순으로 조회
    cursor.execute("""
        SELECT representative_token, new_history_uri, tx_id, timestamp 
        FROM history 
        WHERE user_id = ? 
        ORDER BY id DESC
    """, (user_id,))
    records = cursor.fetchall()
    conn.close()
    
    # 조회된 기록들을 딕셔너리 리스트로 구성
    history_records = []
    for rec in records:
        history_records.append({
            "representative_token": rec[0],
            "new_history_uri": rec[1],
            "tx_id": rec[2],
            "timestamp": rec[3]
        })
    
    return render_template("view_record.html", records=history_records, explorer_url=EXPLORER_URL)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=3000, debug=True)

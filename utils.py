import os
import json
import hashlib
from datetime import datetime
import subprocess
import shutil
import configparser
from PIL import Image  # Pillow 필요
import imagehash       # imagehash 필요
import requests
from io import BytesIO
from typing import List
import re
import base58
from urllib.parse import urlparse

# 설정파일에서 Fabric 관련 설정 읽어오기
config = configparser.ConfigParser()
config.read("info.conf")

FABRIC_CFG_PATH = config["FABRIC"]["FABRIC_CFG_PATH"]
FABRIC_CHANNEL = config["FABRIC"]["FABRIC_CHANNEL"]
FABRIC_CHAINCODE = config["FABRIC"]["FABRIC_CHAINCODE"]

ADMIN_CERT = config["FABRIC"]["ADMIN_CERT"]
PEER_TLS_CA = config["FABRIC"]["PEER_TLS_CA"]
CORE_PEER_ADDRESS = config["FABRIC"]["CORE_PEER_ADDRESS"]

def get_fabric_id(msp_path):
    print(msp_path)
    admincerts_dir = os.path.join(msp_path, "admincerts")
    if not os.path.exists(admincerts_dir):
        os.makedirs(admincerts_dir)
    if not os.listdir(admincerts_dir):
        admin_cert_source = ADMIN_CERT
        try:
            shutil.copy(admin_cert_source, admincerts_dir)
            print(f"Copied admin cert to {admincerts_dir}")
        except Exception as e:
            print(f"Failed to copy admin certificate: {str(e)}")
            return None

    os.environ["FABRIC_CFG_PATH"] = FABRIC_CFG_PATH
    os.environ["CORE_PEER_TLS_ENABLED"] = "true"
    os.environ["CORE_PEER_LOCALMSPID"] = "Org1MSP"
    os.environ["CORE_PEER_MSPCONFIGPATH"] = msp_path
    os.environ["CORE_PEER_TLS_ROOTCERT_FILE"] = PEER_TLS_CA
    os.environ["CORE_PEER_ADDRESS"] = CORE_PEER_ADDRESS

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

def compute_image_phash_from_url(image_url):
    """
    주어진 이미지 URL에서 pHash (perceptual hash)를 계산하여 16진수 문자열로 반환합니다.
    """
    try:
        response = requests.get(image_url)
        response.raise_for_status()
        img = Image.open(BytesIO(response.content))
        phash = imagehash.phash(img)
        return str(phash)
    except Exception as e:
        print(f"Error computing image pHash from URL: {e}")
        return None

def create_features(text: str, n: int = 3) -> List[str]:
    """
    Split the text into n-gram features.
    """
    text = text.lower()
    text = re.sub(r'[^\w\s]', '', text)
    words = text.split()
    return [' '.join(words[i:i+n]) for i in range(len(words) - n + 1)]

def simhash(text: str, hash_bits: int = 64) -> int:
    """
    Compute the SimHash of the given text.
    """
    features = create_features(text)
    v = [0] * hash_bits
    for feature in features:
        h = int(hashlib.md5(feature.encode('utf-8')).hexdigest(), 16)
        for i in range(hash_bits):
            bitmask = 1 << i
            if h & bitmask:
                v[i] += 1
            else:
                v[i] -= 1
    fingerprint = 0
    for i in range(hash_bits):
        if v[i] > 0:
            fingerprint |= (1 << i)
    return fingerprint

def compare_simhashes(hash1: int, hash2: int) -> float:
    """
    Compare two SimHash values and return similarity (0 to 1).
    """
    xor_result = bin(hash1 ^ hash2).count('1')
    similarity = 1 - (xor_result / 64)
    return similarity


def convert_ipfs_to_uint256(ipfs_url: str) -> str:
    """
    주어진 IPFS URL (예: "http://ipfs_api_address/ipfs/CID")에서 URL의 경로 부분을 파싱하여
    마지막 요소(CID)를 추출합니다.
    그런 다음, decode_cid 함수를 사용하여 멀티해시 프리픽스를 제외한 32바이트 digest를 얻고,
    해당 digest를 16진수 문자열로 변환하여 정수로 변환한 값을 문자열로 반환합니다.
    """
    # URL 파싱: 경로의 마지막 요소가 CID라고 가정
    parsed = urlparse(ipfs_url)
    parts = parsed.path.split("/")
    if not parts or parts[-1] == "":
        raise ValueError("Invalid URL format: cannot extract CID")
    cid_full = parts[-1]
    # cid_full 전체를 사용 (CIDv0는 "Qm"로 시작하지만 decode_cid가 내부에서 프리픽스를 제거합니다)
    _, token_id_int, _ = decode_cid(cid_full)
    return str(token_id_int)

def convert_uint256_to_cid(token_id_str: str) -> str:
    """
    주어진 토큰 ID (256비트 정수의 문자열 표현)를 받아서,
    2^256 범위 내의 값으로 맞춘 후, 32바이트의 big-endian 바이트열로 변환합니다.
    그런 다음, SHA-256 해시 멀티해시 프리픽스 (0x12, 0x20)를 붙이고,
    Base58로 인코딩하여 CID (CIDv0)를 반환합니다.
    """
    token_id_int = int(token_id_str)
    token_id_int = token_id_int % (1 << 256)
    try:
        digest_bytes = token_id_int.to_bytes(32, byteorder='big')
    except OverflowError as e:
        raise OverflowError(f"Token id is too big to fit in 32 bytes even after modulo: {e}")
    cid = encode_cid(digest_bytes)
    return cid

def create_nft_metadata(token_id, account, fabric_id, image_cid, prompt, base_dir="./nft"):
    """
    Create NFT metadata JSON file with computed pHash for image and SimHash for prompt,
    and save it to disk under base_dir/<token_id>/<token_id>.json.
    
    Parameters:
      token_id (str or int): NFT token ID.
      account (str): Web server account ID.
      fabric_id (str): Fabric account ID.
      image_cid (str): IPFS CID of the stored image or a full IPFS URL.
      prompt (str): User input prompt.
      base_dir (str): Base directory for saving metadata (default: "./nft").
      
    Returns:
      str: The file path of the created metadata JSON file.
    """
    # Read IPFS gateway URL from config (assumes [IPFS] section with GATEWAY_URL key)
    ipfs_gateway = config["IPFS"]["GATEWAY_URL"].rstrip("/")
    
    # If image_cid starts with "http", assume it's a full URL; otherwise, combine with gateway.
    if image_cid.startswith("http"):
        image_url = image_cid
        # Extract only the CID from the URL (last segment)
        cid_only = image_cid.rstrip("/").split("/")[-1]
    else:
        cid_only = image_cid
        image_url = ipfs_gateway + "/" + image_cid

    # Compute image pHash from image URL
    image_phash = compute_image_phash_from_url(image_url)
    
    # Compute text SimHash from prompt and convert to hex string
    prompt_simhash = simhash(prompt)
    
    # Create current UTC timestamp (ISO8601 format)
    timestamp = datetime.utcnow().isoformat() + "Z"

    # Compose metadata dictionary with all keys in English
    metadata = {
        "tokenID": token_id,
        "amount": 1,
        "account": account,
        "fabricID": fabric_id,
        "image": cid_only,         # Only store the CID
        "image_uri": image_url,      # Full image URL
        "prompt": prompt,
        "image_pHash": image_phash,
        "prompt_SimHash": prompt_simhash,
        "timestamp": timestamp
    }

    # Save file path: base_dir/<token_id>/<token_id>.json
    token_dir = os.path.join(base_dir, str(token_id))
    if not os.path.exists(token_dir):
        os.makedirs(token_dir)
    
    file_path = os.path.join(token_dir, f"{token_id}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=4)
    
    return file_path

def upload_metadata_to_ipfs(metadata_dir: str, token_id: str) -> str:
    """
    주어진 메타데이터 디렉토리를 IPFS에 업로드하고, 
    업로드된 디렉토리의 CID를 이용하여 token_id.json 형식의 메타데이터 URI를 반환합니다.
    
    Parameters:
      metadata_dir (str): 메타데이터 파일이 포함된 디렉토리 경로 (예: "./nft/<token_id>")
      token_id (str): NFT 토큰 ID (메타데이터 파일명이 token_id.json 이어야 함)
      
    Returns:
      str: IPFS 게이트웨이를 통해 접근 가능한 메타데이터 URI.
           예: http://192.168.1.131:8080/ipfs/<directoryCID>/<token_id>.json
    """
    ipfs_api_url = config["IPFS"]["IPFS_API_URL"]
    ipfs_gateway = config["IPFS"]["GATEWAY_URL"].rstrip("/")

    # 업로드할 파일 목록 생성
    # metadata_dir 내 모든 파일들을 상대 경로로 업로드 (재귀적 업로드)
    files = []
    file_handles = []
    for root, dirs, filenames in os.walk(metadata_dir):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, metadata_dir)
            f = open(file_path, "rb")
            file_handles.append(f)  # 나중에 닫기 위해 저장
            files.append(("file", (rel_path, f)))
    
    try:
        response = requests.post(ipfs_api_url, files=files)
        response.raise_for_status()
    except Exception as e:
        # 열린 파일들을 모두 닫음
        for f in file_handles:
            f.close()
        raise Exception(f"Failed to upload metadata to IPFS: {e}")

    # 모든 파일 핸들 닫기
    for f in file_handles:
        f.close()

    # IPFS API는 업로드한 각 파일에 대해 JSON 형식의 라인을 반환합니다.
    # wrap-with-directory 옵션을 사용하면, 마지막 JSON 객체의 "Name" 필드는 빈 문자열("")이고, 
    # 그 "Hash" 필드가 전체 디렉토리의 CID가 됩니다.
    directory_hash = None
    for line in response.text.strip().split("\n"):
        try:
            data = json.loads(line)
            if data.get("Name", "") == "":
                directory_hash = data.get("Hash")
        except json.JSONDecodeError:
            continue

    if not directory_hash:
        raise Exception("Failed to retrieve directory hash from IPFS response.")

    # 최종 메타데이터 URI: IPFS 게이트웨이 + "/" + directory_hash + "/" + token_id + ".json"
    metadata_uri = f"{ipfs_gateway}/{directory_hash}/{token_id}.json"
    return metadata_uri

def create_creative_history_metadata(representative_token, representative_uri, web_user_id, previous_transactions, base_dir="./history"):
    """
    창작 이력 메타파일을 생성하고, 파일로 저장합니다.
    
    파일은 base_dir/<representative_token>/<representative_token>.json 에 저장됩니다.
    
    JSON 파일의 구조:
    {
        "tokenID": 대표 nftID,
        "URI": 대표 nft의 URI,
        "사용자ID": 웹 ID,
        <txID1>: [tokenID, URI],
        <txID2>: [tokenID, URI],
        ...,
        "Timestamp": timestamp
    }
    
    Parameters:
      representative_token (str): 대표 NFT의 토큰 ID.
      representative_uri (str): 대표 NFT의 기존 URI.
      web_user_id (str): 웹 사용자 ID.
      previous_transactions (dict): 이전 트랜잭션 정보를 담은 딕셔너리.
                                     key: 이전 txID, value: [tokenID, URI]
      base_dir (str): 메타파일이 저장될 기본 디렉토리 (기본값: "./history")
      
    Returns:
      str: 생성된 메타파일의 전체 경로.
    """
    # 현재 UTC timestamp (ISO8601 형식)
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # 기본 메타데이터 구성
    metadata = {
        "tokenID": representative_token,
        "URI": representative_uri,
        "account": web_user_id,
        "Timestamp": timestamp
    }
    
    # 이전 트랜잭션 딕셔너리 내용을 그대로 병합
    # 예: { "txID1": [tokenID, URI], "txID2": [tokenID, URI], ... }
    if isinstance(previous_transactions, dict):
        metadata.update(previous_transactions)
    else:
        raise ValueError("previous_transactions must be a dictionary with txID as key and [tokenID, URI] as value")
    
    # 저장 디렉토리: base_dir/<representative_token>
    token_dir = os.path.join(base_dir, str(representative_token))
    if not os.path.exists(token_dir):
        os.makedirs(token_dir)
    
    # 파일명: <representative_token>.json
    file_path = os.path.join(token_dir, f"{representative_token}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=4)
    
    return file_path

def upload_history_metadata_to_ipfs(history_dir: str, representative_token: str) -> str:
    """
    주어진 창작 이력 메타파일이 포함된 디렉토리를 IPFS에 업로드하고,
    업로드된 디렉토리의 CID를 사용하여 최종 메타데이터 URI를 반환합니다.
    
    Parameters:
      history_dir (str): 메타파일이 저장된 디렉토리 경로 (예: "./history/<representative_token>")
      representative_token (str): 대표 NFT 토큰 ID (메타파일 이름이 representative_token.json 이어야 함)
      
    Returns:
      str: IPFS 게이트웨이를 통해 접근 가능한 창작 이력 메타데이터 URI.
           예: http://<gateway_address>/ipfs/<directoryCID>/<representative_token>.json
    """
    ipfs_api_url = config["IPFS"]["IPFS_API_URL"]
    ipfs_gateway = config["IPFS"]["GATEWAY_URL"].rstrip("/")

    # 업로드할 파일 목록 생성 (history_dir 내 모든 파일 재귀적 업로드)
    files = []
    file_handles = []
    for root, dirs, filenames in os.walk(history_dir):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, history_dir)
            f = open(file_path, "rb")
            file_handles.append(f)
            files.append(("file", (rel_path, f)))
    
    try:
        response = requests.post(ipfs_api_url, files=files)
        response.raise_for_status()
    except Exception as e:
        for f in file_handles:
            f.close()
        raise Exception(f"Failed to upload history metadata to IPFS: {e}")
    
    # 모든 파일 핸들 닫기
    for f in file_handles:
        f.close()
    
    # IPFS API의 응답에서 전체 디렉토리의 CID 추출 (wrap-with-directory 옵션 사용 시)
    directory_hash = None
    for line in response.text.strip().split("\n"):
        try:
            data = json.loads(line)
            if data.get("Name", "") == "":
                directory_hash = data.get("Hash")
        except json.JSONDecodeError:
            continue
    
    if not directory_hash:
        raise Exception("Failed to retrieve directory hash from IPFS response.")
    
    # 최종 창작 이력 메타데이터 URI 구성
    metadata_uri = f"{ipfs_gateway}/{directory_hash}/{representative_token}.json"
    return metadata_uri

def create_and_upload_creative_history(representative_token, representative_uri, web_user_id, previous_transactions):
    """
    대표 NFT의 창작 이력 메타파일을 생성하고, 이를 IPFS에 업로드한 후
    반환받은 IPFS CID 주소를 이용해 새로운 URI를 생성합니다.
    
    Parameters:
      representative_token (str): 대표 NFT 토큰 ID.
      representative_uri (str): 대표 NFT의 기존 URI.
      web_user_id (str): 웹 사용자 ID.
      previous_transactions (dict): 이전 트랜잭션 정보를 담은 딕셔너리.
                                    key: 이전 txID, value: [tokenID, URI]
      
    Returns:
      str: IPFS 게이트웨이를 통해 접근 가능한 창작 이력 메타데이터 URI.
    """
    # 메타파일 생성: 파일명은 대표 NFT 토큰 ID, 경로는 ./history/<representative_token>/<representative_token>.json
    metadata_file = create_creative_history_metadata(
        representative_token, representative_uri, web_user_id, previous_transactions, base_dir="./history"
    )
    
    # 메타파일이 있는 디렉토리 (./history/<representative_token>)를 IPFS에 업로드하여 새로운 URI 생성
    history_dir = os.path.dirname(metadata_file)
    new_uri = upload_history_metadata_to_ipfs(history_dir, representative_token)
    
    return new_uri

def decode_cid(cid: str) -> (bytes, int, str):
    """
    주어진 CID (Base58 문자열)를 디코딩하여,
    - digest_bytes: 멀티해시 프리픽스를 제외한 32바이트 digest (bytes)
    - num: 256비트 정수 (int)
    - hex_value: 32바이트 digest의 16진수 문자열 (str)
    를 반환합니다.
    """
    decoded_bytes = base58.b58decode(cid)
    # 앞의 2바이트(멀티해시 프리픽스)를 제외한 나머지 32바이트 사용
    digest_bytes = decoded_bytes[2:]
    hex_value = digest_bytes.hex()
    num = int(hex_value, 16)
    return digest_bytes, num, hex_value

def encode_cid(digest_bytes: bytes) -> str:
    """
    32바이트 digest를 입력받아,
    SHA-256 해시를 의미하는 multihash prefix (0x12: SHA-256, 0x20: 32바이트)를 붙인 후,
    Base58로 인코딩한 CID 문자열을 반환합니다.
    """
    if len(digest_bytes) != 32:
        raise ValueError("Digest must be exactly 32 bytes.")
    multihash_bytes = bytes([0x12, 0x20]) + digest_bytes
    cid = base58.b58encode(multihash_bytes).decode()
    return cid

def encode_cid_from_int(num: int) -> str:
    """
    256비트 정수(num)를 32바이트 big-endian 바이트열로 변환한 후,
    encode_cid 함수를 호출하여 Base58 CID 문자열을 반환합니다.
    """
    digest_bytes = num.to_bytes(32, byteorder='big')
    return encode_cid(digest_bytes)

if __name__ == "__main__":
    # 예시 IPFS URL (CIDv0 형태)
    ipfs_url = "http://192.168.1.131:8080/ipfs/QmbAkvnBz9hajKifh2ECM8BfMdj7Sxe1vbb1ptK1dcs4xg"
    token_id_str = convert_ipfs_to_uint256(ipfs_url)
    print("IPFS URL:", ipfs_url)
    print("Converted uint256 (as string):", token_id_str)
    
    reconstructed_cid = convert_uint256_to_cid(token_id_str)
    print("Reconstructed CID:", reconstructed_cid)
    previous_transactions = {
    "txid11111": ["11111", "https://example.com/tx1-uri"],
    "txid22222": ["22222", "https://example.com/tx2-uri"]
    }

    new_history_uri = create_and_upload_creative_history(
    representative_token="12345",
    representative_uri="https://example.com/old-uri",
    web_user_id="webUser01",
    previous_transactions=previous_transactions
    )
    print("New Creative History URI:", new_history_uri)

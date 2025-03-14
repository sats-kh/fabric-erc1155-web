# Backup
#@app.route('/query_user', methods=['GET'])
def query_user():
    if 'username' not in session or 'msp_path' not in session:
        return jsonify({"error": "User not logged in"}), 401

    username = session['username']
    msp_path = session['msp_path']
    print("Using MSP path:", msp_path)

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

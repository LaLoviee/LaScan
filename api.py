from flask import Flask, request, jsonify
import jwt
import requests
import config

headers = {
    "X-Auth": config.ACUNETIX_API_KEY,
    "Content-Type": "application/json"
}

app = Flask(__name__)

def verify_token(token):
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=['HS256'])
        return payload.get('user_id')
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

@app.route('/api/start', methods=['POST'])
def start():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"response": "Missing token."}), 401

    user_id = verify_token(token)
    if not user_id:
        return jsonify({"response": "Invalid or expired token."}), 401

    return jsonify({"response": "Hello! This is a response from the /api/start endpoint."})

@app.route('/api/acunetix/<path:forward_part>', methods=['GET', 'POST'])
def acunetix(forward_part):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"response": "Missing token."}), 401

    user_id = verify_token(token)
    if not user_id:
        return jsonify({"response": "Invalid or expired token."}), 401

    host = config.HOST.rstrip('/')
    url = f"{host}/api/v1/{forward_part}"

    try:
        if request.method == 'POST':
            response = requests.post(url, headers=headers, json=request.json, verify=False, timeout=30)
        else:
            response = requests.get(url, headers=headers, params=request.args, verify=False, timeout=30)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=getattr(config, 'API_PORT', 5000))

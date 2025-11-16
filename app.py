# flask_app/app.py
import os
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory, abort
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth, firestore
from flask import redirect, url_for

# Initialize Flask
app = Flask(__name__, template_folder="templates", static_folder="static")

# Initialize Firebase Admin SDK
# Option 1: set env var GOOGLE_APPLICATION_CREDENTIALS to path of service-account.json
# Option 2: place service-account.json in this folder and set path below
cred_path = ("serviceAccount.json")
if not firebase_admin._apps:
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)

db = firestore.client()

@app.route("/")
def index():
    # Serve a small client-side protected page that checks Firebase auth
    return render_template("index.html")

@app.route("/profile")
def profile_page():
    return render_template("profile.html")

# API: return user doc for the currently signed-in user (verify ID token)
@app.route("/api/get_user", methods=["GET"])
def api_get_user():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    try:
        doc = db.collection("users").document(uid).get()
        if not doc.exists:
            return jsonify({"error": "user doc not found"}), 404
        return jsonify(doc.to_dict()), 200
    except Exception as e:
        return jsonify({"error": "Failed to read Firestore", "details": str(e)}), 500
    
    
# Serve signup page
@app.route("/signup")
def signup_page():
    return render_template("signup.html")

# Serve signin page
@app.route("/signin")
def signin_page():
    return render_template("signin.html")

# Secure endpoint: create user document in Firestore after verifying ID token
@app.route("/api/create_user", methods=["POST"])
def api_create_user():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    email = decoded.get("email")

    payload = request.get_json() or {}
    name = payload.get("name")
    if not name:
        return jsonify({"error": "Missing name in payload"}), 400

    # Create or update user doc with uid as document id
    user_doc = {
        "name": name,
        "email": email,
        "uid": uid,
        "createdAt": datetime.utcnow().isoformat() + "Z"
    }

    try:
        db.collection("users").document(uid).set(user_doc, merge=True)
    except Exception as e:
        return jsonify({"error": "Failed to write to Firestore", "details": str(e)}), 500

    return jsonify({"ok": True, "user": user_doc}), 200


# Optional: a simple health check
@app.route("/health")
def health():
    return "ok", 200

@app.route("/user")
def user_page():
    return render_template("user.html")

@app.route("/admin")
def admin_page():
    return render_template("admin.html")

@app.route("/waiter")
def waiter_page():
    return render_template("waiter.html")

@app.route("/kitchen")
def kitchen_page():
    return render_template("kitchen.html")


if __name__ == "__main__":
    # For local dev only. In production use a WSGI server or container.
    app.run(port=5000, debug=True)
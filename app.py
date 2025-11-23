import os
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory, abort
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth, firestore
from flask import redirect, url_for
import uuid
from werkzeug.utils import secure_filename

# Initialize Flask
app = Flask(__name__, template_folder="templates", static_folder="static")

# Configure upload folder and allowed extensions
UPLOAD_FOLDER = os.path.join(app.static_folder, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure that upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Firebase Admin SDK (same as your old code)
cred_path = ("serviceAccount.json")
if not firebase_admin._apps:
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)

db = firestore.client()

# Helper function to check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper function to handle file uploads
def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = str(uuid.uuid4()) + '_' + filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        # Return URL that can be used to access the file
        return f"/static/uploads/{unique_filename}"
    return None

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

# API: Get all users without roles
@app.route("/api/get_users", methods=["GET"])
def api_get_users():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Get all users without roles
    try:
        users = []
        docs = db.collection("users").stream()
        for doc in docs:
            user_data = doc.to_dict()
            role = user_data.get("role")
            if not role or role not in ["admin", "kitchen", "waiter"]:
                users.append({
                    "uid": doc.id,
                    **user_data
                })
        return jsonify(users), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch users", "details": str(e)}), 500

# API: Get all waiters
@app.route("/api/get_waiters", methods=["GET"])
def api_get_waiters():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Get all users with waiter role
    try:
        waiters = []
        docs = db.collection("users").where("role", "==", "waiter").stream()
        for doc in docs:
            waiters.append({
                "uid": doc.id,
                **doc.to_dict()
            })
        return jsonify(waiters), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch waiters", "details": str(e)}), 500

# API: Get all kitchen staff
@app.route("/api/get_kitchen", methods=["GET"])
def api_get_kitchen():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Get all users with kitchen role
    try:
        kitchen = []
        docs = db.collection("users").where("role", "==", "kitchen").stream()
        for doc in docs:
            kitchen.append({
                "uid": doc.id,
                **doc.to_dict()
            })
        return jsonify(kitchen), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch kitchen staff", "details": str(e)}), 500

# API: Assign role to user
@app.route("/api/assign_role", methods=["POST"])
def api_assign_role():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Get request data
    try:
        data = request.get_json()
        target_uid = data.get("uid")
        role = data.get("role")
        
        if not target_uid or not role or role not in ["waiter", "kitchen"]:
            return jsonify({"error": "Invalid request data"}), 400
        
        # Update user role
        db.collection("users").document(target_uid).update({"role": role})
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": "Failed to assign role", "details": str(e)}), 500

# API: Remove role from user
@app.route("/api/remove_role", methods=["POST"])
def api_remove_role():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Get request data
    try:
        data = request.get_json()
        target_uid = data.get("uid")
        
        if not target_uid:
            return jsonify({"error": "Invalid request data"}), 400
        
        # Remove user role
        from firebase_admin import firestore
        db.collection("users").document(target_uid).update({
            "role": firestore.DELETE_FIELD
        })
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": "Failed to remove role", "details": str(e)}), 500

# API: Get all categories
@app.route("/api/get_categories", methods=["GET"])
def api_get_categories():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Get all categories
    try:
        categories = []
        docs = db.collection("categories").order_by("name").stream()
        for doc in docs:
            categories.append({
                "id": doc.id,
                **doc.to_dict()
            })
        return jsonify(categories), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch categories", "details": str(e)}), 500

# API: Create category
@app.route("/api/create_category", methods=["POST"])
def api_create_category():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Get request data
    try:
        name = request.form.get("name")
        description = request.form.get("description", "")
        
        if not name:
            return jsonify({"error": "Category name is required"}), 400
        
        # Handle image upload
        image_url = None
        if 'image' in request.files:
            image_file = request.files['image']
            image_url = save_uploaded_file(image_file)
        
        # Create category document
        category_doc = {
            "name": name,
            "description": description,
            "image": image_url,
            "createdAt": datetime.utcnow().isoformat() + "Z"
        }
        
        doc_ref = db.collection("categories").document()
        doc_ref.set(category_doc)
        return jsonify({"success": True, "id": doc_ref.id}), 200
    except Exception as e:
        return jsonify({"error": "Failed to create category", "details": str(e)}), 500

# API: Update category
@app.route("/api/update_category/<category_id>", methods=["PUT"])
def api_update_category(category_id):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Get request data
    try:
        name = request.form.get("name")
        description = request.form.get("description", "")
        
        if not name:
            return jsonify({"error": "Category name is required"}), 400
        
        # Prepare update data
        update_data = {
            "name": name,
            "description": description,
            "updatedAt": datetime.utcnow().isoformat() + "Z"
        }
        
        # Handle image upload if provided
        if 'image' in request.files:
            image_file = request.files['image']
            image_url = save_uploaded_file(image_file)
            if image_url:
                update_data["image"] = image_url
        
        # Update category document
        db.collection("categories").document(category_id).update(update_data)
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": "Failed to update category", "details": str(e)}), 500

# API: Delete category
@app.route("/api/delete_category/<category_id>", methods=["DELETE"])
def api_delete_category(category_id):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Delete category
    try:
        db.collection("categories").document(category_id).delete()
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": "Failed to delete category", "details": str(e)}), 500

# API: Get all products
@app.route("/api/get_products", methods=["GET"])
def api_get_products():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Get all products
    try:
        products = []
        docs = db.collection("products").order_by("name").stream()
        for doc in docs:
            products.append({
                "id": doc.id,
                **doc.to_dict()
            })
        return jsonify(products), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch products", "details": str(e)}), 500

# API: Create product
@app.route("/api/create_product", methods=["POST"])
def api_create_product():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Get request data
    try:
        name = request.form.get("name")
        category_id = request.form.get("categoryId")
        description = request.form.get("description", "")
        ingredients = request.form.get("ingredients", "")
        normal_price = float(request.form.get("normalPrice", 0))
        offer_price = float(request.form.get("offerPrice", 0))
        availability = request.form.get("availability", "available")
        featured = request.form.get("featured") == "true"
        
        if not name or not category_id:
            return jsonify({"error": "Product name and category are required"}), 400
        
        # Handle cover image upload
        cover_image_url = None
        if 'coverImage' in request.files:
            image_file = request.files['coverImage']
            cover_image_url = save_uploaded_file(image_file)
        
        # Handle product images upload (up to 4)
        product_image_urls = []
        for i in range(4):  # up to 4 images
            image_key = f'productImage{i}'
            if image_key in request.files:
                image_file = request.files[image_key]
                url = save_uploaded_file(image_file)
                if url:
                    product_image_urls.append(url)
        
        # Create product document
        product_doc = {
            "name": name,
            "categoryId": category_id,
            "description": description,
            "ingredients": ingredients,
            "normalPrice": normal_price,
            "offerPrice": offer_price,
            "availability": availability,
            "featured": featured,
            "coverImage": cover_image_url,
            "images": product_image_urls,
            "createdAt": datetime.utcnow().isoformat() + "Z"
        }
        
        doc_ref = db.collection("products").document()
        doc_ref.set(product_doc)
        return jsonify({"success": True, "id": doc_ref.id}), 200
    except Exception as e:
        return jsonify({"error": "Failed to create product", "details": str(e)}), 500

# API: Update product
@app.route("/api/update_product/<product_id>", methods=["PUT"])
def api_update_product(product_id):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Get request data
    try:
        name = request.form.get("name")
        category_id = request.form.get("categoryId")
        description = request.form.get("description", "")
        ingredients = request.form.get("ingredients", "")
        normal_price = float(request.form.get("normalPrice", 0))
        offer_price = float(request.form.get("offerPrice", 0))
        availability = request.form.get("availability", "available")
        featured = request.form.get("featured") == "true"
        
        if not name or not category_id:
            return jsonify({"error": "Product name and category are required"}), 400
        
        # Prepare update data
        update_data = {
            "name": name,
            "categoryId": category_id,
            "description": description,
            "ingredients": ingredients,
            "normalPrice": normal_price,
            "offerPrice": offer_price,
            "availability": availability,
            "featured": featured,
            "updatedAt": datetime.utcnow().isoformat() + "Z"
        }
        
        # Handle cover image upload if provided
        if 'coverImage' in request.files:
            image_file = request.files['coverImage']
            cover_image_url = save_uploaded_file(image_file)
            if cover_image_url:
                update_data["coverImage"] = cover_image_url
        
        # Handle product images upload if provided (up to 4)
        product_image_urls = []
        for i in range(4):  # up to 4 images
            image_key = f'productImage{i}'
            if image_key in request.files:
                image_file = request.files[image_key]
                url = save_uploaded_file(image_file)
                if url:
                    product_image_urls.append(url)
        
        if product_image_urls:
            update_data["images"] = product_image_urls
        
        # Update product document
        db.collection("products").document(product_id).update(update_data)
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": "Failed to update product", "details": str(e)}), 500

# API: Delete product
@app.route("/api/delete_product/<product_id>", methods=["DELETE"])
def api_delete_product(product_id):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    id_token = auth_header.split(" ", 1)[1]

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception as e:
        return jsonify({"error": "Invalid ID token", "details": str(e)}), 401

    uid = decoded.get("uid")
    
    # Check if user is admin
    try:
        admin_doc = db.collection("users").document(uid).get()
        if not admin_doc.exists or admin_doc.to_dict().get("role") != "admin":
            return jsonify({"error": "Access denied"}), 403
    except Exception as e:
        return jsonify({"error": "Failed to verify admin role", "details": str(e)}), 500
    
    # Delete product
    try:
        db.collection("products").document(product_id).delete()
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": "Failed to delete product", "details": str(e)}), 500

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

@app.route("/user_manage")
def user_manage_page():
    return render_template("user_manage.html")

@app.route("/manage_products")
def manage_products_page():
    return render_template("manage_products.html")

@app.route("/manage_categories")
def manage_categories_page():
    return render_template("manage_categories.html")

if __name__ == "__main__":
    # For local dev only. In production use a WSGI server or container.
    app.run(port=5000, debug=True)
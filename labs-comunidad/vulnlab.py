#!/usr/bin/env python3
# ============================================================================
#  vulnlab.py  —  LABORATORIO WEB INTENCIONALMENTE VULNERABLE (solo local)
#  Para la comunidad: cada endpoint enseña UNA clase de vulnerabilidad web.
#  ⚠️ NUNCA exponer esto a Internet. Correr SOLO en localhost, para practicar.
#  Correr:  pip install flask requests lxml pyjwt  &&  python3 vulnlab.py
#  Escucha en http://127.0.0.1:5000
# ============================================================================
import os, sqlite3, subprocess, pickle, base64
from flask import Flask, request, Response
from lxml import etree
import requests, jwt

app = Flask(__name__)
JWT_SECRET = "s3cr3t"          # secreto DEBIL a propósito (crackeable)

# --- base de datos de ejemplo (SQLi) ---
def db():
    c = sqlite3.connect(":memory:")
    c.executescript("""
      CREATE TABLE users(id INTEGER, username TEXT, secret TEXT);
      INSERT INTO users VALUES (1,'alice','alice_public_bio');
      INSERT INTE_PLACEHOLDER users VALUES (2,'bob','bob_public_bio');
      INSERT INTO users VALUES (99,'admin','FLAG{sqli_secret_del_admin}');
    """.replace("INSERT INTE_PLACEHOLDER","INSERT INTO"))
    return c

@app.route("/")
def index():
    return ("<h1>vulnlab</h1><ul>"
            "<li>/greet?name= (SSTI)</li>"
            "<li>/ping?host= (Command Injection)</li>"
            "<li>/fetch?url= (SSRF)</li>"
            "<li>/user?id= (SQLi)</li>"
            "<li>/search?q= (XSS reflejado)</li>"
            "<li>POST /xxe (XXE)</li>"
            "<li>POST /login , GET /admin (JWT)</li>"
            "<li>POST /load (Deserializacion insegura - pickle)</li></ul>")

# 8) DESERIALIZACION INSEGURA — pickle.loads sobre datos del usuario
@app.route("/load", methods=["POST"])
def load():
    data = request.get_data()
    try:
        obj = pickle.loads(base64.b64decode(data))   # ⚠️ pickle NUNCA sobre input no confiable
        return "deserializado: " + repr(obj)
    except Exception as e:
        return "error: " + str(e)

# 1) SSTI — el input se renderiza COMO plantilla Jinja2
@app.route("/greet")
def greet():
    from flask import render_template_string
    name = request.args.get("name", "invitado")
    return render_template_string("<p>Hola, " + name + "!</p>")

# 2) COMMAND INJECTION — host va sin sanitizar a un shell
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.run("ping -c 1 " + host, shell=True,
                         capture_output=True, text=True, timeout=8)
    return "<pre>" + out.stdout + out.stderr + "</pre>"

# 3) SSRF — el server pide la URL que vos elijas
@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    try:
        r = requests.get(url, timeout=6)
        return Response(r.text, mimetype="text/plain")
    except Exception as e:
        return "error: " + str(e)

# 4) SQLi — id concatenado a la query (permite UNION)
@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    c = db()
    try:
        rows = c.execute("SELECT id, username FROM users WHERE id = " + uid).fetchall()
        return "<pre>" + "\n".join(str(r) for r in rows) + "</pre>"
    except Exception as e:
        return "SQL error: " + str(e)

# 5) XSS reflejado — q se refleja sin escapar
@app.route("/search")
def search():
    q = request.args.get("q", "")
    return "<p>Resultados para: " + q + "</p>"

# 6) XXE — parser con entidades externas habilitadas
@app.route("/xxe", methods=["POST"])
def xxe():
    data = request.get_data()
    try:
        parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
        root = etree.fromstring(data, parser)
        return Response(etree.tostring(root), mimetype="text/plain")
    except Exception as e:
        return "XML error: " + str(e)

# 7) JWT — secreto debil (HS256), /admin confia en el claim role
@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("user", "guest")
    tok = jwt.encode({"user": u, "role": "user"}, JWT_SECRET, algorithm="HS256")
    return tok

@app.route("/admin")
def admin():
    auth = request.headers.get("Authorization", "")
    tok = auth.replace("Bearer ", "") or request.args.get("token", "")
    try:
        claims = jwt.decode(tok, JWT_SECRET, algorithms=["HS256"])
        if claims.get("role") == "admin":
            return "Bienvenido admin! FLAG{jwt_forjado_role_admin}"
        return "Sos '" + str(claims.get("role")) + "', no admin."
    except Exception as e:
        return "JWT invalido: " + str(e)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)

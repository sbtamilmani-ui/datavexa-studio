import os, sqlite3, secrets, csv, io, re
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, Response
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "datavexa.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
# Lightweight CSRF and request-throttling helpers using only Flask/Werkzeug.
_request_hits = {}

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

@app.before_request
def protect_forms_and_throttle():
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not supplied or not expected or not secrets.compare_digest(supplied, expected):
            abort(400, description="The form security token is missing or expired. Refresh the page and try again.")
        limit = None
        window = None
        if request.endpoint == "contact":
            limit, window = 5, 3600
        elif request.endpoint == "admin_login":
            limit, window = 10, 900
        if limit:
            now = __import__("time").time()
            key = (request.remote_addr or "unknown", request.endpoint)
            hits = [stamp for stamp in _request_hits.get(key, []) if now - stamp < window]
            if len(hits) >= limit:
                abort(429, description="Too many attempts. Please wait before trying again.")
            hits.append(now)
            _request_hits[key] = hits
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, category TEXT NOT NULL DEFAULT 'Web Solutions',
            summary TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', technologies TEXT NOT NULL DEFAULT '',
            image TEXT NOT NULL DEFAULT '', demo_url TEXT NOT NULL DEFAULT '', github_url TEXT NOT NULL DEFAULT '',
            featured INTEGER NOT NULL DEFAULT 0, published INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        con.execute("""CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL,
            service TEXT NOT NULL DEFAULT '', budget TEXT NOT NULL DEFAULT '', message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New', follow_up_date TEXT NOT NULL DEFAULT '',
            admin_notes TEXT NOT NULL DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        # Safe additive migration: existing inquiry records are preserved.
        message_columns = {row[1] for row in con.execute("PRAGMA table_info(messages)").fetchall()}
        for column, definition in [("status", "TEXT NOT NULL DEFAULT 'New'"), ("follow_up_date", "TEXT NOT NULL DEFAULT ''"), ("admin_notes", "TEXT NOT NULL DEFAULT ''")]:
            if column not in message_columns:
                con.execute(f"ALTER TABLE messages ADD COLUMN {column} {definition}")
        con.execute("""CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)""")
        count = con.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        if count == 0:
            samples = [
                ("PatrolIQ Crime Analytics", "patroliq-crime-analytics", "Data Analytics",
                 "Explore crime patterns with interactive maps, clustering, and trend analysis.",
                 "A portfolio-ready analytics concept demonstrating data cleaning, geographic visualization, clustering, and clear decision-support insights.",
                 "Python, Pandas, Plotly, Folium, Scikit-learn", "", "", "", 1, 1),
                ("AI Business Report Generator", "ai-business-report-generator", "AI & Automation",
                 "Turn spreadsheets into readable summaries, KPIs, charts, and recommendations.",
                 "A business analytics concept designed to help teams understand their data faster through automated summaries, visualizations, and action-oriented insights.",
                 "Python, Streamlit, Pandas, Matplotlib", "", "", "", 1, 1),
                ("Business Website Concept", "business-website-concept", "Web Solutions",
                 "A responsive, conversion-focused website concept for a local business.",
                 "A modern responsive website concept with service sections, clear calls to action, and a mobile-first layout.",
                 "HTML, CSS, JavaScript", "", "", "", 0, 1)
            ]
            con.executemany("""INSERT INTO projects
                (title,slug,category,summary,description,technologies,image,demo_url,github_url,featured,published)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""", samples)

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            flash("Please sign in to access the dashboard.", "error")
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)
    return wrapped

def slugify(text):
    import re
    value = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower()).strip("-")
    return value or "project"

@app.context_processor
def shared_context():
    return {"site_name": "DataVexa Studio", "csrf_token": csrf_token}

@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response

@app.route("/")
def home():
    with db() as con:
        projects = con.execute("SELECT * FROM projects WHERE published=1 AND featured=1 ORDER BY created_at DESC LIMIT 3").fetchall()
    return render_template("index.html", projects=projects)

@app.route("/services")
def services():
    return render_template("services.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")

@app.route("/projects")
def projects():
    category = request.args.get("category", "").strip()
    with db() as con:
        if category:
            rows = con.execute("SELECT * FROM projects WHERE published=1 AND category=? ORDER BY created_at DESC", (category,)).fetchall()
        else:
            rows = con.execute("SELECT * FROM projects WHERE published=1 ORDER BY featured DESC, created_at DESC").fetchall()
        categories = [r["category"] for r in con.execute("SELECT DISTINCT category FROM projects WHERE published=1 ORDER BY category").fetchall()]
    return render_template("projects.html", projects=rows, categories=categories, selected_category=category)

@app.route("/showcase")
def showcase():
    with db() as con:
        rows = con.execute("SELECT * FROM projects WHERE published=1 ORDER BY featured DESC, created_at DESC").fetchall()
    return render_template("showcase.html", projects=rows)

@app.route("/projects/<slug>")
def project_detail(slug):
    with db() as con:
        project = con.execute("SELECT * FROM projects WHERE slug=? AND published=1", (slug,)).fetchone()
    if not project:
        abort(404)
    return render_template("project_detail.html", project=project)

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        service = request.form.get("service", "").strip()
        budget = request.form.get("budget", "").strip()
        message = request.form.get("message", "").strip()
        if not name or not email or not message:
            flash("Please fill in your name, email, and project message.", "error")
        elif len(message) > 5000 or len(name) > 120 or len(email) > 254:
            flash("One or more fields are too long.", "error")
        else:
            with db() as con:
                con.execute("INSERT INTO messages (name,email,service,budget,message) VALUES (?,?,?,?,?)",
                            (name, email, service, budget, message))
            flash("Thanks! Your inquiry has been saved. We will get back to you soon.", "success")
            return redirect(url_for("contact"))
    return render_template("contact.html")

@app.route("/admin")
def admin():
    if not session.get("admin_id"):
        return redirect(url_for("admin_login"))
    with db() as con:
        projects = con.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
        messages = con.execute("SELECT * FROM messages ORDER BY created_at DESC").fetchall()
        lead_counts = {row["status"]: row["n"] for row in con.execute("SELECT status, COUNT(*) AS n FROM messages GROUP BY status").fetchall()}
    return render_template("admin.html", projects=projects, messages=messages, lead_counts=lead_counts)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    with db() as con:
        admin_count = con.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
    if admin_count == 0:
        flash("Create your first admin account using the setup command in README.md.", "error")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as con:
            user = con.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["admin_id"] = user["id"]
            session["admin_username"] = user["username"]
            return redirect(url_for("admin"))
        flash("Incorrect username or password.", "error")
    return render_template("admin_login.html")

@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    flash("You have signed out.", "success")
    return redirect(url_for("home"))

@app.route("/admin/project/new", methods=["GET", "POST"])
@app.route("/admin/project/<int:project_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_project(project_id=None):
    with db() as con:
        project = con.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone() if project_id else None
    if project_id and not project:
        abort(404)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "Web Solutions").strip()
        summary = request.form.get("summary", "").strip()
        description = request.form.get("description", "").strip()
        technologies = request.form.get("technologies", "").strip()
        demo_url = request.form.get("demo_url", "").strip()
        github_url = request.form.get("github_url", "").strip()
        featured = 1 if request.form.get("featured") else 0
        published = 1 if request.form.get("published") else 0
        slug = slugify(request.form.get("slug", "") or title)
        image = project["image"] if project else ""
        upload = request.files.get("image_file")
        if upload and upload.filename:
            if "." not in upload.filename or upload.filename.rsplit(".", 1)[1].lower() not in ALLOWED_EXTENSIONS:
                flash("Upload a PNG, JPG, JPEG, WEBP, or GIF image.", "error")
                return render_template("project_form.html", project=project)
            filename = secure_filename(upload.filename)
            stem, ext = os.path.splitext(filename)
            filename = f"{slug}-{secrets.token_hex(4)}{ext.lower()}"
            upload.save(os.path.join(UPLOAD_DIR, filename))
            image = "/static/uploads/" + filename
        if not title or not summary:
            flash("Project title and short summary are required.", "error")
            return render_template("project_form.html", project=project)
        try:
            with db() as con:
                values = (title, slug, category, summary, description, technologies, image, demo_url, github_url, featured, published)
                if project:
                    con.execute("""UPDATE projects SET title=?,slug=?,category=?,summary=?,description=?,technologies=?,image=?,demo_url=?,github_url=?,featured=?,published=? WHERE id=?""", values + (project_id,))
                else:
                    con.execute("""INSERT INTO projects (title,slug,category,summary,description,technologies,image,demo_url,github_url,featured,published) VALUES (?,?,?,?,?,?,?,?,?,?,?)""", values)
            flash("Project saved successfully.", "success")
            return redirect(url_for("admin"))
        except sqlite3.IntegrityError:
            flash("That project URL slug already exists. Choose a different slug.", "error")
    return render_template("project_form.html", project=project)

@app.route("/admin/project/<int:project_id>/delete", methods=["POST"])
@admin_required
def delete_project(project_id):
    with db() as con:
        con.execute("DELETE FROM projects WHERE id=?", (project_id,))
    flash("Project deleted.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/message/<int:message_id>/update", methods=["POST"])
@admin_required
def update_message(message_id):
    status = request.form.get("status", "New").strip()
    if status not in {"New", "Contacted", "Qualified", "Won", "Lost"}:
        abort(400)
    follow_up_date = request.form.get("follow_up_date", "").strip()[:10]
    admin_notes = request.form.get("admin_notes", "").strip()[:3000]
    with db() as con:
        cur = con.execute("UPDATE messages SET status=?, follow_up_date=?, admin_notes=? WHERE id=?", (status, follow_up_date, admin_notes, message_id))
        if cur.rowcount == 0:
            abort(404)
    flash("Lead details updated.", "success")
    return redirect(url_for("admin") + "#inquiries")

@app.route("/admin/messages.csv")
@admin_required
def export_messages():
    with db() as con:
        rows = con.execute("SELECT id,name,email,service,budget,message,status,follow_up_date,admin_notes,created_at FROM messages ORDER BY created_at DESC").fetchall()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["ID", "Name", "Email", "Service", "Budget", "Message", "Status", "Follow-up date", "Admin notes", "Created at"])
    writer.writerows([tuple(row) for row in rows])
    return Response("\ufeff" + output.getvalue(), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=datavexa-leads.csv"})

@app.route("/robots.txt")
def robots_txt():
    base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    lines = ["User-agent: *", "Allow: /", "Disallow: /admin", "Disallow: /admin/"]
    if base and not base.endswith(".example"):
        lines.append(f"Sitemap: {base}/sitemap.xml")
    return Response("\n".join(lines) + "\n", mimetype="text/plain")

@app.route("/sitemap.xml")
def sitemap_xml():
    base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    if not base or base.endswith(".example"):
        base = request.url_root.rstrip("/")
    paths = [url_for("home"), url_for("services"), url_for("about"), url_for("projects"), url_for("showcase"), url_for("contact")]
    with db() as con:
        slugs = con.execute("SELECT slug FROM projects WHERE published=1").fetchall()
    urls = "".join(f"<url><loc>{base}{path}</loc></url>" for path in paths)
    urls += "".join(f"<url><loc>{base}{url_for('project_detail', slug=row['slug'])}</loc></url>" for row in slugs)
    return Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + urls + '</urlset>', mimetype="application/xml")

@app.route("/health")
def health():
    return {"status": "ok"}, 200

@app.route("/admin/message/<int:message_id>/delete", methods=["POST"])
@admin_required
def delete_message(message_id):
    with db() as con:
        con.execute("DELETE FROM messages WHERE id=?", (message_id,))
    flash("Inquiry deleted.", "success")
    return redirect(url_for("admin"))

@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404

def create_admin(username, password):
    init_db()
    with db() as con:
        con.execute("INSERT INTO admins (username,password_hash) VALUES (?,?)",
                    (username, generate_password_hash(password)))
    print(f"Admin account '{username}' created.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--create-admin", nargs=2, metavar=("USERNAME", "PASSWORD"))
    args = parser.parse_args()
    init_db()
    if args.create_admin:
        create_admin(args.create_admin[0], args.create_admin[1])
    else:
        # Local development only. Use a production WSGI server when deploying publicly.
        app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=os.environ.get("FLASK_DEBUG", "0") == "1")

from http.server
import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import http.cookies
import hashlib
import db

SESSIONS = {}  

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

class BlogServer(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            return self.serve_index()
        elif self.path == "/register":
            return self.render("register.html")
        elif self.path == "/login":
            return self.render("login.html")
        elif self.path == "/dashboard":
            return self.serve_dashboard()
        elif self.path.startswith("/static/"):
            return self.serve_static(self.path[1:])
        else:
            self.send_error(404, "Page not found")

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(length).decode()
        form = urllib.parse.parse_qs(data)

        if self.path == "/register":
            return self.handle_register(form)
        elif self.path == "/login":
            return self.handle_login(form)
        elif self.path == "/create":
            return self.handle_create(form)
        else:
            self.send_error(404, "Page not found")

                            
   def serve_index(self):
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT posts.id, users.username, posts.title, posts.content, posts.created_at FROM posts JOIN users ON posts.user_id = users.id ORDER BY posts.created_at DESC")
        posts = cur.fetchall()
        cur.close()
        conn.close()

        html = "<h1>Blog Home</h1><a href='/register'>Register</a> | <a href='/login'>Login</a><hr>"
        for p in posts:
            html += f"<h2>{p[2]}</h2><p>{p[3]}</p><small>By {p[1]} at {p[4]}</small><hr>"
        self.respond(html)

    def serve_dashboard(self):
        user_id = self.get_logged_in_user()
        if not user_id:
            self.redirect("/login")
            return
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, title, content, created_at FROM posts WHERE user_id=%s", (user_id,))
        posts = cur.fetchall()
        cur.close()
        conn.close()

        html = "<h1>Your Dashboard</h1><a href='/'>Home</a><hr>"
        html += """
            <form method="POST" action="/create">
            <input name="title" placeholder="Title"><br>
            <textarea name="content"></textarea><br>
            <button type="submit">Create Post</button>
            </form><hr>
        """
        for p in posts:
            html += f"<h2>{p[1]}</h2><p>{p[2]}</p><small>{p[3]}</small><hr>"
        self.respond(html)

    def handle_register(self, form):
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        conn = db.get_connection()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", 
                        (username, hash_password(password)))
            conn.commit()
            self.redirect("/login")
        except:
            self.respond("Registration failed. Try again.")
        finally:
            cur.close()
            conn.close()

    def handle_login(self, form):
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, password FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user and user[1] == hash_password(password):
            session_id = hashlib.sha256((username+password).encode()).hexdigest()
            SESSIONS[session_id] = user[0]
            self.send_response(302)
            self.send_header("Set-Cookie", f"session={session_id}")
            self.send_header("Location", "/dashboard")
            self.end_headers()
        else:
            self.respond("Invalid login")

    def handle_create(self, form):
        user_id = self.get_logged_in_user()
        if not user_id:
            self.redirect("/login")
            return
        title = form.get("title", [""])[0]
        content = form.get("content", [""])[0]
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO posts (user_id, title, content) VALUES (%s, %s, %s)", 
                    (user_id, title, content))
        conn.commit()
        cur.close()
        conn.close()
        self.redirect("/dashboard")

    
    def render(self, filename):
        try:
            with open("templates/"+filename, "r") as f:
                html = f.read()
            self.respond(html)
        except FileNotFoundError:
            self.send_error(404, "Template not found")

    def serve_static(self, path):
        try:
            with open(path, "rb") as f:
                content = f.read()
            self.send_response(200)
            if path.endswith(".css"):
                self.send_header("Content-Type", "text/css")
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404, "Static file not found")

    def respond(self, html):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def get_logged_in_user(self):
        cookie_header = self.headers.get("Cookie")
        if cookie_header:
            cookies = http.cookies.SimpleCookie(cookie_header)
            if "session" in cookies:
                sid = cookies["session"].value
                return SESSIONS.get(sid)
        return None


if __name__ == "__main__":
    print("Starting server at http://localhost:8080")
    HTTPServer(("localhost", 8080), BlogServer).serve_forever()
      

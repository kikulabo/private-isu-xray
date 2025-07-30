import datetime
import os
import pathlib
import re
import shlex
import subprocess
import tempfile

import flask
import MySQLdb.cursors
from flask_session import Session
from jinja2 import pass_eval_context
from markupsafe import Markup, escape
from pymemcache.client.base import Client as MemcacheClient

# AWS X-Ray imports
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.ext.flask.middleware import XRayMiddleware
from aws_xray_sdk.core import patch_all

UPLOAD_LIMIT = 10 * 1024 * 1024  # 10mb
POSTS_PER_PAGE = 20


_config = None


@xray_recorder.capture('config')
def config():
    global _config
    if _config is None:
        _config = {
            "db": {
                "host": os.environ.get("ISUCONP_DB_HOST", "localhost"),
                "port": int(os.environ.get("ISUCONP_DB_PORT", "3306")),
                "user": os.environ.get("ISUCONP_DB_USER", "root"),
                "db": os.environ.get("ISUCONP_DB_NAME", "isuconp"),
            },
            "memcache": {
                "address": os.environ.get(
                    "ISUCONP_MEMCACHED_ADDRESS", "127.0.0.1:11211"
                ),
            },
        }
        password = os.environ.get("ISUCONP_DB_PASSWORD")
        if password:
            _config["db"]["passwd"] = password
    return _config


_db = None


@xray_recorder.capture('db')
def db():
    global _db
    if _db is None:
        conf = config()["db"].copy()
        conf["charset"] = "utf8mb4"
        conf["cursorclass"] = MySQLdb.cursors.DictCursor
        conf["autocommit"] = True
        _db = MySQLdb.connect(**conf)
    return _db


@xray_recorder.capture('db_initialize')
def db_initialize():
    cur = db().cursor()
    sqls = [
        "DELETE FROM users WHERE id > 1000",
        "DELETE FROM posts WHERE id > 10000",
        "DELETE FROM comments WHERE id > 100000",
        "UPDATE users SET del_flg = 0",
        "UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
    ]
    for q in sqls:
        with xray_recorder.subsegment(f'SQL: {q[:30]}...'):
            cur.execute(q)


_mcclient = None


@xray_recorder.capture('memcache')
def memcache():
    global _mcclient
    if _mcclient is None:
        conf = config()["memcache"]
        _mcclient = MemcacheClient(
            conf["address"], no_delay=True, default_noreply=False
        )
    return _mcclient


@xray_recorder.capture('try_login')
def try_login(account_name, password):
    xray_recorder.current_subsegment().put_metadata('account_name', account_name)
    cur = db().cursor()
    cur.execute(
        "SELECT * FROM users WHERE account_name = %s AND del_flg = 0", (account_name,)
    )
    user = cur.fetchone()

    if user and calculate_passhash(user["account_name"], password) == user["passhash"]:
        return user
    return None


@xray_recorder.capture('validate_user')
def validate_user(account_name: str, password: str):
    if not re.match(r"[0-9a-zA-Z]{3,}", account_name):
        return False
    if not re.match(r"[0-9a-zA-Z_]{6,}", password):
        return False
    return True


@xray_recorder.capture('digest')
def digest(src: str):
    # opensslのバージョンによっては (stdin)= というのがつくので取る
    out = subprocess.check_output(
        f"printf %s {shlex.quote(src)} | openssl dgst -sha512 | sed 's/^.*= //'",
        shell=True,
        encoding="utf-8",
    )
    return out.strip()


@xray_recorder.capture('calculate_salt')
def calculate_salt(account_name: str):
    return digest(account_name)


@xray_recorder.capture('calculate_passhash')
def calculate_passhash(account_name: str, password: str):
    return digest("%s:%s" % (password, calculate_salt(account_name)))


@xray_recorder.capture('get_session_user')
def get_session_user():
    user = flask.session.get("user")
    if user:
        user_id = user["id"]
        # キャッシュは無効化して、常にDBから取得するように変更
        # （Memcachedの設定問題を回避）
        cur = db().cursor()
        cur.execute("SELECT * FROM `users` WHERE `id` = %s", (user_id,))
        db_user = cur.fetchone()
        
        return db_user
    return None


@xray_recorder.capture('make_posts')
def make_posts(results, all_comments=False):
    if not results:
        return []
    
    posts = []
    cursor = db().cursor()
    
    # 全ての投稿IDを取得
    post_ids = [post["id"] for post in results]
    user_ids = list(set(post["user_id"] for post in results))
    
    # 投稿のユーザー情報を一括取得
    format_strings = ','.join(['%s'] * len(user_ids))
    cursor.execute(
        f"SELECT * FROM `users` WHERE `id` IN ({format_strings})",
        user_ids
    )
    users_dict = {user["id"]: user for user in cursor.fetchall()}
    
    # コメント数を一括取得
    format_strings = ','.join(['%s'] * len(post_ids))
    cursor.execute(
        f"SELECT `post_id`, COUNT(*) AS `count` FROM `comments` WHERE `post_id` IN ({format_strings}) GROUP BY `post_id`",
        post_ids
    )
    comment_counts = {row["post_id"]: row["count"] for row in cursor.fetchall()}
    
    # コメントを一括取得
    if all_comments:
        cursor.execute(
            f"SELECT * FROM `comments` WHERE `post_id` IN ({format_strings}) ORDER BY `post_id`, `created_at` DESC",
            post_ids
        )
    else:
        # サブクエリを使って各投稿の最新3件のコメントを取得
        cursor.execute(
            f"""SELECT c.* FROM `comments` c
               INNER JOIN (
                 SELECT `post_id`, `id`, ROW_NUMBER() OVER (PARTITION BY `post_id` ORDER BY `created_at` DESC) as rn
                 FROM `comments`
                 WHERE `post_id` IN ({format_strings})
               ) ranked ON c.id = ranked.id
               WHERE ranked.rn <= 3
               ORDER BY c.`post_id`, c.`created_at` DESC""",
            post_ids
        )
    
    comments_by_post = {}
    comment_user_ids = set()
    for comment in cursor.fetchall():
        post_id = comment["post_id"]
        if post_id not in comments_by_post:
            comments_by_post[post_id] = []
        comments_by_post[post_id].append(comment)
        comment_user_ids.add(comment["user_id"])
    
    # コメントのユーザー情報を一括取得
    if comment_user_ids:
        format_strings = ','.join(['%s'] * len(comment_user_ids))
        cursor.execute(
            f"SELECT * FROM `users` WHERE `id` IN ({format_strings})",
            list(comment_user_ids)
        )
        comment_users_dict = {user["id"]: user for user in cursor.fetchall()}
    else:
        comment_users_dict = {}
    
    # 投稿データを組み立て
    for post in results:
        post_id = post["id"]
        user_id = post["user_id"]
        
        # ユーザー情報を追加
        post["user"] = users_dict.get(user_id)
        if not post["user"] or post["user"]["del_flg"]:
            continue
            
        # コメント数を追加
        post["comment_count"] = comment_counts.get(post_id, 0)
        
        # コメントを追加
        comments = comments_by_post.get(post_id, [])
        for comment in comments:
            comment["user"] = comment_users_dict.get(comment["user_id"])
        
        # コメントを古い順に並び替え（元のコードではreverse()していた）
        comments.reverse()
        post["comments"] = comments
        
        posts.append(post)
        
        if len(posts) >= POSTS_PER_PAGE:
            break
            
    return posts


# app setup
static_path = pathlib.Path(__file__).resolve().parent.parent / "public"
app = flask.Flask(__name__, static_folder=str(static_path), static_url_path="")
# app.debug = True

# X-Ray configuration
xray_recorder.configure(service='private-isu')
XRayMiddleware(app, xray_recorder)
# Patch all supported libraries for automatic tracing
patch_all()

# Flask-Session
app.config["SESSION_TYPE"] = "memcached"
app.config["SESSION_MEMCACHED"] = memcache()
Session(app)


@app.template_global()
def image_url(post):
    ext = ""
    mime = post["mime"]
    if mime == "image/jpeg":
        ext = ".jpg"
    elif mime == "image/png":
        ext = ".png"
    elif mime == "image/gif":
        ext = ".gif"

    return "/image/%s%s" % (post["id"], ext)


# http://flask.pocoo.org/snippets/28/
_paragraph_re = re.compile(r"(?:\r\n|\r|\n){2,}")


@app.template_filter()
@pass_eval_context
def nl2br(eval_ctx, value):
    result = "\n\n".join(
        "<p>%s</p>" % p.replace("\n", "<br>\n")
        for p in _paragraph_re.split(escape(value))
    )
    if eval_ctx.autoescape:
        result = Markup(result)
    return result


# endpoints


@app.route("/initialize")
@xray_recorder.capture('get_initialize')
def get_initialize():
    db_initialize()
    return ""


@app.route("/login")
@xray_recorder.capture('get_login')
def get_login():
    if get_session_user():
        return flask.redirect("/")
    return flask.render_template("login.html", me=None)


@app.route("/login", methods=["POST"])
@xray_recorder.capture('post_login')
def post_login():
    if get_session_user():
        return flask.redirect("/")

    user = try_login(flask.request.form["account_name"], flask.request.form["password"])
    if user:
        flask.session["user"] = {"id": user["id"]}
        flask.session["csrf_token"] = os.urandom(8).hex()
        return flask.redirect("/")

    flask.flash("アカウント名かパスワードが間違っています")
    return flask.redirect("/login")


@app.route("/register")
@xray_recorder.capture('get_register')
def get_register():
    if get_session_user():
        return flask.redirect("/")
    return flask.render_template("register.html", me=None)


@app.route("/register", methods=["POST"])
@xray_recorder.capture('post_register')
def post_register():
    if get_session_user():
        return flask.redirect("/")

    account_name = flask.request.form["account_name"]
    password = flask.request.form["password"]
    if not validate_user(account_name, password):
        flask.flash(
            "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
        )
        return flask.redirect("/register")

    cursor = db().cursor()
    cursor.execute("SELECT 1 FROM users WHERE `account_name` = %s", (account_name,))
    user = cursor.fetchone()
    if user:
        flask.flash("アカウント名がすでに使われています")
        return flask.redirect("/register")

    query = "INSERT INTO `users` (`account_name`, `passhash`) VALUES (%s, %s)"
    cursor.execute(query, (account_name, calculate_passhash(account_name, password)))

    flask.session["user"] = {"id": cursor.lastrowid}
    flask.session["csrf_token"] = os.urandom(8).hex()
    return flask.redirect("/")


@app.route("/logout")
@xray_recorder.capture('get_logout')
def get_logout():
    flask.session.clear()
    return flask.redirect("/")


@app.route("/")
@xray_recorder.capture('get_index')
def get_index():
    me = get_session_user()

    cursor = db().cursor()
    # LIMITを追加してパフォーマンスを向上（make_postsでPOSTS_PER_PAGEまで制限されるため、少し余裕を持たせる）
    cursor.execute(
        "SELECT `id`, `user_id`, `body`, `created_at`, `mime` FROM `posts` ORDER BY `created_at` DESC LIMIT %s",
        (POSTS_PER_PAGE * 2,)
    )
    posts = make_posts(cursor.fetchall())

    return flask.render_template("index.html", posts=posts, me=me)


@app.route("/@<account_name>")
@xray_recorder.capture('get_user_list')
def get_user_list(account_name):
    xray_recorder.current_subsegment().put_annotation('account_name', account_name)
    cursor = db().cursor()

    cursor.execute(
        "SELECT * FROM `users` WHERE `account_name` = %s AND `del_flg` = 0",
        (account_name,),
    )
    user = cursor.fetchone()
    if user is None:
        flask.abort(404)  # raises exception

    cursor.execute(
        "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = %s ORDER BY `created_at` DESC",
        (user["id"],),
    )
    posts = make_posts(cursor.fetchall())

    # 効率化：1つのクエリで複数の統計情報を取得
    cursor.execute("""
        SELECT 
            (SELECT COUNT(*) FROM `comments` WHERE `user_id` = %s) AS comment_count,
            (SELECT COUNT(*) FROM `posts` WHERE `user_id` = %s) AS post_count,
            (SELECT COUNT(*) FROM `comments` WHERE `post_id` IN (SELECT `id` FROM `posts` WHERE `user_id` = %s)) AS commented_count
    """, (user["id"], user["id"], user["id"]))
    
    stats = cursor.fetchone()
    comment_count = stats["comment_count"]
    post_count = stats["post_count"] 
    commented_count = stats["commented_count"]

    me = get_session_user()

    return flask.render_template(
        "user.html",
        posts=posts,
        user=user,
        post_count=post_count,
        comment_count=comment_count,
        commented_count=commented_count,
        me=me,
    )


@xray_recorder.capture('_parse_iso8601')
def _parse_iso8601(s):
    # http://bugs.python.org/issue15873
    # Ignore timezone
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})[ tT](\d{2}):(\d{2}):(\d{2}).*", s)
    if not m:
        raise ValueError("Invlaid iso8601 format: %r" % (s,))
    return datetime.datetime(*map(int, m.groups()))


@app.route("/posts")
@xray_recorder.capture('get_posts')
def get_posts():
    cursor = db().cursor()
    max_created_at = flask.request.args.get("max_created_at") or None
    if max_created_at:
        max_created_at = _parse_iso8601(max_created_at)
        cursor.execute(
            "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= %s ORDER BY `created_at` DESC",
            (max_created_at,),
        )
    else:
        cursor.execute(
            "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` ORDER BY `created_at` DESC"
        )
    results = cursor.fetchall()
    posts = make_posts(results)
    return flask.render_template("posts.html", posts=posts)


@app.route("/posts/<id>")
@xray_recorder.capture('get_posts_id')
def get_posts_id(id):
    xray_recorder.current_subsegment().put_annotation('post_id', id)
    cursor = db().cursor()

    cursor.execute("SELECT * FROM `posts` WHERE `id` = %s", (id,))
    posts = make_posts(cursor.fetchall(), all_comments=True)
    if not posts:
        flask.abort(404)

    me = get_session_user()
    return flask.render_template("post.html", post=posts[0], me=me)


@app.route("/", methods=["POST"])
@xray_recorder.capture('post_index')
def post_index():
    me = get_session_user()
    if not me:
        return flask.redirect("/login")

    if flask.request.form["csrf_token"] != flask.session["csrf_token"]:
        flask.abort(422)

    file = flask.request.files.get("file")
    if not file:
        flask.flash("画像が必要です")
        return flask.redirect("/")

    # 投稿のContent-Typeからファイルのタイプを決定する
    mime = file.mimetype
    if mime not in ("image/jpeg", "image/png", "image/gif"):
        flask.flash("投稿できる画像形式はjpgとpngとgifだけです")
        return flask.redirect("/")

    with tempfile.TemporaryFile() as tempf:
        file.save(tempf)
        tempf.flush()

        if tempf.tell() > UPLOAD_LIMIT:
            flask.flash("ファイルサイズが大きすぎます")
            return flask.redirect("/")

        tempf.seek(0)
        imgdata = tempf.read()

    query = "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (%s,%s,%s,%s)"
    cursor = db().cursor()
    cursor.execute(query, (me["id"], mime, imgdata, flask.request.form.get("body")))
    pid = cursor.lastrowid
    return flask.redirect("/posts/%d" % pid)


@app.route("/image/<id>.<ext>")
@xray_recorder.capture('get_image')
def get_image(id, ext):
    if not id:
        return ""
    id = int(id)
    if id == 0:
        return ""
    
    xray_recorder.current_subsegment().put_annotation('image_id', id)
    xray_recorder.current_subsegment().put_annotation('ext', ext)

    cursor = db().cursor()
    cursor.execute("SELECT * FROM `posts` WHERE `id` = %s", (id,))
    post = cursor.fetchone()

    mime = post["mime"]
    if (
        ext == "jpg"
        and mime == "image/jpeg"
        or ext == "png"
        and mime == "image/png"
        or ext == "gif"
        and mime == "image/gif"
    ):
        return flask.Response(post["imgdata"], mimetype=mime)

    flask.abort(404)


@app.route("/comment", methods=["POST"])
@xray_recorder.capture('post_comment')
def post_comment():
    me = get_session_user()
    if not me:
        return flask.redirect("/login")

    if flask.request.form["csrf_token"] != flask.session["csrf_token"]:
        flask.abort(422)

    post_id = flask.request.form["post_id"]
    if not re.match(r"[0-9]+", post_id):
        return "post_idは整数のみです"
    post_id = int(post_id)

    query = (
        "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (%s, %s, %s)"
    )
    cursor = db().cursor()
    cursor.execute(query, (post_id, me["id"], flask.request.form["comment"]))

    return flask.redirect("/posts/%d" % post_id)


@app.route("/admin/banned")
@xray_recorder.capture('get_banned')
def get_banned():
    me = get_session_user()
    if not me:
        return flask.redirect("/login")

    if me["authority"] == 0:
        flask.abort(403)

    cursor = db().cursor()
    cursor.execute(
        "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC"
    )
    users = cursor.fetchall()

    return flask.render_template("banned.html", users=users, me=me)


@app.route("/admin/banned", methods=["POST"])
@xray_recorder.capture('post_banned')
def post_banned():
    me = get_session_user()
    if not me:
        return flask.redirect("/login")

    if me["authority"] == 0:
        flask.abort(403)

    if flask.request.form["csrf_token"] != flask.session["csrf_token"]:
        flask.abort(422)

    cursor = db().cursor()
    query = "UPDATE `users` SET `del_flg` = %s WHERE `id` = %s"
    for id in flask.request.form.getlist("uid", type=int):
        cursor.execute(query, (1, id))

    return flask.redirect("/admin/banned")

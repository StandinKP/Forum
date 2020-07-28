from flask import (
    Flask,
    render_template,
    redirect,
    json,
    url_for,
    flash,
    request,
    session,
    logging,
    jsonify,
)
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from pymongo.errors import DuplicateKeyError
from PIL import Image
import os
import secrets
from functools import wraps
from flask_cors import CORS
from random import randint
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature


app = Flask(__name__)


app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["MONGO_URI"] = "mongodb://localhost:27017/forum"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)


app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER")
print(os.getenv("MAIL_DEFAULT_SENDER"))

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
CORS(app)


s = URLSafeTimedSerializer(os.getenv("SECRET_KEY"))


# Check if user logged in
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Unauthorized, Please login", "danger")
            return redirect(url_for("login"))

    return wrap


# Routes
@app.route("/")
def index():
    posts = mongo.db.posts.find()
    all_posts = []
    for post in posts:
        all_posts.append(
            {
                "post_id": post["post_id"],
                "title": post["title"],
                "content": post["content"],
                "created_at": post["created_at"],
                "author": mongo.db.users.find_one({"username": post["author"]}),
                "likes": post["likes"],
            }
        )
    return render_template("index.html", posts=all_posts)


@app.route("/register/", methods=["GET", "POST"])
def register():
    if "logged_in" in session:
        return redirect(url_for("index"))

    default_pic = url_for("static", filename="img/default.jpg")
    if request.method == "POST":
        user = mongo.db.users.find_one({"username": request.form["username"]})
        user1 = mongo.db.users.find_one({"email": request.form["email"]})
        if user:
            flash("Username already taken", "danger")
            return redirect(url_for("register"))

        elif user1:
            flash("Email already taken", "danger")
            return redirect(url_for("register"))

        elif request.form["password"] == request.form["confirm_password"]:
            hashed_password = bcrypt.generate_password_hash(
                request.form["password"]
            ).decode("utf-8")

            try:
                mongo.db.users.insert_one(
                    {
                        "fname": request.form["fname"],
                        "lname": request.form["lname"],
                        "username": request.form["username"],
                        "email": request.form["email"],
                        "password": hashed_password,
                        "profile_pic": default_pic,
                        "badges": [],
                        "points": 0,
                        "verified": False,
                    }
                )

                email = request.form["email"]
                token = s.dumps(email, salt="email-confirm")

                msg = Message("Confirm email", recipients=[email])
                link = url_for("verify_email", token=token, _external=True)
                msg.html = (
                    """<h1>Confirm your email!</h1>
                           <a href=" """
                    + link
                    + """ "><button class="btn btn-primary">Verify Email</button></a>"""
                )
                mail.send(msg)
                flash(
                    "Your account has been created! Please verify your email to login!",
                    "success",
                )

                return redirect(url_for("login"))

            except DuplicateKeyError:
                flash("User already exists!", "success")
        elif request.form["password"] != request.form["confirm_password"]:
            flash(
                "Please enter same password in confirm password and password fields!",
                "danger",
            )

    return render_template("register.html", title="Register")


@app.route("/login/", methods=["GET", "POST"])
def login():
    if "logged_in" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        user = mongo.db.users.find_one({"username": request.form["username"]})

        if user and bcrypt.check_password_hash(
            user["password"], request.form["password"]
        ):
            if user["verified"] == True:
                session["logged_in"] = True
                session["username"] = request.form["username"]
                a = mongo.db.users.find_one({"username": session["username"]})
                session["profile_pic"] = a["profile_pic"]
                session["permanent"] = True
                next_page = request.args.get("next")

                return redirect(next_page) if next_page else redirect(url_for("index"))

            elif user["verified"] == False:
                flash("Please verify email first before login.", "danger")
                return redirect(url_for("login"))

        else:
            flash("Login Unsuccessful. Please check username and password", "danger")

    return render_template("login.html", title="Login")


@app.route("/logout/")
@login_required
def logout():
    session.clear()
    return redirect(url_for("index"))


def save_picture(form_picture):
    random_hex = secrets.token_hex(12)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, "static/img", picture_fn)
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return url_for("static", filename="img/" + picture_fn)


@app.route("/account/<username>/", methods=["GET", "POST"])
def account(username):
    if "logged_in" in session:
        old_user = mongo.db.users.find_one({"username": session["username"]})

        if request.method == "POST" and username == session["username"]:
            picture = request.files["picture"]
            email = request.form["email"]
            fname = request.form["fname"]
            lname = request.form["lname"]

            if picture:
                profile_pic = save_picture(picture)

            else:
                profile_pic = session["profile_pic"]

            mongo.db.users.update_one(
                {"username": session["username"]},
                {
                    "$set": {
                        "fname": fname,
                        "lname": lname,
                        "profile_pic": profile_pic,
                        "email": email,
                    }
                },
            )

            new_user = mongo.db.users.find_one({"username": username})

            session["username"] = new_user["username"]
            session["email"] = new_user["email"]
            session["profile_pic"] = new_user["profile_pic"]
            flash("Account updated!", "success")

            return redirect(url_for("account", username=session["username"]))

        elif request.method == "GET":
            user = mongo.db.users.find_one({"username": username})
            session["username"] = user["username"]
            session["email"] = user["email"]
            session["profile_pic"] = user["profile_pic"]

        new_user = mongo.db.users.find_one({"username": session["username"]})
        profile_pic = new_user["profile_pic"]

        return render_template(
            "account.html", title="Account", profile_pic=profile_pic, user=user
        )
    user = mongo.db.users.find_one({"username": username})
    return render_template("account.html", user=user)


@app.route("/post/new", methods=["GET", "POST"])
@login_required
def new_post():
    if request.method == "POST":

        if request.form["title"] == "" or request.form["content"] == "":
            flash("Enter at least one character in Title and Content!", "danger")

            return redirect(url_for("new_post"))

        mongo.db.posts.insert_one(
            {
                "post_id": str(randint(11, 99))
                + session["username"][:2]
                + str(randint(11, 99)),
                "title": request.form["title"],
                "content": request.form["content"],
                "author": session["username"],
                "created_at": datetime.utcnow().strftime("%D %B, %Y"),
                "likes": [],
                "comments": [],
            }
        )

        user = mongo.db.users.find_one({"username": session["username"]})
        mongo.db.users.update_one(
            {"username": session["username"]}, {"$set": {"points": user["points"] + 10}}
        )
        flash("Post created!", "success")

        return redirect(url_for("index"))

    return render_template("create_post.html", title="New Post")


@app.route("/post/<post_id>/", methods=["GET", "POST"])
def post(post_id):
    post = mongo.db.posts.find_one({"post_id": post_id})
    user = mongo.db.users.find_one({"username": post["author"]})
    profile_pic = user["profile_pic"]

    return render_template("post.html", post=post, user=user, profile_pic=profile_pic)


@app.route("/post/<post_id>/delete")
def delete_post(post_id):
    mongo.db.posts.delete_one({"post_id": post_id})

    return redirect(url_for("index"))


@app.route("/like_post/<id>/<username>", methods=["POST"])
def like_post(id, username):
    old_post = mongo.db.posts.find_one({"post_id": id})
    done = mongo.db.posts.update_one(
        {"post_id": id}, {"$addToSet": {"likes": username}}
    )

    new_post = mongo.db.posts.find_one({"post_id": id})
    new_like = ""

    if len(old_post["likes"]) != len(new_post["likes"]):
        new_like = "true"

    else:
        new_like = "false"

    user = mongo.db.users.find_one({"username": new_post["author"]})
    mongo.db.users.update_one(
        {"username": username}, {"$set": {"points": user["points"] + 10}}
    )

    return jsonify(
        {
            "post_id": id,
            "total_likes": len(new_post["likes"]),
            "username": username,
            "new_like": new_like,
        }
    )


@app.route("/post_comment/", methods=["POST"])
def post_comment():
    data = json.loads(request.data)
    done = mongo.db.posts.update_one(
        {"post_id": data["post_id"]},
        {
            "$push": {
                "comments": {
                    "username": data["username"],
                    "comment": data["comment"],
                    "posted_on": datetime.utcnow().strftime("%D %B, %Y"),
                }
            }
        },
    )

    post = mongo.db.posts.find_one({"post_id": data["post_id"]})
    comments = post["comments"]
    print(comments)
    user = mongo.db.users.find_one({"username": post["author"]})
    mongo.db.users.update_one(
        {"username": user["username"]}, {"$set": {"points": user["points"] + 10}}
    )

    return jsonify(
        {
            "post_id": data["post_id"],
            "username": data["username"],
            "comment": data["comment"],
            "posted_on": datetime.utcnow().strftime("%D %B, %Y"),
        }
    )


@app.route("/verify_send_email", methods=["GET", "POST"])
def verify_send_email():
    if request.method == "POST":
        email = request.form["email"]
        token = s.dumps(email, salt="email-confirm")

        msg = Message("Confirm email", recipients=[email])
        link = url_for("verify_email", token=token, _external=True)
        msg.html = (
            """<h1>Confirm your email!</h1>
                    <a href=" """
            + link
            + """ "><button class="btn btn-primary">Verify Email<button></a>"""
        )
        mail.send(msg)
        flash("Verification has been sent. Please check your email", "success")
        return redirect(url_for("login"))
    return redirect(url_for("verify"))


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        user = mongo.db.users.find_one({"email": request.form["email"]})
        if user["verified"] == True:
            flash("Your account has already been verified. You can login", "warning")
            return redirect(url_for("login"))

        else:
            email = request.form["email"]
            token = s.dumps(email, salt="email-confirm")
            msg = Message("Confirm email", recipients=[email])
            link = url_for("verify_email", token=token, _external=True)
            msg.html = (
                """<h1>Confirm your email!</h1>
                        <a href=" """
                + link
                + """ "><button class="btn btn-primary">Verify Email</button></a>"""
            )
            mail.send(msg)
            flash("Verification has been sent. Please check your email,", "info")
            return redirect(url_for("login"))

    return render_template("verify.html")


@app.route("/verify_email/<token>", methods=["GET", "POST"])
def verify_email(token):
    try:
        email = s.loads(token, salt="email-confirm", max_age=900)
        mongo.db.users.update_one({"email": email}, {"$set": {"verified": True}})
        flash("Your email has been verified. You can login now!", "success")
        return redirect(url_for("login"))

    except SignatureExpired or BadTimeSignature:
        flash("Your email couldn't be verified. Please try again!", "danger")
        return redirect(url_for("index"))


@app.route("/forgot_password/", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        token = s.dumps(email, salt="change-password")

        msg = Message("Change password", recipients=[email])
        link = url_for("change_password", token=token, _external=True)
        msg.html = (
            """<h1>Change your password!</h1>
                   <a href=" """
            + link
            + """ "><button class="btn btn-primary">Change password</button></a>"""
        )
        mail.send(msg)
        flash(
            "Link to change password has been sent to your email. Please check your email",
            "info",
        )
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/change_password/<token>", methods=["GET", "POST"])
def change_password(token):
    if request.method == "POST":
        try:
            email = s.loads(token, salt="change-password", max_age=900)
            if request.form["password"] == request.form["confirm_password"]:
                hash_password = bcrypt.generate_password_hash(
                    request.form["password"]
                ).decode("utf-8")
                mongo.db.users.update_one(
                    {"email": email}, {"$set": {"password": hash_password}}
                )
                flash("Your password has been changed. You can login now!", "success")
                return redirect(url_for("login"))
            else:
                flash("Wrong password entered in both fields!", "danger")

        except SignatureExpired or BadTimeSignature:
            flash("Your password couldn't be changed. Please try again!", "danger")
            return redirect(url_for("change_password", token=token))

    return render_template("change_password.html")


# End Routes


if __name__ == "__main__":
    app.run(debug=True)

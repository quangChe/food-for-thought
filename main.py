import os
import re
import random
import time
import hashlib
import hmac
import string
import webapp2
import jinja2
from google.appengine.ext import db


"""This is a multi-user blog that utilizes Google Cloud App Engine servers,
Google Datastore database, jinja2 for templating and webapp2 for routing and
exception handling.
"""

# Jinja2 environment configuration
template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

def render_str( template, **params):
    """Convenience function for retrieving templates and passing parameters
    to them"""
    temp = jinja_env.get_template(template)
    return temp.render(params)

# =====================
# 1. SECURITY FUNCTIONS
# =====================

#Secret (sha256 hexadecimal for 'Quang Che'):
secret = "3002a6ac0f3c621d4eacac34921c68a74411f7da2811303be6a1163f5b5aebaa"

def make_secure_val(val):
    """Takes a value, produces an hmac hexadecimal and returns string:
    'value|hmac_hexadecimal'"""
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(val):
    """Takes in the string returned by make_secure_val() and checks to see if
    value has been tampered with"""
    val_check = val.split('|')[0]
    if val == make_secure_val(val_check):
        return val_check

# B. Salt and Hash (for passwords):
def make_salt():
    """Produces a randomly-generated, 5-digit string of letters"""
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    """Combines username, password and a salt hash password and returns
    string: 'salt|pw_hash_hexadecimal'
    """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)

def check_pw(name, pw, h):
    """Verifies password hash by running it through make_pw_hash() and
    returning a boolean"""
    salt = h.split('|')[0]
    return h == make_pw_hash(name, pw, salt)


# ====================================
# BASE HANDLER & CONVENIENCE FUNCTIONS
# ====================================
class BaseHandler(webapp2.RequestHandler):
    """This class contains the basic handlers and functions that
    the other route handlers inherit from.
    """

    # A. Basic route handlers

    def write(self, *a, **kw):
        """Convenience function for writing HTML responses"""
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """Defines a global user object that gives all templates access
        to the current user object matching the logged-in user"""
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        """Convenience function for rendering pages with specific parameters
        """
        self.write(self.render_str(template, **kw))

    # B. Cookies setting and reading:

    def set_cookie(self, name, val):
        """Hashes (with hmac) a value and sets a cookie with
        new secured value"""
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'
                                        % (name, cookie_val))

    def read_cookie(self, name):
        """Returns the cookie value if there is one and it passes
        check_secure_val()"""
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # C. Login and logout handlers:

    def login_cookie_set(self, user):
        """Logs a user in by setting a secured cookie for them with
        set_cookie()"""
        self.set_cookie('user_id', str(user.key().id()))

    def logout_cookie_dlt(self):
        """Clears the user's cookie, ending the session"""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """Checks cookie to pull the user object from database and
        log the that user as the current session user"""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and Users.by_id(int(uid))

    #D. Validations:

    def post_exists(self, post_id):
        key = db.Key.from_path('Posts', int(post_id))
        post = db.get(key)
        if post != None:
            return True
        else:
            return False

    def user_owns_post(self, post):
        return self.user.username == post.poster

    def comment_exists(self, comment_id):
        key = db.Key.from_path('Comments', int(comment_id))
        comment = db.get(key)
        if comment != None:
            return True
        else:
            return False

    def user_owns_comment(self, comment):
        return self.user.username == comment.poster

# ===============
# DATABASE MODELS
# ===============
class Users(db.Model):
    """This is the database model for our app's users.

    Attributes:
        1. Users.by_id(id): references user by the id.
        2. Users.by_name(username): references user by the username.
        3. Users.register(username, password, email): creates a user object
            that is compatible with Users model and can be stored.
        4. Users.login(username, pw): checks database to return the user object
            if provided username and password are correct.
    """

    username = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    date = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        user_found = cls.all().filter('username =', name).get()
        return user_found

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return cls(username = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and check_pw(name, pw, u.pw_hash):
            return u

class Posts(db.Model):
    """This is the database model for our app's posts.

    Attributes:
        1. Posts.get_all(): retrieves all posts sorted by date descending.
        2. Posts.get_by_poster(name): retrieves all posts posted by username
            sorted by date posted in descending order
    """
    body = db.TextProperty(required = True) #The post's content
    poster = db.StringProperty(required = True) #The post's original submitter
    date = db.DateTimeProperty(auto_now_add = True)
    digests = db.IntegerProperty(default = 0) #The post's upvote count

    @classmethod
    def get_all(cls):
        return cls.all().order('-date')

    @classmethod
    def get_by_poster(cls, name):
        return cls.all().filter('poster =', name).order('-date')

class PostVoters(db.Model):
    """This is the model for post voters.

    This model references the Posts model in order to log the usernames of
    users who upvote the post. This allows the app to prevent users from
    upvoting their own posts or upvoting a post twice.
    """
    post = db.ReferenceProperty(Posts, collection_name='voters')

    username = db.StringProperty() #Name of each of the post's upvoter

class Comments(db.Model):
    """This is the comments model.

    This model which references the Posts model in order to provide an array
    of comments with specific properties for each post. This allows the app to
    query and display comments that are specific to the referenced post.
    """
    post = db.ReferenceProperty(Posts, collection_name='comments')

    body = db.TextProperty(required = True) #The comment's content
    poster = db.StringProperty(required = True) #Name of commenter
    date = db.DateTimeProperty(auto_now_add = True)


# ==========
# FRONT PAGE
# ==========
class HomePage(BaseHandler):
    """This is the handler for the front page of the app. It lists all the
    posts sorted from most recent to oldest"""
    def get(self):
        posts = Posts.get_all()
        has_posts = (posts.count()>0)

        self.render('home.html', posts = posts, has_posts = has_posts)

# ===========
# SIGNUP PAGE
# ===========
class SignupPage(BaseHandler):
    """This is the handler for the signup page that validates the user inputs
    before adding a user to the database.

    The conditions make sure that the user is notified of the specific errors
    that need to be fixed before proceeding. Successful signup will add
    a new user object to the database and set a secure cookie of the
    user's session.
    """

    # Validation for user signup info:
    USER_RE = re.compile("^[a-zA-Z0-9_-]{3,20}$")
    def valid_user(username):
        """Validates username inputs"""
        return username and USER_RE.match(username)

    PW_RE = re.compile("^.{3,20}$")
    def valid_pw(password):
        """Validates password inputs"""
        return password and PW_RE.match(password)

    EMAIL_RE = re.compile("^[\S]+@[\S]+.[\S]+$")
    def valid_email(email):
        """Validates email inputs"""
        if email:
            return EMAIL_RE.match(email)
        if not email:
            return True


    #Request handing for the route:
    def get(self):
        if not self.user:
            self.render('signup.html')
        else:
            self.error(404)

    def post(self):
        if not self.user:
            username = self.request.get('username')
            password = self.request.get('password')
            verify = self.request.get('verify')
            email = self.request.get('email')

            params = dict(username = username,
                            email = email)

            have_error = False

            #Validate user signup info:
            if not valid_user(username):
                params['username_error'] = 'Please enter a valid username.'
                have_error = True
            if not valid_pw(password):
                params['pw_error'] = 'Please enter a valid password.'
                have_error = True
            elif password != verify:
                params['pw_ver_error'] = ('Please make sure your passwords '
                                            'match.')
                have_error = True
            if not valid_email(email):
                params['email_error'] = 'Please enter a valid email.'
                have_error = True

            if have_error:
                self.render('signup.html', **params)
            else:
                name_exists = Users.by_name(str(username))
                if name_exists:
                    error = "Username already exists."
                    self.render("signup.html", username = username,
                                                username_error = error)
                else:
                    new_user = Users.register(username, password, email)
                    new_user.put()

                    self.login_cookie_set(new_user)
                    self.redirect('/welcome')
        else:
            self.error(404)

# ==========
# LOGIN PAGE
# ==========
class LoginPage(BaseHandler):
    """This is the handler for the login page.

    The provided username and password are compared to those in the database
    so that if they match an existing user object, a secure cookie is set for
    that user

    This page provides specific notifications if users were redirected here
    due invalid actions.
    """
    def get(self):
        if not self.user:
            error = self.request.get('error')
            if error:
                if error == '1':
                    redirect_msg = "You must be logged in to do that!"
                elif error == '2':
                    redirect_msg = ("Invalid login. Please check your "
                                    "username and password.")

                self.render("login.html", redirect_msg = redirect_msg)

            else:
                self.render("login.html")

        else:
            self.error(404)

    def post(self):
        if not self.user:
            username = self.request.get('username')
            password = self.request.get('password')

            logger = Users.login(username, password)

            if logger:
                self.login_cookie_set(logger)
                self.redirect('/welcome')
            else:
                self.redirect('/login?error=2')

        else:
            self.error(404)

# ============
# WELCOME PAGE
# ============
class WelcomePage(BaseHandler):
    """This is the handler for the welcome page that the user is redirected to
    upon successful signup/login. This page is also the user's profile page
    and displays user's name and a list of their posts.
    """
    def get(self):
        if self.user:
            user = self.user.username
            posts = Posts.get_by_poster(user)
            dlt_notice = self.request.get('notice')
            has_posts = False

            if posts != None:
                for post in posts:
                    if post:
                        has_posts = True

                params = dict(posts = posts,
                                has_posts = has_posts)

                if dlt_notice:
                    params['redirect_msg'] = "A post has been deleted!"

                self.render('welcome.html', **params)

        else:
            self.redirect('/login?error=1')

# ===========
# LOGOUT PAGE
# ===========
class LogoutPage(BaseHandler):
    """This is the handler for the logout page which deletes the secure cookie
    containing the session's user info"""
    def get(self):
        if self.user:
            self.logout_cookie_dlt()
            self.redirect('/login')
        else:
            self.error(404)

# =============
# NEW POST PAGE
# =============
class NewPostPage(BaseHandler):
    """This is the handler for the new post page that can only be accessed
    if user is logged in and creats a new post that is submitted to the db.
    """
    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/login?error=1')

    def post(self):
        if self.user:
            body = self.request.get('body')

            params = dict(body = body)

            if body:
                poster = self.user.username
                new_post = Posts(body = body, poster = poster)
                new_post.put()
                post_id = new_post.key().id()
                time.sleep(.1)
                self.redirect("/%s" % post_id)

            else:
                params['error'] = "Your post contains invalid content!"
                self.render("newpost.html", **params)
        else:
            self.redirect('/login?error=1')

# ==============
# VIEW POST PAGE
# ==============
class ViewPostPage(BaseHandler):
    """This is the handler that pulls a specific post that a user has
    selected to view by the post's id. The post is then displayed on a page
    along with all its comments. Only logged-in users may access this form.
    """
    def get(self, post_id):
        if self.user:
            if self.post_exists(post_id):
                post = Posts.get_by_id(int(post_id))
                error = self.request.get('error')
                notice = self.request.get('notice')
                if post.comments:
                    comments = post.comments
                    has_comment = (comments.count()>0)

                params = dict(post = post,
                                comments = comments,
                                has_comment = has_comment)
                if error:
                    if error == "1":
                        params['redirect_msg'] = ("You've cannot vote more"
                                                    " than once!")
                    elif error == "2":
                        params['redirect_msg'] = ("You cannot upvote your own"
                                                    " thought!")
                elif notice:
                    params['redirect_msg'] = "Your comment has been deleted."

                self.render('viewpost.html', **params)
            else:
                self.error(404)
        else:
            self.redirect('/login?error=1')

# ==============
# EDIT POST PAGE
# ==============
class EditPostPage(BaseHandler):
    """Handler for the edit post page that queries a specific post by id
    and updates that post with new content provided by the user. This page can
    only be accessed by the user if the user's name matches the name of the
    post's original poster. User is redirected to the post's display page with
    the updated content shown.
    """
    def get(self, post_id):
        if self.user:
            if self.post_exists(post_id):
                post = Posts.get_by_id(int(post_id))

                if self.user_owns_post(post):
                    self.render('edit.html', post = post)
                else:
                    self.error(404)
            else:
                self.error(404)
        else:
            self.redirect('/login?error=1')

    def post(self, post_id):
        if self.user:
            if self.post_exists(post_id):
                post = Posts.get_by_id(int(post_id))
                new_body = self.request.get('body')

                if new_body:
                    if self.user_owns_post(post):
                        post.body = new_body
                        post.put()
                        time.sleep(.1)
                        self.redirect("/%s" % post_id)
                    else:
                        self.error(404)
                else:
                    error = "Your post contains invalid content."
                    self.render('edit.html', error = error)
            else:
                self.error(404)
        else:
            self.redirect('/login?error=1')

# ================
# DELETE POST PAGE
# ================
class DltPostPage(BaseHandler):
    """Handler for the delete page that queries a specific post by id and
    deletes that post from the database. This page can only be accessed by the
    user if the user's name matches the name of the post's original poster.
    The user is redirected to the welcome page upon successful deletion with
    a notice confirming the delete.
    """
    def get(self, post_id):
        if self.user:
            if self.post_exists(post_id):
                post = Posts.get_by_id(int(post_id))

                if self.user_owns_post(post):
                        post.delete()
                        time.sleep(.1)
                        self.redirect('/welcome?notice=dlt')
                else:
                    self.error(404)
            else:
                self.error(404)
        else:
            self.redirect('/login?error=1')

# ================
# DIGEST POST PAGE
# ================
class DigestPage(BaseHandler):
    """This is the handler for the URI which increments a post's digests. No
    template is rendered for this URI--rather, it redirects to a post's
    display page under three conditions (with notifications).

    1. The vote was successful and digest count increments by 1.
    2. The vote was unsucessful because user already voted and logged.
    3. The vote was unsucessful because the user is voting on her own post.
    """
    def get(self, post_id):
        if self.user:
            user = self.user.username

            if self.post_exists(post_id):
                post = Posts.get_by_id(int(post_id))
                voters = post.voters
                for voter in voters:
                    if voter.username == user:
                        self.redirect('/%s?error=1' % post_id)
                        return

                if self.user_owns_post(post):
                    self.redirect('/%s?error=2' % post_id)

                else:
                    post.digests += 1
                    new_voter = PostVoters(post = post,
                                            username = user)
                    new_voter.put()
                    post.put()
                    time.sleep(.1)
                    self.redirect('/%s' % post_id)
            else:
                self.error(404)
        else:
            self.redirect('/login?error=1')


# ================
# ADD COMMENT PAGE
# ================
class AddCommentPage(BaseHandler):
    """This handler renders the form for comments which can only be accessed
    if the user is logged in. The comments are posted under a specific post
    and exists only for that post.
    """
    def get(self, post_id):
        if self.user:
            if self.post_exists(post_id):
                post = Posts.get_by_id(int(post_id))
                error = self.request.get('error')
                params = dict(post = post)

                if error:
                    params['redirect_msg'] = ("Your comment contains invalid "
                                                "content!")

                self.render('comment.html', **params)
            else:
                self.error(404)
        else:
            self.redirect('/login?error=1')

    def post(self, post_id):
        if self.user:
            poster = self.user.username

            if self.post_exists(post_id):
                post = Posts.get_by_id(int(post_id))
                body = self.request.get('body')

                if body:
                    new_comment = Comments(post = post,
                                        body = body,
                                        poster = poster)
                    new_comment.put()
                    time.sleep(.1)
                    self.redirect('/%s' % post_id)
                else:
                    self.redirect('/%s/addcomment?error=cont' % post_id)
            else:
                self.error(404)
        else:
            self.redirect('/login?error=1')

# =================
# EDIT COMMENT PAGE
# =================
class EditCommentPage(BaseHandler):
    """This handler references a post and targeted comment to be edited. The
    form will contain the current content of the comment and upon posting,
    will update that comment with any changes. User will be redirected to the
    display page for the post which the comment references.
    """
    def get(self, post_id, comment_id):
        if self.user:
            if self.post_exists(post_id) and self.comment_exists(comment_id):
                post = Posts.get_by_id(int(post_id))
                comment = Comments.get_by_id(int(comment_id))
                error = self.request.get('error')

                params = dict(post = post, comment = comment)

                if self.user_owns_comment(comment):
                    if error:
                        params['redirect_msg'] = ("Comment contains invalid "
                                                    "content!")

                    self.render('comment_edit.html', **params)
                else:
                    self.error(404)
            else:
                self.error(404)
        else:
            self.redirect('/login?error=1')

    def post(self, post_id, comment_id):
        if self.user:
            if self.post_exists(post_id) and self.comment_exists(comment_id):
                new_body = self.request.get('body')
                post = Posts.get_by_id(int(post_id))
                comment = Comments.get_by_id(int(comment_id))

                if new_body:
                    if self.user_owns_comment(comment):
                        comment.body = new_body
                        comment.put()
                        time.sleep(.1)
                        self.redirect('/%s' % post_id)
                    else:
                        self.error(404)
                else:
                    self.redirect('/%s/%s/edit?error=!' % (post_id, comment_id))
        else:
            self.redirect('/login?error=1')

# ===================
# DELETE COMMENT PAGE
# ===================
class DltCommentPage(BaseHandler):
    """This handler links to the delete page which queries a comment
    by its id and deletes that comment. The user is then redirected to the
    display page of that comment's post with a delete notice.
    """
    def get(self, post_id, comment_id):
        if self.user:
            if self.post_exists(post_id) and self.comment_exists(comment_id):
                post = Posts.get_by_id(int(post_id))
                comment = Comments.get_by_id(int(comment_id))

                if self.user_owns_comment(comment):
                    comment.delete()
                    time.sleep(.1)
                    self.redirect('/%s?notice=dlt' % post_id)
                else:
                    self.error(404)
            else:
                self.error(404)
        else:
            self.redirect('/login?error=1')

# ==============
# HANDLER ROUTES
# ==============
app = webapp2.WSGIApplication([('/', HomePage),
                                ('/signup', SignupPage),
                                ('/login', LoginPage),
                                ('/welcome', WelcomePage),
                                ('/logout', LogoutPage),
                                ('/newpost', NewPostPage),
                                ('/(\d+)/edit', EditPostPage),
                                ('/(\d+)/delete', DltPostPage),
                                ('/(\d+)/digest', DigestPage),
                                ('/(\d+)/addcomment', AddCommentPage),
                                ('/(\d+)/(\d+)/edit', EditCommentPage),
                                ('/(\d+)/(\d+)/delete', DltCommentPage),
                                ('/(\d+)', ViewPostPage)], debug=True)

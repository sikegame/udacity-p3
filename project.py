"""
This is a simple web-based catalog app
with JSON/XML/RSS API endpoints.

This app has integrated with CSRF protection and
the oAuth2 social media user authentication system.

Author: Shinsuke JJ Ikegame
Date: 2015-10-12
"""

# Default libraries
import os
import random
import string
import json
import requests
import httplib2
from functools import wraps

# Flask-related libraries
from flask import Flask, render_template, request, redirect, \
    jsonify, url_for, flash, abort, \
    session as login_session, make_response, Response

# SQL Alchemy libraries
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Product
from sqlalchemy.engine.url import URL
import settings

# Google oAuth library
from oauth2client.client \
    import flow_from_clientsecrets, FlowExchangeError

# File name validity check library
from werkzeug import secure_filename

# XML generator library
from dict2xml import dict2xml as xmlify

# CSRF protection library
from flask.ext.seasurf import SeaSurf


app = Flask(__name__)
# Activate CSRF protection
csrf = SeaSurf(app)

# Configure file uploads
UPLOAD_FOLDER = 'static/images/'
ALLOWED_EXTENSIONS = set(['jpg', 'jpeg', 'png', 'gif'])
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Configure SQL Alchemy session
engine = create_engine(URL(**settings.DATABASE))
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(f):
    """
    User credential check decorator
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in login_session:
            return redirect(url_for('show_login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def show_homepage():
    """
    Show homepage with the most recent five products

    :return: Homepage in HTML
    """
    products = session.query(Product).join(Category)\
        .order_by(desc(Product.id)).limit(5).all()
    return render_template('home.html',
                           products=products,
                           session=login_session)


@app.route('/category/<int:c_id>/product/<int:p_id>')
def show_product(c_id, p_id):
    """
    Return a single product page

    :param c_id: Category ID
    :param p_id: Product ID
    :return: Single product page in HTML
    """
    product = session.query(Product).filter_by(id=p_id).one()

    # Check if a user has logged in
    if 'user_id' in login_session:
        user_id = login_session['user_id']
    else:
        user_id = None

    return render_template('product.html',
                           product=product,
                           user_id=user_id)


@app.route('/category/<int:c_id>')
def show_product_list(c_id):
    """
    Return a list of products specified by category ID

    :param c_id: Category ID
    :return: A list of products page in HTML
    """
    category = session.query(Category).filter_by(id=c_id).one()
    products = session.query(Product).filter_by(cat_id=c_id).all()

    # Pluralize the title by the number of items
    p_len = len(products)
    if p_len > 1:
        title_item = '%s products' % p_len
    else:
        title_item = '%s product' % p_len

    return render_template('category.html',
                           category=category,
                           title_item=title_item,
                           products=products)


@app.route('/my-categories')
@login_required
def show_my_categories():
    """
    Return a list of categories the user owns

    :return: A list of categories the user owns in HTML
    """
    categories = session.query(Category)\
        .filter_by(owner_id=login_session['user_id']).all()
    return render_template('category-list.html',
                           categories=categories)


@app.route('/add/category', methods=['GET', 'POST'])
@login_required
def add_category():
    """
    Add a new category to a database

    :return: Page to add new category in HTML
    """
    # Add new category
    if request.method == 'POST':
        name = request.form['category_name']
        new_category = Category(name=name,
                                owner_id=login_session['user_id'])
        session.add(new_category)
        session.commit()
        flash('%s has been successfully added.' % name)
        return redirect(url_for('show_my_categories'))

    return render_template('add-category.html')


@app.route('/edit/category/<int:c_id>', methods=['GET', 'POST'])
@login_required
def edit_category(c_id):
    """
    Edit an existing category specified by param

    :param c_id: Category ID
    :return: Page to edit an existing category in HTML
    """
    # Update the database
    category = session.query(Category).filter_by(id=c_id).one()
    if request.method == 'POST':
        # Check if user owns the category
        if category.owner_id == login_session['user_id']:
            name = request.form['name']
            if name:
                category.name = name
                session.add(category)
                session.commit()
                flash('%s has been successfully updated.' % name)
            else:
                flash('No changes were made.')
        else:
            # Prompt forbidden error message
            abort(403)

    return render_template('edit-category.html',
                           category=category)


@app.route('/delete/category/<int:c_id>', methods=['GET', 'POST'])
@login_required
def delete_category(c_id):
    """
    Delete an existing category specified by param

    :param c_id: Category ID
    :return: Page to delete an existing category in HTML
    """
    category = session.query(Category).filter_by(id=c_id).one()

    if request.method == 'POST':
        # Check if user owns the category
        if category.owner_id == login_session['user_id']:
            name = category.name
            session.delete(category)
            session.commit()
            flash('%s has been successfully deleted.' % name)
            return redirect(url_for('show_my_categories'))
        else:
            # Prompt forbidden error message
            abort(403)

    return render_template('delete-category.html',
                           category=category)


def allowed_file(filename):
    """
    Check for user uploaded file name validity

    :param filename: Filename
    :return: True if the filename is valid
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/add/product', methods=['GET', 'POST'])
@login_required
def add_product():
    """
    Add a new product to a database

    :return: Page to add new product in HTML
    """
    if request.method == 'POST':
        # Get user inputs
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        owner = login_session['user_id']

        # Get a user upload image
        image = request.files['file']
        filename = ''
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.abspath(app.config['UPLOAD_FOLDER'] + filename))

        # Check for required inputs
        if name and category:
            product = Product(name=name,
                              description=description,
                              image=filename,
                              cat_id=category,
                              owner_id=owner)
            session.add(product)
            session.commit()
            flash('%s has been successfully added.' % name)
        else:
            flash('Please fill the required fields.')
    return render_template('add-product.html')


@app.route('/edit/product/<int:p_id>', methods=['GET', 'POST'])
@login_required
def edit_product(p_id):
    """
    Edit an existing product specified by param

    :param p_id: Product ID
    :return: Page to edit an existing product in HTML
    """
    product = session.query(Product)\
        .join(Category).filter(Product.id == p_id).one()
    if request.method == 'POST':
        # Check if login_session user_id and owner_id matches
        if product.owner_id != login_session['user_id']:
            abort(401)

        # Get updated user inputs
        if request.form['name']:
            product.name = request.form['name']
        if request.form['description']:
            product.description = request.form['description']
        if request.form.get('category'):
            product.cat_id = request.form['category']

        # Get a user upload image
        if request.files['file']:
            image = request.files['file']
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image.save(os.path.abspath
                           (app.config['UPLOAD_FOLDER'] + filename))
                product.image = filename

        # Update the database
        session.add(product)
        session.commit()
        flash('%s has been successfully updated.' % product.name)

    return render_template('edit-product.html',
                           product=product)


@app.route('/delete/product/<int:p_id>', methods=['GET', 'POST'])
@login_required
def delete_product(p_id):
    """
    Delete an existing product specified by param

    :param p_id: Product ID
    :return: Page to delete an existing product in HTML
    """
    product = session.query(Product).filter_by(id=p_id).one()

    if request.method == 'POST':
        # Check if user has the product
        if product.owner_id == login_session['user_id']:
            name = product.name
            session.delete(product)
            session.commit()
            flash('%s has been successfully deleted.' % name)
            return redirect('/')
        else:
            abort(403)

    return render_template('delete-product.html',
                           product=product)


@app.route('/json')
def output_json():
    """
    JSON API endpoint

    :return: A list of all the products in JSON format
    """
    products = session.query(Product).all()
    return jsonify(Product=[p.serialize for p in products])


@app.route('/xml')
def output_xml():
    """
    XML API endpoint

    :return: A list of all the products in XML format
    """
    output = "<products>"
    products = session.query(Product).all()
    result = [p.serialize for p in products]
    output += xmlify(result, wrap="product", indent="   ")
    output += "</products>"
    return Response(output, mimetype="application/xml")


@app.route('/feed')
def show_feed():
    """
    RSS Feed endpoint

    :return: The most recent five products in RSS
    """
    products = session.query(Product)\
        .order_by(desc(Product.id)).limit(5).all()
    feed = render_template('rss.xml',
                           products=products)
    return Response(feed, mimetype="text/xml")


def get_categories():
    """
    :return: A list of all the categories
    """
    categories = session.query(Category).all()
    return categories


# Store the list of categories to the global variable
app.jinja_env.globals['category_list'] = get_categories


# CONNECT - Retrieve a user token and store into login_session


# Create anti-forgery state token
@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html',
                           state=state)


@app.route('/gconnect', methods=['POST'])
@csrf.exempt
def g_connect():
    client_id = json.loads(
        open('client_secrets.json', 'r').read())['web']['client_id']
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != client_id:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # Check if user exists, if it doesn't make a new one
    user_id = get_user_id(data["email"], 'google')
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    return "Success!"


@app.route('/fbconnect', methods=['POST'])
@csrf.exempt
def fb_connect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(
        open('secrets.json', 'r').read())['facebook']['app_id']
    app_secret = json.loads(
        open('secrets.json', 'r').read())['facebook']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token' \
          '?grant_type=fb_exchange_token&client_id=%s' \
          '&client_secret=%s&fb_exchange_token=%s' \
          % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.5/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session
    # in order to properly logout,
    # let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/' \
          'v2.5/me/picture?%s&redirect=0' \
          '&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # Check if user exists
    user_id = get_user_id(login_session['email'], 'facebook')
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    flash("Now logged in as %s" % login_session['username'])

    return "Success!"


@app.route('/gitconnect', methods=['POST', 'GET'])
@csrf.exempt
def git_connect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Prepare necessary information
    code = request.args.get('code')
    result = json.loads(open('secrets.json', 'r').read())['github']
    client_id = result['client_id']
    client_secret = result['client_secret']

    # Get a token
    url = 'https://github.com/login/oauth/access_token?client_id=%s' \
          '&client_secret=%s&code=%s' % (client_id, client_secret, code)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    token = result.split('&')[0].replace('access_token=', '')
    login_session['access_token'] = token

    # Get user name and picture url
    url = 'https://api.github.com/user?access_token=%s' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['username'] = data['name']
    login_session['picture'] = data['avatar_url']
    login_session['provider'] = 'github'

    # Get user email
    url = 'https://api.github.com/user/emails?access_token=%s' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)[0]
    login_session['email'] = data['email']

    # Check if user exists
    user_id = get_user_id(data["email"], 'github')
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    return redirect(url_for('show_homepage'))


# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/logout')
def logout():
    if 'provider' in login_session:
        # Disconnect from Google
        if login_session['provider'] == 'google':
            g_disconnect()
            del login_session['gplus_id']
            del login_session['credentials']

        # Disconnect from Facebook
        if login_session['provider'] == 'facebook':
            fb_disconnect()
            del login_session['facebook_id']

        # Disconnect from GitHub
        if login_session['provider'] == 'github':
            git_disconnect()

        # Delete user session information
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('show_homepage'))
    else:
        flash("You were not logged in")
        return redirect(url_for('show_homepage'))


def g_disconnect():
    # Only disconnect a connected user.
    if 'credentials' not in login_session:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    credentials = json.loads(login_session['credentials'])
    access_token = credentials['access_token']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    if 'error' in result:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def fb_disconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/' \
          '%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "You have been successfully logged out."


def git_disconnect():
    client_id = json.loads(
        open('secrets.json', 'r').read())['github']['client_id']
    url = 'https://api.github.com/applications/%s/tokens/%s'\
          % (client_id, login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "You have been successfully logged out."


# User Helper Functions


def create_user(login_session):
    new_user = User(name=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'],
                    provider=login_session['provider'])
    session.add(new_user)
    session.commit()
    user = session.query(User)\
        .filter_by(email=login_session['email'],
                   provider=login_session['provider'])\
        .one()
    return user.id


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email, provider):
    try:
        user = session.query(User)\
            .filter_by(email=email, provider=provider).one()
        return user.id
    except:
        return None


@app.errorhandler(401)
def forbidden(e):
    """
    Handle 401 error message

    :param e:
    :return: 401 error page in HTML
    """
    categories = session.query(Category).all()
    return render_template('401.html',
                           categories=categories), 401


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

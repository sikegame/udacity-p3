# Default modules
import os
import random
import string
import json
import requests
import httplib2

# Flask-related modules
from flask import Flask, render_template, request, redirect, \
    jsonify, url_for, flash, abort, \
    session as login_session, make_response

# SQL Alchemy modules
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Product

# Google oAuth module
from oauth2client.client \
    import flow_from_clientsecrets, FlowExchangeError

# The module for checking uploaded file name
from werkzeug import secure_filename


app = Flask(__name__)


# Configure file uploads
UPLOAD_FOLDER = 'static/images/'
ALLOWED_EXTENSIONS = set(['jpg', 'jpeg', 'png', 'gif'])
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Configure SQL Alchemy session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
def show_homepage():
    """ Shows the most recent 5 products
    """
    products = session.query(Product).join(Category)\
        .order_by(desc(Product.id)).limit(5).all()
    return render_template('home.html',
                           products=products,
                           session=login_session)


@app.route('/category/<int:c_id>/product/<int:p_id>')
def show_product(c_id, p_id):
    """ Takes a product id and shows a single product page
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
    """ Takes a category id and shows products in the category
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


@app.route('/add/category', methods=['GET', 'POST'])
def add_category():
    """ Add new category to the database
    """
    # Check if a user has logged in
    if 'user_id' not in login_session:
        abort(401)

    # Add new category
    if request.method == 'POST':
        name = request.form['category_name']
        new_category = Category(name=name)
        session.add(new_category)
        session.commit()
        flash('%s has been successfully added.' % name)

    return render_template('add-category.html')


@app.route('/edit/category/<int:c_id>', methods=['GET', 'POST'])
def edit_category(c_id):
    """ Takes a category id and shows a page to modify the category
    """
    # Check if a user has logged in
    if 'user_id' not in login_session:
        abort(401)

    # Update the database
    category = session.query(Category).filter_by(id=c_id).one()
    if request.method == 'POST':
        name = request.form['name']
        if name:
            category.name = name
            session.add(category)
            session.commit()
            flash('%s has been successfully updated.' % name)

    return render_template('edit-category.html',
                           category=category)


@app.route('/delete/categories', methods=['GET', 'POST'])
def delete_categories():
    """ Shows a page to delete multiple categories
    """
    # Check if a user has logged in
    if 'user_id' not in login_session:
        abort(401)

    if request.method == 'POST':
        token = login_session.pop('csrf_token', None)
        if token and token == request.form.get('csrf_token'):
            items_to_delete = request.form.getlist('delete[]')

            # Check if user checked any boxes
            if items_to_delete:
                items = session.query(Category)\
                    .filter(Category.id.in_(items_to_delete)).all()
                for item in items:
                    session.delete(item)
                    flash("%s has been deleted from the database." % item.name)
                session.commit()
            else:
                flash("No categories were selected.")
        else:
            abort(403)

    return render_template('delete-category.html')


def allowed_file(filename):
    """ Check if user uploaded file is acceptable format
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/add/product', methods=['GET', 'POST'])
def add_product():
    """ Allows logged user to add new product
    """
    # Check if a user has logged in
    if 'user_id' not in login_session:
        abort(401)

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
def edit_product(p_id):
    """ Takes a product id and allows the page owner to modify the product
    """
    # Check if a user has logged in
    if 'user_id' not in login_session:
        abort(401)

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
def delete_product(p_id):
    """ Takes a product id and allows the page owner to delete the product
    """
    # Check if a user has logged in
    if 'user_id' not in login_session:
        abort(401)

    product = session.query(Product).filter_by(id=p_id).one()

    if request.method == 'POST':
        # Check for CSRF protection token
        token = login_session.pop('csrf_token', None)
        if token == request.form.get('csrf_token'):
            # Check if user has the product
            if product.owner_id == login_session['user_id']:
                name = product.name
                session.delete(product)
                session.commit()
                flash('%s has been successfully deleted.' % name)
                return redirect('/')
            else:
                abort(403)
        else:
            abort(403)

    return render_template('delete-product.html',
                           product=product)


@app.route('/json')
def products_json():
    """ Returns all products in JSON format
    """
    products = session.query(Product).all()
    return jsonify(Product=[p.serialize for p in products])


@app.route('/feed')
def show_feed():
    """ Very simple XML-RSS feed generator
    """
    products = session.query(Product)\
        .order_by(desc(Product.id)).limit(5).all()
    return render_template('rss.xml',
                           products=products)


def get_categories():
    """ Returns the list of categories
    """
    categories = session.query(Category).all()
    return categories


# Store the list of categories to the global variable
app.jinja_env.globals['category_list'] = get_categories


def generate_csrf_token():
    """ Generate token for CSRF protection
    """
    if 'csrf_token' not in login_session:
        login_session['csrf_token'] = ''.join(
            random.choice(
                string.ascii_uppercase + string.digits) for x in xrange(32))
        return login_session['csrf_token']


# Store CSRF token function object to the global variable
app.jinja_env.globals['csrf_token'] = generate_csrf_token


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
    login_session['credentials'] = credentials
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
    user_id = get_user_id(data["email"])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    return "Success!"


@app.route('/fbconnect', methods=['POST'])
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

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
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
          'v2.4/me/picture?%s&redirect=0' \
          '&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # Check if user exists
    user_id = get_user_info(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    flash("Now logged in as %s" % login_session['username'])

    return "Success!"


@app.route('/gitconnect', methods=['POST', 'GET'])
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
    user_id = get_user_id(data["email"])
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
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    if result['status'] != '200':
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
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.errorhandler(401)
def forbidden(e):
    """ Error handler for the forbidden page
    """
    categories = session.query(Category).all()
    return render_template('401.html',
                           categories=categories), 401


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

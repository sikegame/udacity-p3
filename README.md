<h1>Product Catalog App</h1>

## Synopsis

This is a simple web-based product catalog with the social media user authentication system. Users can connect their credentials through Facebook, Google and GitHub account.

## Features

- JSON/XML/RSS API endpoints
- oAuth2 user authentication with Facebook, Google, Github
- CSRF protection
- File upload function
- Create, modify, delete categories
- User-friendly bootstrap interface

## Requirements

- Python 2.7
- Flask version 0.9
- Werkzung WSGI utility library
- dict2xml library
- Flask-SeaSurf library

## Installation

1. Install Python 2.7.
2. Install Flask 0.9 by running `python pip install flask==0.9`.
3. Install all the dependent libraries from the command line.
	- Run `python pip install Werkzeug`.
	- Run `python pip install dict2xml`.
	- Run `python pip install flask-seasurf`.
4. Move to the location of the folder containing `project.py`.
5. Run `python project.py` from the command line.
6. Open a browser and type http://localhost:5000 in the address bar.

## Screenshot

![Homepage](/screenshot.jpg)

## Category Operation

`/add/category`

Add a new category. A user must be logged in.

`/edit/category/CATEGORY_ID`

Modify an existing category. A user must be logged in and has to be the creator of the category.

`/delete/category/CATEGORY_ID`

Delete an existing category. A user must be logged in and has to be the creator of the category.

## Product Operation

`/add/product`

Add a new product. A user must be logged in.

`/edit/product/PRODUCT_ID`

Modify an existing product. A user must be logged in and has to be the creator of the product page.

`/delete/product/PRODUCT_ID`

Delete an existing product. A user must be logged in and has to be the creator of the product page.

## API endpoints

`/json`

Returns the list of all products in JSON format.

`/xml`

Returns the list of all products in XML format.

`/feed`

Returns the most recent 5 products in XML format for RSS feed.

## Sample Data

Initial installation comes with the sample data. You can safely remove the sample data by removing `catalog.db`.

## Contacts

Please send any bug reports or feedbacks to

Email: no_junk_email@gmail.com

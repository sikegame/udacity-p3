<h1>Product Catalog App</h1>

## Synopsis

This is a simple web-based product catalog with the social media user authentication system. Users can connect their credentials through Facebook, Google and GitHub account.

## Requirements

- Python 2.7 or newer
- Werkzung WSGI utility library

## Installation

1. Install Python 2.7 or newer.
2. Run `python pip install Werkzeug` from the command line.
3. Move to the location of the folder containing `project.py`.
4. Run `python project.py` from the command line.
5. Open a browser and type http://localhost:5000 in the address bar.

## Category Operation

`/add/category`

Add a new category. A user must be logged in.

`/edit/category/CATEGORY ID`

Modify an existing category. A user must be logged in.

`/delete/categories`

Delete multiple categories. A user must be logged in.

## Product Operation

`/add/product`

Add a new product. A user must be logged in.

`/edit/product/PRODUCT ID`

Modify an existing product. A user must be logged in and has to be the creator of the product page.

`/delete/product/PRODUCT ID`

Delete an existing product. A user must be logged in and has to be the creator of the product page.

## API endpoints

`/json`

Returns the list of all products in JSON format.

`/feed`

Returns the most recent 5 products in XML format for RSS feed.

## Sample Data

Initial installation comes with the sample data. You can safely remove the sample data by removing `catalog.db`.

## Contacts

Please send any bug reports or feedbacks to

Email: no_junk_email@gmail.com

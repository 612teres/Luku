from flask import Flask, render_template, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
import os
from models import Product, db

app = Flask(__name__)
app.config['SECRETE_KEY'] = 'secrete_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///luku.db'

db.init_app(app)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class ProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description')
    price = StringField('Price', validators=[DataRequired()])
    image = FileField('Image')
    submit = SubmitField('Add Product')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/products')
def products():
    products = Product.query.all()
    return render_template('products.html', products=products)

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        if 'image' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['image']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            product = Product(name=form.name.data, description=form.description.data, price=form.price.data, image_path=filename)

            db.session.add(product)
            db.session.commit()
            return redirect(url_for('products'))
        
    return render_template('add_product.html', form=form)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
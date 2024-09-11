from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file, Response
from flask_admin import Admin
from functools import wraps
from flask_admin.contrib.sqla import ModelView
from flask_admin.form.upload import ImageUploadField
from flask_admin.actions import action
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from wtforms import StringField, SubmitField, FileField
from wtforms.validators import DataRequired, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import mimetypes
from models import Product, db

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///luku.db'

db.init_app(app)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

login_manager = LoginManager()
login_manager.init_app(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for(index))
        return f(*args, **kwargs)
    return decorated_function

class ProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description')
    price = StringField('Price', validators=[DataRequired()])
    image = FileField('Image', validators=[DataRequired()])
    submit = SubmitField('Add Product')

class ProductAdminView(ModelView):
    form_extra_fields = {
        'image_data': ImageUploadField('Image', base_path=UPLOAD_FOLDER)
    }
    #Override the _save_file method to skip resizing
    def _save_file(self, data, filename):
        path = self._get_path(filename)
        if self.image:
            self.image.save(path)
        else:
            with open(path, 'wb') as f:
                f.write(data)
        return filename

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    product = db.relationship('Product', backref=db.backref('orders', lazy=True))
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    customer = db.relationship('User', backref=db.backref('orders', lazy=True))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class UserAdminView(ModelView):
    # List of columns to display in the list view
    column_list = ['username', 'is_admin', 'orders']  # Assuming 'orders' is the relationship in your User model

    # Allow sorting on these columns
    column_sortable_list = ['username', 'is_admin']

    # Add search functionality on these columns
    column_searchable_list = ['username']

    # Add filters for the 'is_admin' column
    column_filters = ['is_admin']

    # Customize how the 'is_admin' column is displayed
    def _list_thumbnail(view, context, model, name):
        if model.is_admin:
            return '✅'  # Or any other suitable visual indicator
        else:
            return ''

    column_formatters = {
        'is_admin': _list_thumbnail
    }

    @action('promote_to_admin', 'Promote to Admin', 'Are you sure you want to promote selected users to admins?')
    def promote_to_admin(self, ids):
        try:
            query = User.query.filter(User.id.in_(ids))
            count = 0
            for user in query.all():
                if not user.is_admin:
                    user.is_admin = True
                    count += 1
            db.session.commit()
            flash(f"{count} user(s) were successfully promoted to admin.", 'success')
        except Exception as ex:
            flash(f"Failed to promote users to admin. Error: {str(ex)}", 'error')

class AdminRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    is_admin = BooleanField('Is Admin')
    submit = SubmitField('Register')

admin = Admin(app, name='Luku Admin', template_mode='bootstrap3')
admin.add_view(ModelView(User, db.session))
admin.add_view(ProductAdminView(Product, db.session))
admin.add_view(ModelView(Order, db.session))

@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    form = AdminRegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, is_admin=True)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Admin created successfully', 'success')
        return redirect(url_for('admin_index'))
    return  render_template('admin_register.html', title='Admin Register', form=form)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        # Or another page after login
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('That username is already taken. Please choose a different one.')
        else:
            user = User(username=form.username.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in')
            return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()  # You can reuse your existing LoginForm
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data) and user.is_admin:
            login_user(user)
            flash('Admin logged in successfully.')
            return redirect(url_for('admin.index'))  # Redirect to the admin dashboard
        else:
            flash('Invalid username or password or not an admin.')
    return render_template('admin_login.html', title='Admin Login', form=form)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/products')
def products():
    products = Product.query.all()
    return render_template('products.html', products=products)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
@admin_required
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        if 'image' not in request.files:  # Check if image is in the request
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['image']  # Get the file from the form

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file and allowed_file(file.filename):  # Ensure file is allowed (extension check)
            filename = secure_filename(file.filename)  # Secure the filename
            
            # Read the file data in binary mode
            image_data = file.read()  # Read the image as binary data

            # Optionally save the file to the uploads folder
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(file_path, 'wb') as f:
                f.write(image_data)  # Write binary data to file

            # Create the product entry in the database
            product = Product(
                name=form.name.data,
                description=form.description.data,
                price=float(form.price.data),  # Convert price to float
                image_data=image_data,  # Store binary data in the database
                original_filename=filename  # Store the original filename
            )

            db.session.add(product)
            db.session.commit()

            flash('Product added successfully', 'success')
            return redirect(url_for('products'))

    return render_template('add_product.html', form=form)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = {}
    if product_id in session['cart']:
        session['cart']['product_id'] += 1
    else:
        session['cart']['product_id'] = 1

    session.modified = True
    return redirect(url_for('cart'))

@app.route('/product_image/<int:product_id>')
def product_image(product_id):
    product = Product.query.get_or_404(product_id)
    image_data = bytes(product.image_data)

    mimetype, _ = mimetypes.guess_type(product.original_filename)

    if not mimetype:
        mimetype = 'application/octet-steam'

    return Response(image_data, mimetype=mimetype)

@app.route('/cart')
def cart():
    cart_items = []
    total_price = 0
    for product_id, quantity in session.get('cart', {}).items():
        product = Product.query.get(product_id)
        if product:
            cart_items.append({
                'product': product,
                'quantity': quantity,
                'subtotal': product.price * quantity
            })
            total_price += product.price * quantity
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)


with app.app_context():
    db.drop_all()
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
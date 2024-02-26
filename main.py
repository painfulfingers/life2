from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, send_from_directory,request,session,jsonify
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_talisman import Talisman
from sqlalchemy.orm import relationship
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from flask_wtf.file import FileField, FileRequired, FileAllowed, MultipleFileField
from wtforms.validators import DataRequired, URL, Email, Length
import random
import time
from PIL import Image
import io
import base64


app = Flask(__name__)
talisman = Talisman(app)
app.secret_key = 'dsgzdfshdfhdgxhghdfhdf'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///dukan.db"
db = SQLAlchemy()
db.init_app(app)
app.config["TEMPLATES_AUTO_RELOAD"] = True
bootstrap = Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=80,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(Details, user_id)

# Content Security Policy (CSP) Header
csp = {
    'default-src': [
        '\'self\'',
        'https://code.jquery.com',
        'https://cdn.jsdelivr.net'
    ]
}
# HTTP Strict Transport Security (HSTS) Header
hsts = {
    'max-age': 31536000,
    'includeSubDomains': True
}

# Enforce HTTPS and other headers
talisman.force_https = True
talisman.force_file_save = True
talisman.x_xss_protection = True
talisman.session_cookie_secure = True
talisman.session_cookie_samesite = 'Lax'
talisman.frame_options_allow_from = 'https://www.google.com'
 
# Add the headers to Talisman
talisman.content_security_policy = csp
talisman.strict_transport_security = hsts


class MyForm(FlaskForm):
    name = StringField('name', validators=[DataRequired()])
    email = StringField('email', validators=[DataRequired(),Email(message="incorrect email")])
    password = PasswordField('password', validators=[DataRequired(), Length(min=7, message="should be greater than 7")])
    Submit = SubmitField('Submit')

class Seachform(FlaskForm):
    searched =  StringField('searched', validators=[DataRequired()])
    Submit = SubmitField('Submit')

class Form(FlaskForm):
    product = StringField('product', validators=[DataRequired()])
    price = StringField('price', validators=[DataRequired()])
    description = StringField('description', validators=[DataRequired()])
    data_file = MultipleFileField(validators=[FileRequired(), FileAllowed(['png','jpg','jpeg'], 'png and jpg files only')])
    enter = SubmitField('enter')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")

class Details(UserMixin, db.Model):
    __tablename__ = 'manager'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(250), nullable=False)
    followers = db.Column(db.Integer, nullable=False)
    chips = relationship("Book", back_populates="ate")
    kurkure = relationship("Description", back_populates="eat")

class Description(db.Model):
    __tablename__ = 'product_imf'
    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(250), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(250), nullable=False)
    picture = relationship("Book", back_populates="author")
    eat = relationship("Details", back_populates="kurkure")
    eat_id = db.Column(db.Integer, db.ForeignKey("manager.id"))

class Book(db.Model):
    __tablename__ = 'images'
    id = db.Column(db.Integer, primary_key=True)
    my_blob = db.Column(db.LargeBinary, nullable=False)
    author = relationship("Description", back_populates="picture")
    ate = relationship("Details", back_populates="chips") 
    author_id = db.Column(db.Integer, db.ForeignKey("product_imf.id"))
    ate_id = db.Column(db.Integer, db.ForeignKey("manager.id"))

with app.app_context():
    db.create_all()    

@app.route('/listed',  methods=['GET', 'POST'])
def my_route():
    result = db.session.execute(db.select(Description).order_by(Description.id)).scalars()
    all_images = db.session.execute(db.select(Book).order_by(Book.id)).scalars()
    listing = {}
    for i in result:
        listing[i.id] = []
    for j in all_images:
        corrected_blob = j.my_blob.decode('utf-8')
        listing[j.author.id].append(corrected_blob)
    all_books = db.session.execute(db.select(Description).order_by(Description.id)).scalars()     

    return render_template("product.html", all_books=all_books, listing=listing)


@app.route('/forgot_password',  methods=['GET', 'POST'])
def forgot_password():
    if request.method == "GET":
    
        session['start_time'] = time.time()
        session['otpe'] = random.randint(0,100)

    if request.method == "POST":
        start_time = session.get('start_time')
        new_time = int(time.time()) - int(start_time)  # Calculate the time difference in seconds     
        if request.form.get('enter') == 'enter':
            if new_time >= 10:
                flash("Time limit exceeded.")
                return redirect(url_for('forgot_password'))
            elif int(request.form['otp']) == session.get('otpe'):
                    return redirect(url_for('bhoot'))
            else:
               flash('wrong password')
               return redirect(url_for('forgot_password'))

        if  request.form.get('enter') == 'resend':
            
            return redirect(url_for('forgot_password'))
    return render_template('otp.html', generate_number=session.get('otpe'))        



@app.route('/my_listed', methods=['GET', 'POST'])
def hello_world1():
    result = db.session.execute(db.select(Description).order_by(Description.id)).scalars()
    all_images = db.session.execute(db.select(Book).order_by(Book.id)).scalars()
    change = {}
    for i in result:
        change[i.id] = []
    for j in all_images:
        corrected_blob = j.my_blob.decode('utf-8')
        change[j.author.id].append(corrected_blob)
    all_books =  db.session.execute(db.select(Description).order_by(Description.id)).scalars()   
    return render_template("admin.html", all_books=all_books, check=current_user, change=change)

@app.route('/',  methods=['GET', 'POST'])
def hello_name():
   regs = MyForm()
   if regs.validate_on_submit():
       meow = regs.email.data
       book = db.session.execute(db.select(Details).where(Details.email == meow)).scalar()
       if book:
           flash("email already exists")
           return render_template("login.html")
       new_password = generate_password_hash(regs.password.data, method='pbkdf2', salt_length=16)
       new_book = Details(name=regs.name.data, email=regs.email.data, password=new_password, followers=0)
       db.session.add(new_book)
       db.session.commit()
       login_user(new_book)
       return render_template("product.html")
   return render_template("Regs.html", regs=regs)


@app.route('/profile',  methods=['GET', 'POST'])
def profile():
   result = db.session.execute(db.select(Details).order_by(Details.id)).scalars()
   return render_template('profile.html',result=result)


@app.route('/login',  methods=['GET', 'POST'])
def bhoot():
    loginform = LoginForm()
    if loginform.validate_on_submit():
        password = loginform.password.data
        result = db.session.execute(db.select(Details).where(Details.email == loginform.email.data))
        
        user = result.scalar()
      
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('bhoot'))
     
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('bhoot'))
        else:
            login_user(user)
            return redirect(url_for('my_route'))
        
        
    return render_template("login.html", loginform=loginform, current_user=current_user)




@login_required
@app.route('/search', methods=['GET'])
def search():
    billi = Seachform()
    pass
    


@login_required
@app.route('/create_list',  methods=['GET', 'POST'])
def hello_world():
    series =  Form()
    if series.validate_on_submit():

      list = Description(product=series.product.data, price=series.price.data, description=series.description.data, eat_id=current_user.id)
      db.session.add(list)
      db.session.commit()
      
      meow = series.data_file.data
      for data_file in meow:
         im = Image.open(data_file)
         rgb_im = im.convert('RGB')
         data = io.BytesIO()
         rgb_im.save(data, "jpeg")
         encoded_img_data = base64.b64encode(data.getvalue())
         
          

         list2 = Book(my_blob=encoded_img_data, author_id=list.id, ate_id=current_user.id)
         db.session.add(list2)
          
      db.session.commit()
      
          
      return redirect(url_for('my_route'))

      
    return render_template("pregs.html", series=series)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/delete/<index>',  methods=['GET', 'POST'])
def delete(index):
    book_to_delete = db.get_or_404(Description, index)
    db.session.delete(book_to_delete)
    db.session.commit()
    return redirect(url_for('my_route'))

@app.route('/edit/<index>', methods=['GET', 'POST'])
def edit(index):
    edit = db.get_or_404(Description, index)
    edit_form = Form(product=edit.product, price=edit.price, description=edit.description)
    if edit_form.validate_on_submit():
        book_to_update = db.get_or_404(Description, index)
        book_to_update.product = edit_form.data.product
        book_to_update.price = edit_form.data.price
        book_to_update.description = edit_form.data.description
        db.session.commit() 
        try:
           return redirect(url_for('my_route'))
        except Exception:
            return redirect(url_for('my_route'))

    return render_template('pregs.html', series=edit_form)
        
# Create an admin-only decorator
#def admin_only(f):
    #@wraps(f)
    #def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        #if current_user.id != 1:
            #return abort(403)
        # Otherwise continue with the route function
        #return f(*args, **kwargs)

    #return decorated_function
    

if __name__ == '__main__':
   app.run(debug=True)


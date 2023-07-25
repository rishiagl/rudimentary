from flask import Flask, render_template
from forms import RegistrationForm, LoginForm
app = Flask(__name__)

app.config['SECRET_KEY'] = '60623738d5cbd26293770a5797ea3d0e'

@app.route("/")
def hello_world():
    print(__name__)
    return render_template('home.html', title ='Home')

@app.route("/register")
def register():
     form = RegistrationForm()
     
     return render_template('register.html', title = 'Register', form = form)
 
@app.route("/login")
def login():
     form = LoginForm()
     return render_template('login.html', title = 'Login', form = form)

if __name__ == '__main__':
    app.run(debug = True)
import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Define function that checks for password strength

def PassStrength(password):
    properties = {"lower": 0, "upper": 0, "numbers": 0, "special": 0}
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    numbers = "1234567890"
    special = "!§$%&'\"<>\\:;/()=?,.-_+#*~^"

    if len(password) < 8:
        return False

    for letter in password:
        if letter in alphabet:
            properties["lower"] += 1

        elif letter in alphabet.upper():
            properties["upper"] += 1

        elif letter in numbers:
            properties["numbers"] += 1

        elif letter in special:
            properties["special"] += 1


    for prop in properties:
        if properties[prop] < 1:
            return False

    return True


def SpecialCharacters(username):
    special = "!§$%&/()\\=\"?,.-_:;+#'*~<>^"

    for letter in username:
        if letter in special:
            return True

    return False


@app.route("/")
@login_required
def index():

    """Show portfolio of stocks"""

    # Get all pervious transations by ID
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = :id", id = session["user_id"])

    holdings = {}

    for transaction in transactions:
        if transaction["type"] == "BUY":
            if transaction["symbol"] not in holdings.keys():
                holdings[transaction["symbol"]] = int(transaction["shares"])
            else:
                holdings[transaction["symbol"]] = int(holdings[transaction["symbol"]]) + int(transaction["shares"])
            if int(holdings[transaction["symbol"]]) == 0:
                holdings.pop("symbol")

        if transaction["type"] == "SELL":
            if transaction["symbol"] not in holdings.keys():
                holdings[transaction["symbol"]] = - int(transaction["shares"])
            else:
                holdings[transaction["symbol"]] = int(holdings[transaction["symbol"]]) - int(transaction["shares"])
            if int(holdings[transaction["symbol"]]) == 0:
                holdings.pop(transaction["symbol"])

    prices = {}
    names = {}
    values = {}
    total = 0

    for index, holding in enumerate(holdings):
        data = lookup(holding)
        prices[holding] = usd(data["price"])
        names[holding] = data["name"]
        values[holding] = float(data["price"]) * int(holdings[data["symbol"]])
        total = total + (float(data["price"]) * int(holdings[data["symbol"]]))



    for value in values:
        values[value] = usd(values[value])

    current_user = db.execute("SELECT * FROM users WHERE id = :id", id = session["user_id"])
    if len(current_user) != 1:
        return apology("Your user id was not found. Please try loggin in again.")

    cash = current_user[0]["cash"]

    net_worth = total + cash

    return render_template("dashboard.html", holdings=holdings, prices=prices, names=names, values=values, total=usd(total), cash=usd(cash), net_worth=usd(net_worth))



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide a stock symbol to buy", 403)

        # Ensure shares were submitted
        if not request.form.get("shares") or int(request.form.get("shares")) <= 0:
            return apology("must provide a valid number of shares to buy", 403)

        # Ensure shares are not negative

        response = lookup(request.form.get("symbol"))
        if response == None:
            return apology("that stock symbol doesnt exist", 403)

        name = response["name"]
        price = response["price"]
        symbol = response["symbol"]

        # Calculate amount of money required to buy the selected shares
        required_funds = float(price) * int(request.form.get("shares"))

        current_user = db.execute("SELECT * FROM users WHERE id = :id", id = session["user_id"])
        if len(current_user) != 1:
            return apology("there seems to be no ID found. Critical Error!", 403)

        # Check if funds required are present in the account
        if float(required_funds) > float(current_user[0]["cash"]):
            return apology("your existing funds are too small for this purchse", 403)

        # Get the last transaction ID in order to insert the next one in order
        last_id = db.execute("SELECT id FROM transactions ORDER BY id DESC LIMIT 1")
        print(last_id)
        if len(last_id) == 0:
            last_id = [{"id":0}]

        new_id = last_id[0]["id"] + 1

        db.execute("INSERT INTO transactions VALUES(:newid, :currentuser, datetime('now', 'localtime'), :symbol, :shares, :type, :company, :shareprice)", newid = new_id, currentuser = current_user[0]["id"], symbol = request.form.get("symbol"), shares = int(request.form.get("shares")), type = "BUY", company = name, shareprice = price)
        db.execute("UPDATE users SET cash = :cashvalue WHERE id = :currentuser ", cashvalue = (float(current_user[0]["cash"]) - float(required_funds)), currentuser = current_user[0]["id"])

        flash(f'Your purchase of {request.form.get("shares")} shares of {name} ({symbol}) was successful.')

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get all pervious transations by ID
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = :currentuser ORDER BY datetime DESC", currentuser = session["user_id"])

    values = {}
    total = 0

    for index, transaction in enumerate(transactions):
        values[transaction["symbol"]] = float(transaction["price"]) * int(transaction["shares"])
        total = float(total) + (float(transaction["price"]) * int(transaction["shares"]))

    for value in values:
        values[value] = usd(values[value])

    flash("You have successfully loaded your transaction history.")

    return render_template("history.html", transactions=transactions, values=values, total=usd(total))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        flash("You have successfully logged in.")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    flash("You have successfully logged out.")


    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

         # Ensure stock symbol was submitted
        if not request.form.get("symbol") or SpecialCharacters(request.form.get("symbol")) == True:
            return apology("must provide a valid stock symbol to get a quote.", 403)

        response = lookup(request.form.get("symbol"))
        name = response["name"]
        price = response["price"]
        symbol = response["symbol"]

        return render_template("quoted.html", name=name, price=usd(price), symbol=symbol)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Password must match the confirmation
        elif  request.form.get("password") !=  request.form.get("confirmation"):
            return apology("the entered passwords do not match", 403)

        # Ensure that password is strong enough
        elif PassStrength(request.form.get("password")) != True:

            flash("Password was not strong enough. It must be at least 8 characters long and contain 1 upper case letter, 1 number, and 1 special character. Try again.")

            return render_template("register.html")

        elif SpecialCharacters(request.form.get("username")) == True:

            flash("Username cannot contain special characters.")

            return render_template("register.html")



        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        if len(rows) != 0:
            return apology("Username already exists. Please choose a different one.", 403)

        lastUser = db.execute("SELECT * FROM users ORDER BY id DESC LIMIT 1")

        if len(lastUser) == 0:
            lastID = 0
        else:
            lastID = lastUser[0]["id"]


        db.execute("INSERT INTO users (id, username, hash, cash) values (:newid, :currentuser, :password, :cash)", newid = (lastID + 1), currentuser = request.form.get("username"), password = generate_password_hash(request.form.get("password")), cash = 10000)

        flash("You have successfully registered your account.")


        # Redirect user to home page
        return redirect("/")


    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide a stock symbol", 403)

        # Ensure shares were submitted
        elif not request.form.get("shares") or int(request.form.get("shares")) <= 0:
            return apology("must provide a number of shares you want to sell", 403)

        # Ensure user actually owns shares
        shares_bought = db.execute("Select SUM(shares) FROM transactions WHERE symbol = :symbol AND user_id = :currentuser AND type = 'BUY'", symbol = request.form.get("symbol"), currentuser = session["user_id"])
        shares_sold = db.execute("SELECT SUM(shares) FROM transactions WHERE symbol = :symbol AND user_id = :currentuser AND type = 'SELL'", symbol = request.form.get("symbol"), currentuser = session["user_id"])

        print(shares_bought)
        print(shares_sold)

        # Check if the SQLite queries returned null because no records were found
        if shares_bought[0]["SUM(shares)"] == None:
            shares_bought[0]["SUM(shares)"] = 0

        if shares_sold[0]["SUM(shares)"] == None:
            shares_sold[0]["SUM(shares)"] = 0

        current_shares = int(shares_bought[0]["SUM(shares)"]) - int(shares_sold[0]["SUM(shares)"])


        if current_shares <= 0:
            return apology("you do not own any shares in that stock anymore.")

        if ((int(current_shares) - int(request.form.get("shares"))) < 0 ):
            return apology("you are trying to sell more shares than you own.")

        # Get data on prices and company
        data = lookup(request.form.get("symbol"))

        price = data["price"]
        name = data["name"]
        symbol = data["symbol"]

        # The funds won by selling
        won_funds = float(price) * int(request.form.get("shares"))

        # Get the current balance of the users
        current_user = db.execute("SELECT * FROM users WHERE id = :currentuser", currentuser = session["user_id"])
        if len(current_user) != 1:
            return apology("there seems to be no ID found. Critical Error! Try loggin in again.", 403)

        # Check if funds required are present in the account
        if int(request.form.get("shares")) > int(current_user[0]["cash"]):
            return apology("you are trying to sell more shares than you own", 403)

        last_id = db.execute("SELECT id FROM transactions ORDER BY id DESC LIMIT 1")
        print(last_id)
        if len(last_id) == 0:
            last_id = [{"id":0}]

        new_id = last_id[0]["id"] + 1


        db.execute("INSERT INTO transactions VALUES(:newid, :currentuser, datetime('now', 'localtime'), :symbol, :shares, :type, :company, :stockprice)", newid = new_id, currentuser = current_user[0]["id"], symbol = request.form.get("symbol"), shares = int(request.form.get("shares")), type = "SELL", company = name, stockprice = price)
        db.execute("UPDATE users SET cash = :cash WHERE id = :currentuser ", cash = (float(current_user[0]["cash"]) + float(won_funds)), currentuser = current_user[0]["id"])

        flash(f'Your sell order of {request.form.get("shares")} shares of {name} ({symbol}) was successful.')

        return redirect("/")

    else:

        stocks = []

        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = :currentuser", currentuser = session["user_id"])

        for row in symbols:
            if row["symbol"] in stocks:
                continue
            stocks.append(row["symbol"])

        return render_template("sell.html", stocks=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

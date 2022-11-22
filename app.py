import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

#Create new table in database for transactions
db.execute("CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, user_id INTEGER NOT NULL, name TEXT NOT NULL, shares INTEGER NOT NULL, symbol TEXT NOT NULL, price NUMERIC NOT NULL, type TEXT NOT NULL, time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))")



@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""
    if request.method == "GET":
        transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
        name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
        current_balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        stock_value = 0
        for transaction in transactions:
            stock_value += float(transaction["price"])

        grand_total = stock_value + current_balance


        return render_template("index.html", name=name, transactions=transactions, balance=usd(current_balance), grand_total=usd(grand_total))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():

    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Please input a company's symbol.")
        symbol = request.form.get("symbol")
        if not lookup(symbol):
            return apology("Company does not exist. Please enter a valid symbol to continue.")
        if not request.form.get("shares"):
            return apology(f"Please input the number of shares from {symbol} that you wish to purchase.")
        shares = int(request.form.get("shares"))
        if shares <= 0:
            return apology(f"Please input a POSITIVE number of shares if you wish to purchase from {symbol}.")

        stock_price = lookup(symbol)["price"]
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        if user_cash < (shares * stock_price):
            return apology(f"You do not have enough to purchase {shares} shares of {symbol} stock.")
        else:
            db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash - (shares * stock_price), session["user_id"])
            db.execute("INSERT INTO transactions (user_id, name, shares, symbol, price, type) VALUES (?,?,?,?,?,?)", session["user_id"], lookup(symbol)["name"], shares, symbol, shares * stock_price, "buy")

    """Buy shares of stock"""
    return redirect("/buy")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    if request.method == "GET":
        transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
        return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "GET":
        return render_template("quote.html")

    if request.method == "POST":


        if not request.form.get("symbol"):
            return apology("Please input a company's symbol.")

        symbol = request.form.get("symbol")

        if not lookup(symbol):
            return apology("No Company found with those Symbols. Please try again.")

        quote_info = lookup(symbol)
        return render_template("quoted.html", name=quote_info["name"], price=usd(quote_info["price"]), symbol=quote_info["symbol"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")

        if password != confirm_password:
            return apology("Passwords do not match.")
        if not request.form.get("username"):
            return apology("Please input a username.")
        if not request.form.get("confirmation"):
            return apology("Please confirm your password.")
        if not request.form.get("password"):
            return apology("Please input a password.")


        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))
        return redirect("/")

    if request.method == "GET":
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        symbols = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", symbols=symbols)

    if request.method == "POST":
        if not request.form.get("shares"):
            return apology("Please input a number of shares that you would like to sell.")
        symbol = request.form.get("symbol")
        num_shares = int(request.form.get("shares"))
        if num_shares <= 0:
            return apology("Please ensure you are inputting a positive number of shares.")
        user_shares = db.execute("SELECT shares FROM transactions WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)[0]["shares"]
        if num_shares > user_shares:
            return apology("You do not have that many shares to sell.")

        new_shares = user_shares - num_shares

        db.execute("UPDATE transactions SET shares = ? WHERE user_id = ? AND symbol = ?", new_shares, session["user_id"], symbol)
        cash_gained = num_shares * lookup(symbol)["price"]
        current_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        new_cash = cash_gained + current_cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, session["user_id"])
        db.execute("INSERT INTO transactions (user_id, name, shares, symbol, price, type) VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], lookup(symbol)["name"], num_shares, symbol, cash_gained, "sell")


        return redirect("/sell")

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "GET":
        return render_template("add.html")

    if request.method == "POST":
        if not request.form.get("add_cash"):
            return apology("Please input a cash amount to add.")
        amt = float(request.form.get("add_cash"))

        if amt <= 0:
            return apology("Please ensure that you are inputting a positive amount of cash to add.")

        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        new_cash = user_cash + amt
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, session["user_id"])
        return redirect("/add")



import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
from datetime import datetime
from sqlite3 import IntegrityError


# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    if not rows:
        return apology("missing user")

    cash = rows[0]["cash"]
    total = cash

    stocks = db.execute("""SELECT symbol, SUM(shares) AS shares FROM transactions
                        WHERE user_id = :user_id GROUP BY symbol HAVING sum(shares) > 0""", user_id=session["user_id"])

    for stock in stocks:
        stock_quote = lookup(stock["symbol"])
        stock["price"] = stock_quote["price"]
        total += stock["shares"] * stock_quote["price"]

    return render_template("index.html", stocks=stocks, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    # User reached route via GET
    if request.method == "GET":
        # Display form to buy a stock
        return render_template("buy.html")

    # User reached route via POST
    else:
        # Purchase the stock so long as the user can afford it
        # Check for valid input
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("invalid symbol")

        shares = request.form.get("shares")
        if not shares.isdigit() or int(shares) <= 0:
            return apology("invalid number of shares")
        stock["shares"] = int(shares)

        if not stock["price"]:
            return apology("price not found")

        # Ensure user has enough cash to afford the stock
        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = rows[0]["cash"]
        total_cost = stock["price"] * stock["shares"]
        if cash < total_cost:
            # If user can't afford stock, return an apology
            return apology("can't afford")

        # Run SQL statement on database to purchase stock
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transacted) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], stock["symbol"], stock["shares"], stock["price"], datetime.now())
        flash("Bought!")

        # Update cash to reflect purchased stock
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   cash - stock["price"] * stock["shares"], session["user_id"])

        # Redirect user to home page
        return redirect("/")


@app.route("/history")
@login_required
def history():
    # Query all transactions for the current user
    transactions = db.execute(
        "SELECT symbol, shares, price, transacted FROM transactions WHERE user_id = ?", session["user_id"])

    # Convert price to a float
    for transaction in transactions:
        transaction["price"] = float(transaction["price"])

    # Pass the transactions to the template
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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    # User reached route via GET
    if request.method == "GET":
        # Display change password form
        return render_template("change_password.html")

    # User reached route via POST
    else:
        # Check for possible errors
        # If any field is left blank, return an apology
        if not request.form.get("current_password"):
            return apology("missing current password")
        elif not request.form.get("new_password"):
            return apology("missing new password")
        elif not request.form.get("confirmation"):
            return apology("missing password confirmation")

        # If current password is incorrect, return an apology
        user_id = session.get("user_id")
        user = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
        current_password = request.form.get("current_password")
        if not check_password_hash(user[0]["hash"], current_password):
            return apology("invalid current password")

        # If password and confirmation don't match, return an apology
        elif request.form.get("confirmation") != request.form.get("new_password"):
            return apology("passwords don't match")

        # Hash the new password
        hashed_password = generate_password_hash(request.form.get("new_password"))

        # Update the password in the database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed_password, user_id)

        flash("Password changed!")

        # Redirect user to home page
        return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    # User reached route via GET
    if request.method == "GET":
        # Display form to request a stock quote
        return render_template("quote.html")

    # User reached route via POST
    else:
        # Lookup the stock symbol by calling the lookup function, and display the results
        symbol = lookup(request.form.get("symbol"))
        if not symbol:
            return apology("invalid symbol")
        else:
            return render_template("quoted.html", symbol=symbol)


@app.route("/register", methods=["GET", "POST"])
def register():
    # User reached route via GET
    if request.method == "GET":
        # Display registration form
        return render_template("register.html")

    # User reached route via POST
    else:
        # Check for possible errors
        # If any field is left blank, return an apology
        if not request.form.get("username"):
            return apology("missing username")
        elif not request.form.get("password"):
            return apology("missing password")
        elif not request.form.get("confirmation"):
            return apology("missing password confirmation")

        # If password and confirmation don't match, return an apology
        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("passwords don't match")

        # Insert the new user into users table
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                       request.form.get("username"),
                       generate_password_hash(request.form.get("password")))

        # If the username is already taken, return an apology
        except ValueError:
            return apology("username taken")

        # Retrieve the user ID of the newly registered user
        rows = db.execute("SELECT id FROM users WHERE username = ?", request.form.get("username"))

        # Ensure the user was found and get the user ID
        if len(rows) == 1:
            user_id = rows[0]["id"]

        # Log user in
        session["user_id"] = user_id

        flash("Registered!")

        # Redirect user to home page
        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    # User reached route via GET
    if request.method == "GET":
        # Display form to sell a stock
        stocks = db.execute("""SELECT symbol, SUM(shares) AS shares FROM transactions
                            WHERE user_id = :user_id GROUP BY symbol HAVING sum(shares) > 0""", user_id=session["user_id"])
        return render_template("sell.html", stocks=stocks)

    # User reached route via POST
    else:
        # Check for errors
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("missing symbol")

        shares = request.form.get("shares")
        if not shares.isdigit() or int(shares) <= 0:
            return apology("invalid number of shares")
        stock["shares"] = int(shares)

        shares_owned = db.execute("SELECT SUM(shares) AS shares FROM transactions WHERE user_id = :user_id AND symbol = :symbol GROUP BY symbol",
                                  user_id=session["user_id"], symbol=stock["symbol"])
        if shares_owned[0]["shares"] < stock["shares"]:
            return apology("too many shares")

        # Sell the specified number of shares of stock
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transacted) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], stock["symbol"], -stock["shares"], stock["price"], datetime.now())
        flash("Sold!")

        # Update the user's cash
        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = rows[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   cash + stock["price"] * stock["shares"], session["user_id"])

        # Redirect user to home page
        return redirect("/")

import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import re
import hashlib
import random
import string
from datetime import datetime


# -------------------- Helper Functions --------------------
def hash_password(password):
    """Hash a password using SHA256 for secure storage."""
    return hashlib.sha256(password.encode()).hexdigest()


def validate_email(email):
    """Validate email format using regex."""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)


def validate_phone(phone):
    """Ensure phone number fits the pattern 000000-0000."""
    pattern = r'^\d{6}-\d{4}$'
    return re.match(pattern, phone)


def validate_date(date_str):
    """Validate that the date is in YYYY-MM-DD format."""
    try:
        dt = datetime.strptime(date_str, '%Y-%m-%d')
        return dt
    except ValueError:
        return None


def validate_dates(checkin_str, checkout_str):
    """Return True if both dates are valid and check-in is before check-out."""
    checkin = validate_date(checkin_str)
    checkout = validate_date(checkout_str)
    return checkin and checkout and checkin < checkout


def generate_two_factor_code():
    """Generate a random 6-digit code."""
    return ''.join(random.choices(string.digits, k=6))


# -------------------- Database Setup --------------------
def setup_database():
    """Create necessary tables and preload sample employee data if not already present."""
    conn = sqlite3.connect('ocean_heaven.db')
    c = conn.cursor()
    # Users table for registration/login
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password TEXT NOT NULL,
                 email TEXT NOT NULL,
                 phone TEXT NOT NULL,
                 role TEXT NOT NULL)''')
    # Employees table with preloaded sample data
    c.execute('''CREATE TABLE IF NOT EXISTS employees (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL,
                 role TEXT NOT NULL,
                 shift TEXT NOT NULL)''')
    # Bookings table for room bookings
    c.execute('''CREATE TABLE IF NOT EXISTS bookings (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL,
                 email TEXT NOT NULL,
                 phone TEXT NOT NULL,
                 checkin TEXT NOT NULL,
                 checkout TEXT NOT NULL,
                 guests INTEGER NOT NULL,
                 room_type TEXT NOT NULL,
                 special_requests TEXT,
                 payment_status TEXT DEFAULT 'Pending')''')
    # Contacts table for inquiries
    c.execute('''CREATE TABLE IF NOT EXISTS contacts (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT,
                 email TEXT,
                 phone TEXT,
                 message TEXT)''')
    # Feedback table for customer reviews
    c.execute('''CREATE TABLE IF NOT EXISTS feedback (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 customer_name TEXT NOT NULL,
                 room_id TEXT NOT NULL,
                 rating INTEGER NOT NULL,
                 comments TEXT)''')

    # Preload employee data
    c.execute("SELECT COUNT(*) FROM employees")
    if c.fetchone()[0] == 0:
        sample_employees = [
            ("Alice Johnson", "Receptionist", "Morning Shift – 7AM to 3PM"),
            ("Bob Smith", "Housekeeping", "Afternoon Shift – 3PM to 11PM"),
            ("Charlie Evans", "Maintenance", "Night Shift – 11PM to 7AM"),
            ("Daisy Williams", "Manager", "Full-Day Shift")
        ]
        c.executemany("INSERT INTO employees (name, role, shift) VALUES (?, ?, ?)", sample_employees)

    conn.commit()
    conn.close()


setup_database()


# -------------------- GUI Components --------------------
class Header(tk.Frame):
    """Persistent header with the hotel logo and navigation links."""

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#003366", bd=2, relief="raised")
        self.controller = controller
        logo = tk.Label(self, text="Ocean Heaven", font=("Arial", 24, "bold"), fg="white", bg="#003366")
        logo.pack(side="left", padx=10)
        nav_frame = tk.Frame(self, bg="#003366")
        nav_frame.pack(side="right", padx=10)
        nav_buttons = [
            ("Home", "HomePage"),
            ("Rooms", "RoomSelectionPage"),
            ("Contact Us", "ContactPage"),
            ("Restaurant", "CustomerRestaurantPage")
        ]
        for label, page in nav_buttons:
            btn = ttk.Button(nav_frame, text=label, command=lambda p=page: controller.show_frame(p))
            btn.pack(side="left", padx=5)


class BasePage(tk.Frame):
    """Base page that always includes the header."""

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#e6f2ff")
        self.controller = controller
        header = Header(self, controller)
        header.pack(fill="x", pady=5)


# -------------------- Home Page --------------------
class HomePage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        welcome = tk.Label(body, text="Welcome to Ocean Heaven", font=("Arial", 28, "bold"),
                           bg="#e6f2ff", fg="#003366")
        welcome.pack(pady=20)
        banner = tk.Label(body, text="[Hotel Banner Image Here]", font=("Arial", 16),
                          bg="#cce6ff", width=50, height=5, relief="sunken")
        banner.pack(pady=10)
        btn_frame = tk.Frame(body, bg="#e6f2ff")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Book a Room", command=lambda: controller.show_frame("BookingPage")).pack(
            side="left", padx=5)
        ttk.Button(btn_frame, text="Customer Dashboard",
                   command=lambda: controller.show_frame("CustomerDashboardPage")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Admin Login", command=lambda: controller.show_frame("LoginPage")).pack(side="left",
                                                                                                           padx=5)
        ttk.Button(btn_frame, text="Employee Login", command=lambda: controller.show_frame("LoginPage")).pack(
            side="left", padx=5)


# -------------------- Booking Page --------------------
class BookingPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Room Booking", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        form = tk.Frame(body, bg="#e6f2ff", bd=2, relief="groove")
        form.pack(pady=10, padx=10)
        labels = [("Full Name*", "name"), ("Email*", "email"), ("Phone (000000-0000)*", "phone")]
        self.booking_vars = {}
        for idx, (lbl, key) in enumerate(labels):
            tk.Label(form, text=lbl, bg="#e6f2ff").grid(row=idx, column=0, sticky="e", padx=5, pady=5)
            var = tk.StringVar()
            self.booking_vars[key] = var
            ttk.Entry(form, textvariable=var, width=30).grid(row=idx, column=1, padx=5, pady=5)
        tk.Label(form, text="Number of Guests*", bg="#e6f2ff").grid(row=3, column=0, sticky="e", padx=5, pady=5)
        self.guests_var = tk.StringVar(value="1")
        ttk.Combobox(form, textvariable=self.guests_var, values=[str(i) for i in range(1, 9)], width=28).grid(row=3,
                                                                                                              column=1,
                                                                                                              padx=5,
                                                                                                              pady=5)
        tk.Label(form, text="Check-in Date (YYYY-MM-DD)*", bg="#e6f2ff").grid(row=4, column=0, sticky="e", padx=5,
                                                                              pady=5)
        self.checkin_entry = ttk.Entry(form, width=30)
        self.checkin_entry.grid(row=4, column=1, padx=5, pady=5)
        tk.Label(form, text="Check-out Date (YYYY-MM-DD)*", bg="#e6f2ff").grid(row=5, column=0, sticky="e", padx=5,
                                                                               pady=5)
        self.checkout_entry = ttk.Entry(form, width=30)
        self.checkout_entry.grid(row=5, column=1, padx=5, pady=5)
        tk.Label(form, text="Room Type*", bg="#e6f2ff").grid(row=6, column=0, sticky="e", padx=5, pady=5)
        self.room_type_var = tk.StringVar()
        ttk.Combobox(form, textvariable=self.room_type_var, values=["Single", "Double", "Suite"], width=28).grid(row=6,
                                                                                                                 column=1,
                                                                                                                 padx=5,
                                                                                                                 pady=5)
        tk.Label(form, text="Special Requests", bg="#e6f2ff").grid(row=7, column=0, sticky="e", padx=5, pady=5)
        self.special_req = tk.StringVar()
        ttk.Entry(form, textvariable=self.special_req, width=30).grid(row=7, column=1, padx=5, pady=5)
        btn_frame = tk.Frame(body, bg="#e6f2ff")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Make Payment", command=self.process_payment).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Submit Booking", command=self.submit_booking).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Back to Home", command=lambda: controller.show_frame("HomePage")).pack(side="left",
                                                                                                           padx=5)

    def process_payment(self):
        if messagebox.askyesno("Payment", "Proceed with dummy payment of £100?"):
            messagebox.showinfo("Payment", "Payment successful. Confirmation email sent.")
            self.payment_status = "Paid"
        else:
            self.payment_status = "Pending"

    def submit_booking(self):
        name = self.booking_vars["name"].get().strip()
        email = self.booking_vars["email"].get().strip()
        phone = self.booking_vars["phone"].get().strip()
        guests = self.guests_var.get().strip()
        checkin = self.checkin_entry.get().strip()
        checkout = self.checkout_entry.get().strip()
        room_type = self.room_type_var.get().strip()
        special_req = self.special_req.get().strip()
        payment_status = getattr(self, "payment_status", "Pending")
        if not (name and email and phone and guests and checkin and checkout and room_type):
            messagebox.showerror("Error", "Please fill in all mandatory fields marked with *.")
            return
        if not validate_email(email):
            messagebox.showerror("Error", "Invalid email format.")
            return
        if not validate_phone(phone):
            messagebox.showerror("Error", "Phone must be in format 000000-0000.")
            return
        if not (validate_date(checkin) and validate_date(checkout)):
            messagebox.showerror("Error", "Dates must be in YYYY-MM-DD format.")
            return
        if not validate_dates(checkin, checkout):
            messagebox.showerror("Error", "Check-out date must be after check-in date.")
            return
        try:
            conn = sqlite3.connect('ocean_heaven.db')
            c = conn.cursor()
            c.execute('''INSERT INTO bookings (name, email, phone, checkin, checkout, guests, room_type, special_requests, payment_status)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (name, email, phone, checkin, checkout, int(guests), room_type, special_req, payment_status))
            conn.commit()
            conn.close()
            self.controller.send_dummy_email("Booking Confirmation",
                                             f"Dear {name}, your booking for a {room_type} room has been confirmed.")
            messagebox.showinfo("Success", "Booking submitted successfully!")
            self.clear_form()
        except Exception as e:
            messagebox.showerror("Database Error", str(e))

    def clear_form(self):
        for var in self.booking_vars.values():
            var.set("")
        self.guests_var.set("1")
        self.checkin_entry.delete(0, tk.END)
        self.checkout_entry.delete(0, tk.END)
        self.room_type_var.set("")
        self.special_req.set("")


# -------------------- Login, Registration, Forgot Password --------------------
class LoginPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="User Login", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        form = tk.Frame(body, bg="#e6f2ff")
        form.pack(pady=10)
        tk.Label(form, text="Username:", bg="#e6f2ff").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.username_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        tk.Label(form, text="Password:", bg="#e6f2ff").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.password_var, show="*", width=30).grid(row=1, column=1, padx=5, pady=5)
        btn_frame = tk.Frame(body, bg="#e6f2ff")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Login as Customer", command=lambda: self.perform_login("customer")).pack(
            side="left", padx=5)
        ttk.Button(btn_frame, text="Login as Admin", command=lambda: self.perform_login("admin")).pack(side="left",
                                                                                                       padx=5)
        ttk.Button(btn_frame, text="Login as Employee", command=lambda: self.perform_login("employee")).pack(
            side="left", padx=5)
        ttk.Button(body, text="Forgot Password", command=lambda: controller.show_frame("ForgotPasswordPage")).pack(
            pady=5)
        ttk.Button(body, text="Back to Home", command=lambda: controller.show_frame("HomePage")).pack(pady=5)

    def perform_login(self, expected_role):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Fill in username and password.")
            return
        try:
            conn = sqlite3.connect('ocean_heaven.db')
            c = conn.cursor()
            c.execute("SELECT username, password, role FROM users WHERE username=?", (username,))
            result = c.fetchone()
            conn.close()
            if result:
                stored_user, stored_pass, role = result
                if hash_password(password) == stored_pass and role.lower() == expected_role.lower():
                    messagebox.showinfo("Success", f"Logged in as {role}")
                    self.controller.current_user = username
                    if role.lower() == "admin":
                        self.controller.show_frame("AdminDashboard")
                    elif role.lower() == "employee":
                        self.controller.show_frame("EmployeeDashboardPage")
                    else:
                        self.controller.show_frame("CustomerDashboardPage")
                else:
                    messagebox.showerror("Error", "Invalid credentials or role mismatch.")
            else:
                messagebox.showinfo("Demo Mode", f"Logged in as {expected_role} (demo mode)")
                if expected_role.lower() == "admin":
                    self.controller.show_frame("AdminDashboard")
                elif expected_role.lower() == "employee":
                    self.controller.show_frame("EmployeeDashboardPage")
                else:
                    self.controller.show_frame("CustomerDashboardPage")
        except Exception as e:
            messagebox.showerror("Database Error", str(e))


class RegisterPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="User Registration", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        form = tk.Frame(body, bg="#e6f2ff", bd=2, relief="groove")
        form.pack(pady=10, padx=10)
        fields = [("Username*", "username"), ("Password*", "password"), ("Confirm Password*", "confirm"),
                  ("Email*", "email"), ("Phone (000000-0000)*", "phone")]
        self.reg_vars = {}
        for idx, (lbl, key) in enumerate(fields):
            tk.Label(form, text=lbl, bg="#e6f2ff").grid(row=idx, column=0, sticky="e", padx=5, pady=5)
            var = tk.StringVar()
            self.reg_vars[key] = var
            show = "*" if "Password" in lbl else None
            ttk.Entry(form, textvariable=var, width=30, show=show).grid(row=idx, column=1, padx=5, pady=5)
        ttk.Button(form, text="Send 2FA Code", command=self.send_two_factor).grid(row=5, column=0, padx=5, pady=5)
        tk.Label(form, text="Enter 2FA Code*", bg="#e6f2ff").grid(row=5, column=1, sticky="e", padx=5, pady=5)
        self.twofa_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.twofa_var, width=15).grid(row=5, column=2, padx=5, pady=5)
        tk.Label(form, text="Confirm 2FA Code*", bg="#e6f2ff").grid(row=6, column=0, sticky="e", padx=5, pady=5)
        self.twofa_confirm_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.twofa_confirm_var, width=15).grid(row=6, column=1, padx=5, pady=5)
        ttk.Button(body, text="Sign Up", command=self.perform_register).pack(pady=10)
        ttk.Button(body, text="Back to Login", command=lambda: controller.show_frame("LoginPage")).pack(pady=5)

    def send_two_factor(self):
        code = generate_two_factor_code()
        self.controller.two_factor_code = code
        self.controller.send_dummy_email("Your 2FA Code", f"Your two-factor authentication code is: {code}")
        messagebox.showinfo("2FA", "2FA code sent to your email.")

    def perform_register(self):
        username = self.reg_vars["username"].get().strip()
        password = self.reg_vars["password"].get().strip()
        confirm = self.reg_vars["confirm"].get().strip()
        email = self.reg_vars["email"].get().strip()
        phone = self.reg_vars["phone"].get().strip()
        twofa = self.twofa_var.get().strip()
        twofa_confirm = self.twofa_confirm_var.get().strip()
        if not (username and password and confirm and email and phone and twofa and twofa_confirm):
            messagebox.showerror("Error", "Please fill in all mandatory fields.")
            return
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        if twofa != twofa_confirm:
            messagebox.showerror("Error", "2FA codes do not match.")
            return
        if twofa != self.controller.two_factor_code:
            messagebox.showerror("Error", "Invalid 2FA code.")
            return
        if not validate_email(email):
            messagebox.showerror("Error", "Invalid email format.")
            return
        if not validate_phone(phone):
            messagebox.showerror("Error", "Phone must be in the format 000000-0000.")
            return
        try:
            conn = sqlite3.connect('ocean_heaven.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, email, phone, role) VALUES (?, ?, ?, ?, 'customer')",
                      (username, hash_password(password), email, phone))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Registered successfully! Please login.")
            self.controller.show_frame("LoginPage")
        except Exception as e:
            messagebox.showerror("Database Error", str(e))


class ForgotPasswordPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Forgot Password", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        form = tk.Frame(body, bg="#e6f2ff")
        form.pack(pady=10)
        tk.Label(form, text="Enter your username:", bg="#e6f2ff").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.username_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(body, text="Send Reset Link", command=self.send_reset).pack(pady=10)
        ttk.Button(body, text="Back to Login", command=lambda: controller.show_frame("LoginPage")).pack(pady=5)

    def send_reset(self):
        username = self.username_var.get().strip()
        if not username:
            messagebox.showerror("Error", "Enter your username.")
            return
        self.controller.send_dummy_email("Password Reset",
                                         f"Dear {username}, click the link to reset your password (simulation).")
        messagebox.showinfo("Reset", "A password reset link has been sent to your email.")


# -------------------- Contact Us Page --------------------
class ContactPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Contact Us", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        form = tk.Frame(body, bg="#e6f2ff", bd=2, relief="groove")
        form.pack(pady=10, padx=10)
        tk.Label(form, text="Your Name:", bg="#e6f2ff").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.name_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.name_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        tk.Label(form, text="Email:", bg="#e6f2ff").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.email_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.email_var, width=30).grid(row=1, column=1, padx=5, pady=5)
        tk.Label(form, text="Phone:", bg="#e6f2ff").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.phone_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.phone_var, width=30).grid(row=2, column=1, padx=5, pady=5)
        tk.Label(form, text="Message:", bg="#e6f2ff").grid(row=3, column=0, sticky="ne", padx=5, pady=5)
        self.message_text = tk.Text(form, width=30, height=5, bd=2, relief="solid")
        self.message_text.grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(body, text="Submit Inquiry", command=self.submit_contact).pack(pady=10)
        ttk.Button(body, text="Back to Home", command=lambda: controller.show_frame("HomePage")).pack(pady=5)

    def submit_contact(self):
        name = self.name_var.get().strip()
        email = self.email_var.get().strip()
        phone = self.phone_var.get().strip()
        message = self.message_text.get("1.0", tk.END).strip()
        if not (name and email and phone and message):
            messagebox.showerror("Error", "Please fill in all fields.")
            return
        if not validate_email(email):
            messagebox.showerror("Error", "Invalid email format.")
            return
        if not validate_phone(phone):
            messagebox.showerror("Error", "Phone must be in format 000000-0000.")
            return
        try:
            conn = sqlite3.connect('ocean_heaven.db')
            c = conn.cursor()
            c.execute("INSERT INTO contacts (name, email, phone, message) VALUES (?, ?, ?, ?)",
                      (name, email, phone, message))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Your message has been sent!")
        except Exception as e:
            messagebox.showerror("Database Error", str(e))


# -------------------- Room Selection Page --------------------
class RoomSelectionPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Our Rooms", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        self.room_listbox = tk.Listbox(body, width=60, height=10, bd=2, relief="solid")
        rooms = [
            "Room 101 - Single - £100/night | Wi-Fi, TV, A/C",
            "Room 102 - Double - £150/night | Wi-Fi, TV, Mini Bar",
            "Room 201 - Suite - £250/night | Wi-Fi, TV, A/C, Mini Bar, Balcony",
            "Room 202 - Single - £100/night | Wi-Fi, TV",
            "Room 203 - Double - £150/night | Wi-Fi, A/C, TV"
        ]
        for room in rooms:
            self.room_listbox.insert(tk.END, room)
        self.room_listbox.pack(pady=10)
        ttk.Button(body, text="Select Room", command=self.select_room).pack(pady=5)
        ttk.Button(body, text="Back to Home", command=lambda: controller.show_frame("HomePage")).pack(pady=5)

    def select_room(self):
        selected = self.room_listbox.get(tk.ACTIVE)
        if selected:
            messagebox.showinfo("Room Selected", f"You selected: {selected}")
        else:
            messagebox.showerror("Error", "No room selected.")


# -------------------- Feedback Page --------------------
class FeedbackPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Feedback & Reviews", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        form = tk.Frame(body, bg="#e6f2ff", bd=2, relief="groove")
        form.pack(pady=10, padx=10)
        tk.Label(form, text="Your Name:", bg="#e6f2ff").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.fb_name = tk.StringVar()
        ttk.Entry(form, textvariable=self.fb_name, width=30).grid(row=0, column=1, padx=5, pady=5)
        tk.Label(form, text="Room ID:", bg="#e6f2ff").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.fb_room = tk.StringVar()
        ttk.Entry(form, textvariable=self.fb_room, width=30).grid(row=1, column=1, padx=5, pady=5)
        tk.Label(form, text="Rating (1-5):", bg="#e6f2ff").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.fb_rating = tk.IntVar(value=1)
        ttk.Spinbox(form, from_=1, to=5, textvariable=self.fb_rating, width=5).grid(row=2, column=1, sticky="w", padx=5,
                                                                                    pady=5)
        tk.Label(form, text="Comments:", bg="#e6f2ff").grid(row=3, column=0, sticky="ne", padx=5, pady=5)
        self.fb_comments = tk.Text(form, width=30, height=5, bd=2, relief="solid")
        self.fb_comments.grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(body, text="Submit Feedback", command=self.submit_feedback).pack(pady=10)
        ttk.Button(body, text="Back to Home", command=lambda: controller.show_frame("HomePage")).pack(pady=5)

    def submit_feedback(self):
        name = self.fb_name.get().strip()
        room = self.fb_room.get().strip()
        rating = self.fb_rating.get()
        comments = self.fb_comments.get("1.0", tk.END).strip()
        if not (name and room and rating):
            messagebox.showerror("Error", "Please fill in all mandatory fields.")
            return
        try:
            conn = sqlite3.connect('ocean_heaven.db')
            c = conn.cursor()
            c.execute("INSERT INTO feedback (customer_name, room_id, rating, comments) VALUES (?, ?, ?, ?)",
                      (name, room, rating, comments))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Feedback submitted. Thank you!")
            self.fb_name.set("")
            self.fb_room.set("")
            self.fb_rating.set(1)
            self.fb_comments.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Database Error", str(e))


# -------------------- Customer Dashboard --------------------
class CustomerDashboardPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Customer Dashboard", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        btn_frame = tk.Frame(body, bg="#e6f2ff")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Book a Room", command=lambda: controller.show_frame("BookingPage")).pack(
            side="left", padx=5)
        ttk.Button(btn_frame, text="Restaurant Reservations",
                   command=lambda: controller.show_frame("CustomerRestaurantPage")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Book Activities",
                   command=lambda: controller.show_frame("CustomerActivitiesPage")).pack(side="left", padx=5)
        ttk.Button(body, text="Logout", command=lambda: controller.show_frame("HomePage")).pack(pady=5)


# -------------------- Customer Restaurant Page --------------------
class CustomerRestaurantPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Restaurant Reservations", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        tk.Label(body, text="Reserve a table at our award-winning restaurant.", bg="#e6f2ff").pack(pady=5)
        ttk.Button(body, text="Book Table", command=self.book_table).pack(pady=5)
        ttk.Button(body, text="Back to Dashboard", command=lambda: controller.show_frame("CustomerDashboardPage")).pack(
            pady=5)

    def book_table(self):
        messagebox.showinfo("Restaurant Reservation", "Your table has been reserved. Confirmation email sent.")
        self.controller.send_dummy_email("Restaurant Reservation", "Your restaurant table reservation is confirmed.")


# -------------------- Customer Activities Page --------------------
class CustomerActivitiesPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Activity Bookings", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        tk.Label(body, text="Book exciting activities during your stay.", bg="#e6f2ff").pack(pady=5)
        ttk.Button(body, text="Book Activity", command=self.book_activity).pack(pady=5)
        ttk.Button(body, text="Back to Dashboard", command=lambda: controller.show_frame("CustomerDashboardPage")).pack(
            pady=5)

    def book_activity(self):
        messagebox.showinfo("Activity Booking", "Your activity has been booked. Confirmation email sent.")
        self.controller.send_dummy_email("Activity Booking", "Your activity booking is confirmed.")


# -------------------- Admin Dashboard --------------------
class AdminDashboard(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Admin Dashboard", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        ttk.Button(body, text="Manage Employees", command=lambda: controller.show_frame("EmployeeManagement")).pack(
            pady=5)
        ttk.Button(body, text="Assign Shifts", command=lambda: controller.show_frame("ShiftAssignmentPage")).pack(
            pady=5)
        ttk.Button(body, text="Logout", command=lambda: controller.show_frame("HomePage")).pack(pady=5)


# -------------------- Employee Management Page (Admin) --------------------
class EmployeeManagement(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True, fill="both")
        title = tk.Label(body, text="Employee Management", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        self.tree = ttk.Treeview(body, columns=("ID", "Name", "Role", "Shift"), show="headings")
        for col in ("ID", "Name", "Role", "Shift"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180)
        self.tree.pack(pady=10, padx=10, fill="both", expand=True)
        self.load_employees()
        btn_frame = tk.Frame(body, bg="#e6f2ff")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Refresh Data", command=self.load_employees).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Back to Dashboard", command=lambda: controller.show_frame("AdminDashboard")).pack(
            side="left", padx=5)

    def load_employees(self):
        self.tree.delete(*self.tree.get_children())
        conn = sqlite3.connect('ocean_heaven.db')
        c = conn.cursor()
        c.execute("SELECT id, name, role, shift FROM employees")
        for row in c.fetchall():
            self.tree.insert("", "end", values=row)
        conn.close()


# -------------------- Shift Assignment Page (Admin) --------------------
class ShiftAssignmentPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True, fill="both")
        title = tk.Label(body, text="Shift Assignment", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        form = tk.Frame(body, bg="#e6f2ff", bd=2, relief="groove")
        form.pack(pady=10, padx=10)
        tk.Label(form, text="Employee Name:", bg="#e6f2ff").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.emp_name_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.emp_name_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        tk.Label(form, text="Shift Details:", bg="#e6f2ff").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.shift_details_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.shift_details_var, width=30).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(form, text="Assign Shift", command=self.assign_shift).grid(row=2, column=0, columnspan=2, pady=10)
        self.tree = ttk.Treeview(body, columns=("ID", "Name", "Role", "Shift"), show="headings")
        for col in ("ID", "Name", "Role", "Shift"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        self.tree.pack(pady=10, padx=10, fill="both", expand=True)
        ttk.Button(body, text="Refresh Data", command=self.load_employees).pack(pady=5)
        ttk.Button(body, text="Back to Dashboard", command=lambda: controller.show_frame("AdminDashboard")).pack(pady=5)
        self.load_employees()

    def assign_shift(self):
        name = self.emp_name_var.get().strip()
        shift = self.shift_details_var.get().strip()
        if not (name and shift):
            messagebox.showerror("Error", "Please enter both employee name and shift details.")
            return
        try:
            conn = sqlite3.connect('ocean_heaven.db')
            c = conn.cursor()
            c.execute("SELECT id FROM employees WHERE name=?", (name,))
            result = c.fetchone()
            if result:
                c.execute("UPDATE employees SET shift=? WHERE name=?", (shift, name))
            else:
                c.execute("INSERT INTO employees (name, role, shift) VALUES (?, ?, ?)", (name, "Employee", shift))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Shift assigned successfully!")
            self.emp_name_var.set("")
            self.shift_details_var.set("")
            self.load_employees()
        except Exception as e:
            messagebox.showerror("Database Error", str(e))

    def load_employees(self):
        self.tree.delete(*self.tree.get_children())
        conn = sqlite3.connect('ocean_heaven.db')
        c = conn.cursor()
        c.execute("SELECT id, name, role, shift FROM employees")
        for row in c.fetchall():
            self.tree.insert("", "end", values=row)
        conn.close()


# -------------------- Employee Dashboard --------------------
class EmployeeDashboardPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Employee Dashboard", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        btn_frame = tk.Frame(body, bg="#e6f2ff")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Guest Support", command=lambda: controller.show_frame("GuestSupportPage")).pack(
            side="left", padx=5)
        ttk.Button(btn_frame, text="Manage Bookings", command=lambda: controller.show_frame("SearchBookingsPage")).pack(
            side="left", padx=5)
        ttk.Button(btn_frame, text="Cleaning Tasks", command=lambda: controller.show_frame("EmployeeTasksPage")).pack(
            side="left", padx=5)
        ttk.Button(body, text="Logout", command=lambda: controller.show_frame("HomePage")).pack(pady=5)


# -------------------- Employee Tasks Page --------------------
class EmployeeTasksPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Employee Cleaning Tasks", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        self.rooms_status = {
            "Room 101": "Not Cleaned",
            "Room 102": "Not Cleaned",
            "Room 201": "Not Cleaned",
            "Room 202": "Not Cleaned",
            "Room 203": "Not Cleaned"
        }
        container = tk.Frame(body, bg="#e6f2ff")
        container.pack(pady=10)
        self.room_vars = {}
        self.room_status_labels = {}
        for room in self.rooms_status:
            row = tk.Frame(container, bg="#e6f2ff")
            row.pack(fill="x", padx=5, pady=2)
            tk.Label(row, text=room, width=15, bg="#e6f2ff").pack(side="left")
            status_lbl = tk.Label(row, text=self.rooms_status[room], width=15, bg="#e6f2ff")
            status_lbl.pack(side="left")
            var = tk.IntVar()
            self.room_vars[room] = var
            ttk.Checkbutton(row, variable=var, command=lambda r=room: self.toggle_status(r)).pack(side="left")
            self.room_status_labels[room] = status_lbl
        ttk.Button(body, text="Submit Room Status", command=self.submit_status).pack(pady=10)
        ttk.Button(body, text="Back to Dashboard", command=lambda: controller.show_frame("EmployeeDashboardPage")).pack(
            pady=5)

    def toggle_status(self, room):
        self.rooms_status[room] = "Cleaned" if self.room_vars[room].get() == 1 else "Not Cleaned"
        self.room_status_labels[room].config(text=self.rooms_status[room])

    def submit_status(self):
        messagebox.showinfo("Success", "Room statuses updated.")


# -------------------- Guest Support Page (Employee) --------------------
class GuestSupportPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True, fill="both")
        title = tk.Label(body, text="Guest Support - Special Requests", font=("Arial", 22, "bold"), bg="#e6f2ff",
                         fg="#003366")
        title.pack(pady=10)
        self.tree = ttk.Treeview(body, columns=("ID", "Name", "Special Requests"), show="headings")
        for col in ("ID", "Name", "Special Requests"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200)
        self.tree.pack(pady=10, padx=10, fill="both", expand=True)
        ttk.Button(body, text="Refresh", command=self.load_special_requests).pack(pady=5)
        ttk.Button(body, text="Back to Dashboard", command=lambda: controller.show_frame("EmployeeDashboardPage")).pack(
            pady=5)
        self.load_special_requests()

    def load_special_requests(self):
        self.tree.delete(*self.tree.get_children())
        conn = sqlite3.connect('ocean_heaven.db')
        c = conn.cursor()
        c.execute(
            "SELECT id, name, special_requests FROM bookings WHERE special_requests IS NOT NULL AND TRIM(special_requests) != ''")
        for row in c.fetchall():
            self.tree.insert("", "end", values=row)
        conn.close()


# -------------------- Search Bookings Page --------------------
class SearchBookingsPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Search Room Availability", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        self.search_var = tk.StringVar()
        search_frame = tk.Frame(body, bg="#e6f2ff")
        search_frame.pack(pady=5)
        tk.Label(search_frame, text="Enter Room Type: ", bg="#e6f2ff").pack(side="left")
        ttk.Combobox(search_frame, textvariable=self.search_var, values=["Single", "Double", "Suite"], width=20).pack(
            side="left", padx=5)
        ttk.Button(search_frame, text="Search", command=self.search_rooms).pack(side="left", padx=5)
        container = tk.Frame(body, bg="#e6f2ff")
        container.pack(expand=True, fill="both", pady=10)
        self.tree = ttk.Treeview(container, columns=(
        "ID", "Name", "Email", "Phone", "Checkin", "Checkout", "Guests", "Room", "Payment"), show="headings")
        for col in ("ID", "Name", "Email", "Phone", "Checkin", "Checkout", "Guests", "Room", "Payment"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        ttk.Button(body, text="Back to Home", command=lambda: controller.show_frame("HomePage")).pack(pady=5)

    def search_rooms(self):
        room_type = self.search_var.get().strip()
        self.tree.delete(*self.tree.get_children())
        try:
            conn = sqlite3.connect('ocean_heaven.db')
            c = conn.cursor()
            c.execute(
                "SELECT id, name, email, phone, checkin, checkout, guests, room_type, payment_status FROM bookings WHERE room_type LIKE ?",
                ('%' + room_type + '%',))
            for row in c.fetchall():
                self.tree.insert("", "end", values=row)
            conn.close()
        except Exception as e:
            messagebox.showerror("Database Error", str(e))


# -------------------- Customer Dashboard Page --------------------
class CustomerDashboardPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Customer Dashboard", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        btn_frame = tk.Frame(body, bg="#e6f2ff")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Book a Room", command=lambda: controller.show_frame("BookingPage")).pack(
            side="left", padx=5)
        ttk.Button(btn_frame, text="Restaurant Reservations",
                   command=lambda: controller.show_frame("CustomerRestaurantPage")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Book Activities",
                   command=lambda: controller.show_frame("CustomerActivitiesPage")).pack(side="left", padx=5)
        ttk.Button(body, text="Logout", command=lambda: controller.show_frame("HomePage")).pack(pady=5)


# -------------------- Customer Restaurant Page --------------------
class CustomerRestaurantPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Restaurant Reservations", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        tk.Label(body, text="Reserve a table at our award-winning restaurant.", bg="#e6f2ff").pack(pady=5)
        ttk.Button(body, text="Book Table", command=self.book_table).pack(pady=5)
        ttk.Button(body, text="Back to Dashboard", command=lambda: controller.show_frame("CustomerDashboardPage")).pack(
            pady=5)

    def book_table(self):
        messagebox.showinfo("Restaurant Reservation", "Your table has been reserved. Confirmation email sent.")
        self.controller.send_dummy_email("Restaurant Reservation", "Your restaurant table reservation is confirmed.")


# -------------------- Customer Activities Page --------------------
class CustomerActivitiesPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Activity Bookings", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        tk.Label(body, text="Book exciting activities during your stay.", bg="#e6f2ff").pack(pady=5)
        ttk.Button(body, text="Book Activity", command=self.book_activity).pack(pady=5)
        ttk.Button(body, text="Back to Dashboard", command=lambda: controller.show_frame("CustomerDashboardPage")).pack(
            pady=5)

    def book_activity(self):
        messagebox.showinfo("Activity Booking", "Your activity has been booked. Confirmation email sent.")
        self.controller.send_dummy_email("Activity Booking", "Your activity booking is confirmed.")


# -------------------- Admin Dashboard --------------------
class AdminDashboard(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Admin Dashboard", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        ttk.Button(body, text="Manage Employees", command=lambda: controller.show_frame("EmployeeManagement")).pack(
            pady=5)
        ttk.Button(body, text="Assign Shifts", command=lambda: controller.show_frame("ShiftAssignmentPage")).pack(
            pady=5)
        ttk.Button(body, text="Logout", command=lambda: controller.show_frame("HomePage")).pack(pady=5)


# -------------------- Employee Management Page (Admin) --------------------
class EmployeeManagement(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True, fill="both")
        title = tk.Label(body, text="Employee Management", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        self.tree = ttk.Treeview(body, columns=("ID", "Name", "Role", "Shift"), show="headings")
        for col in ("ID", "Name", "Role", "Shift"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180)
        self.tree.pack(pady=10, padx=10, fill="both", expand=True)
        self.load_employees()
        btn_frame = tk.Frame(body, bg="#e6f2ff")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Refresh Data", command=self.load_employees).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Back to Dashboard", command=lambda: controller.show_frame("AdminDashboard")).pack(
            side="left", padx=5)

    def load_employees(self):
        self.tree.delete(*self.tree.get_children())
        conn = sqlite3.connect('ocean_heaven.db')
        c = conn.cursor()
        c.execute("SELECT id, name, role, shift FROM employees")
        for row in c.fetchall():
            self.tree.insert("", "end", values=row)
        conn.close()


# -------------------- Shift Assignment Page (Admin) --------------------
class ShiftAssignmentPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True, fill="both")
        title = tk.Label(body, text="Shift Assignment", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        form = tk.Frame(body, bg="#e6f2ff", bd=2, relief="groove")
        form.pack(pady=10, padx=10)
        tk.Label(form, text="Employee Name:", bg="#e6f2ff").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.emp_name_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.emp_name_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        tk.Label(form, text="Shift Details:", bg="#e6f2ff").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.shift_details_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.shift_details_var, width=30).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(form, text="Assign Shift", command=self.assign_shift).grid(row=2, column=0, columnspan=2, pady=10)
        self.tree = ttk.Treeview(body, columns=("ID", "Name", "Role", "Shift"), show="headings")
        for col in ("ID", "Name", "Role", "Shift"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        self.tree.pack(pady=10, padx=10, fill="both", expand=True)
        ttk.Button(body, text="Refresh Data", command=self.load_employees).pack(pady=5)
        ttk.Button(body, text="Back to Dashboard", command=lambda: controller.show_frame("AdminDashboard")).pack(pady=5)
        self.load_employees()

    def assign_shift(self):
        name = self.emp_name_var.get().strip()
        shift = self.shift_details_var.get().strip()
        if not (name and shift):
            messagebox.showerror("Error", "Please enter both employee name and shift details.")
            return
        try:
            conn = sqlite3.connect('ocean_heaven.db')
            c = conn.cursor()
            c.execute("SELECT id FROM employees WHERE name=?", (name,))
            result = c.fetchone()
            if result:
                c.execute("UPDATE employees SET shift=? WHERE name=?", (shift, name))
            else:
                c.execute("INSERT INTO employees (name, role, shift) VALUES (?, ?, ?)", (name, "Employee", shift))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Shift assigned successfully!")
            self.emp_name_var.set("")
            self.shift_details_var.set("")
            self.load_employees()
        except Exception as e:
            messagebox.showerror("Database Error", str(e))

    def load_employees(self):
        self.tree.delete(*self.tree.get_children())
        conn = sqlite3.connect('ocean_heaven.db')
        c = conn.cursor()
        c.execute("SELECT id, name, role, shift FROM employees")
        for row in c.fetchall():
            self.tree.insert("", "end", values=row)
        conn.close()


# -------------------- Employee Dashboard --------------------
class EmployeeDashboardPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Employee Dashboard", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        btn_frame = tk.Frame(body, bg="#e6f2ff")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Guest Support", command=lambda: controller.show_frame("GuestSupportPage")).pack(
            side="left", padx=5)
        ttk.Button(btn_frame, text="Manage Bookings", command=lambda: controller.show_frame("SearchBookingsPage")).pack(
            side="left", padx=5)
        ttk.Button(btn_frame, text="Cleaning Tasks", command=lambda: controller.show_frame("EmployeeTasksPage")).pack(
            side="left", padx=5)
        ttk.Button(body, text="Logout", command=lambda: controller.show_frame("HomePage")).pack(pady=5)


# -------------------- Employee Tasks Page --------------------
class EmployeeTasksPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Employee Cleaning Tasks", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        self.rooms_status = {
            "Room 101": "Not Cleaned",
            "Room 102": "Not Cleaned",
            "Room 201": "Not Cleaned",
            "Room 202": "Not Cleaned",
            "Room 203": "Not Cleaned"
        }
        container = tk.Frame(body, bg="#e6f2ff")
        container.pack(pady=10)
        self.room_vars = {}
        self.room_status_labels = {}
        for room in self.rooms_status:
            row = tk.Frame(container, bg="#e6f2ff")
            row.pack(fill="x", padx=5, pady=2)
            tk.Label(row, text=room, width=15, bg="#e6f2ff").pack(side="left")
            status_lbl = tk.Label(row, text=self.rooms_status[room], width=15, bg="#e6f2ff")
            status_lbl.pack(side="left")
            var = tk.IntVar()
            self.room_vars[room] = var
            ttk.Checkbutton(row, variable=var, command=lambda r=room: self.toggle_status(r)).pack(side="left")
            self.room_status_labels[room] = status_lbl
        ttk.Button(body, text="Submit Room Status", command=self.submit_status).pack(pady=10)
        ttk.Button(body, text="Back to Dashboard", command=lambda: controller.show_frame("EmployeeDashboardPage")).pack(
            pady=5)

    def toggle_status(self, room):
        self.rooms_status[room] = "Cleaned" if self.room_vars[room].get() == 1 else "Not Cleaned"
        self.room_status_labels[room].config(text=self.rooms_status[room])

    def submit_status(self):
        messagebox.showinfo("Success", "Room statuses updated.")


# -------------------- Guest Support Page (Employee) --------------------
class GuestSupportPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True, fill="both")
        title = tk.Label(body, text="Guest Support - Special Requests", font=("Arial", 22, "bold"), bg="#e6f2ff",
                         fg="#003366")
        title.pack(pady=10)
        self.tree = ttk.Treeview(body, columns=("ID", "Name", "Special Requests"), show="headings")
        for col in ("ID", "Name", "Special Requests"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200)
        self.tree.pack(pady=10, padx=10, fill="both", expand=True)
        ttk.Button(body, text="Refresh", command=self.load_special_requests).pack(pady=5)
        ttk.Button(body, text="Back to Dashboard", command=lambda: controller.show_frame("EmployeeDashboardPage")).pack(
            pady=5)
        self.load_special_requests()

    def load_special_requests(self):
        self.tree.delete(*self.tree.get_children())
        conn = sqlite3.connect('ocean_heaven.db')
        c = conn.cursor()
        c.execute(
            "SELECT id, name, special_requests FROM bookings WHERE special_requests IS NOT NULL AND TRIM(special_requests) != ''")
        for row in c.fetchall():
            self.tree.insert("", "end", values=row)
        conn.close()


# -------------------- Search Bookings Page --------------------
class SearchBookingsPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Search Room Availability", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        self.search_var = tk.StringVar()
        search_frame = tk.Frame(body, bg="#e6f2ff")
        search_frame.pack(pady=5)
        tk.Label(search_frame, text="Enter Room Type: ", bg="#e6f2ff").pack(side="left")
        ttk.Combobox(search_frame, textvariable=self.search_var, values=["Single", "Double", "Suite"], width=20).pack(
            side="left", padx=5)
        ttk.Button(search_frame, text="Search", command=self.search_rooms).pack(side="left", padx=5)
        container = tk.Frame(body, bg="#e6f2ff")
        container.pack(expand=True, fill="both", pady=10)
        self.tree = ttk.Treeview(container, columns=(
        "ID", "Name", "Email", "Phone", "Checkin", "Checkout", "Guests", "Room", "Payment"), show="headings")
        for col in ("ID", "Name", "Email", "Phone", "Checkin", "Checkout", "Guests", "Room", "Payment"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        ttk.Button(body, text="Back to Home", command=lambda: controller.show_frame("HomePage")).pack(pady=5)

    def search_rooms(self):
        room_type = self.search_var.get().strip()
        self.tree.delete(*self.tree.get_children())
        try:
            conn = sqlite3.connect('ocean_heaven.db')
            c = conn.cursor()
            c.execute(
                "SELECT id, name, email, phone, checkin, checkout, guests, room_type, payment_status FROM bookings WHERE room_type LIKE ?",
                ('%' + room_type + '%',))
            for row in c.fetchall():
                self.tree.insert("", "end", values=row)
            conn.close()
        except Exception as e:
            messagebox.showerror("Database Error", str(e))


# -------------------- Customer Dashboard Page --------------------
class CustomerDashboardPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Customer Dashboard", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        btn_frame = tk.Frame(body, bg="#e6f2ff")
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Book a Room", command=lambda: controller.show_frame("BookingPage")).pack(
            side="left", padx=5)
        ttk.Button(btn_frame, text="Restaurant Reservations",
                   command=lambda: controller.show_frame("CustomerRestaurantPage")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Book Activities",
                   command=lambda: controller.show_frame("CustomerActivitiesPage")).pack(side="left", padx=5)
        ttk.Button(body, text="Logout", command=lambda: controller.show_frame("HomePage")).pack(pady=5)


# -------------------- Customer Restaurant Page --------------------
class CustomerRestaurantPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Restaurant Reservations", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        tk.Label(body, text="Reserve a table at our award-winning restaurant.", bg="#e6f2ff").pack(pady=5)
        ttk.Button(body, text="Book Table", command=self.book_table).pack(pady=5)
        ttk.Button(body, text="Back to Dashboard", command=lambda: controller.show_frame("CustomerDashboardPage")).pack(
            pady=5)

    def book_table(self):
        messagebox.showinfo("Restaurant Reservation", "Your table has been reserved. Confirmation email sent.")
        self.controller.send_dummy_email("Restaurant Reservation", "Your restaurant table reservation is confirmed.")


# -------------------- Customer Activities Page --------------------
class CustomerActivitiesPage(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Activity Bookings", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        tk.Label(body, text="Book exciting activities during your stay.", bg="#e6f2ff").pack(pady=5)
        ttk.Button(body, text="Book Activity", command=self.book_activity).pack(pady=5)
        ttk.Button(body, text="Back to Dashboard", command=lambda: controller.show_frame("CustomerDashboardPage")).pack(
            pady=5)

    def book_activity(self):
        messagebox.showinfo("Activity Booking", "Your activity has been booked. Confirmation email sent.")
        self.controller.send_dummy_email("Activity Booking", "Your activity booking is confirmed.")


# -------------------- Admin Dashboard --------------------
class AdminDashboard(BasePage):
    def __init__(self, parent, controller):
        BasePage.__init__(self, parent, controller)
        body = tk.Frame(self, bg="#e6f2ff")
        body.pack(expand=True)
        title = tk.Label(body, text="Admin Dashboard", font=("Arial", 22, "bold"), bg="#e6f2ff", fg="#003366")
        title.pack(pady=10)
        ttk.Button(body, text="Manage Employees", command=lambda: controller.show_frame("EmployeeManagement")).pack(
            pady=5)
        ttk.Button(body, text="Assign Shifts", command=lambda: controller.show_frame("ShiftAssignmentPage")).pack(
            pady=5)
        ttk.Button(body, text="Logout", command=lambda: controller.show_frame("HomePage")).pack(pady=5)


# -------------------- Main Application --------------------
class OceanHeavenApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ocean Heaven - Hotel Management System")
        self.geometry("900x600")
        self.resizable(False, False)
        self.configure(bg="#e6f2ff")
        self.two_factor_code = None
        self.current_user = None

        container = tk.Frame(self, bg="#e6f2ff")
        container.pack(side="top", fill="both", expand=True)
        self.frames = {}
        pages = (HomePage, BookingPage, LoginPage, RegisterPage, ForgotPasswordPage,
                 ContactPage, RoomSelectionPage, FeedbackPage, CustomerDashboardPage,
                 CustomerRestaurantPage, CustomerActivitiesPage, AdminDashboard, EmployeeManagement,
                 ShiftAssignmentPage, EmployeeDashboardPage, EmployeeTasksPage, GuestSupportPage,
                 SearchBookingsPage)
        for Page in pages:
            page_name = Page.__name__
            frame = Page(parent=container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("HomePage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

    def send_dummy_email(self, subject, content):
        messagebox.showinfo("Email Sent", f"Subject: {subject}\n\n{content}")


# -------------------- Run the Application --------------------
if __name__ == "__main__":
    app = OceanHeavenApp()
    app.mainloop()

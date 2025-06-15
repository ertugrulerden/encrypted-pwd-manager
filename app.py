import flet as ft
import os
import base64
import json
import sqlite3
import random
import string
import re
import logging
import traceback
from datetime import datetime
from encryption_utils import derive_key, encrypt_vault_key, decrypt_vault_key, encrypt_entry, decrypt_entry

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app_debug.log'),
        logging.StreamHandler()
    ]
)

def debug_log(message: str, level: str = "INFO"):
    """Log debug messages with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    
    if level == "ERROR":
        logging.error(log_message)
    elif level == "WARNING":
        logging.warning(log_message)
    elif level == "DEBUG":
        logging.debug(log_message)
    else:
        logging.info(log_message)

def debug_error(e: Exception, context: str = ""):
    """Log error with full traceback and context."""
    error_msg = f"Error in {context}: {str(e)}"
    debug_log(error_msg, "ERROR")
    debug_log(f"Traceback:\n{traceback.format_exc()}", "ERROR")

def debug_state(page: ft.Page, state_name: str, state_value: any):
    """Log state changes."""
    debug_log(f"State Change - {state_name}: {state_value}", "DEBUG")

def debug_operation(operation: str, details: str = ""):
    """Log operation details."""
    debug_log(f"Operation: {operation} - {details}", "DEBUG")

def show_error(page: ft.Page, message: str, is_error: bool = True):
    """Show a consistent error or success message in the app."""
    snack_bar = ft.SnackBar(
        content=ft.Text(
            message,
            color=ft.Colors.WHITE,
            size=16,
            weight=ft.FontWeight.BOLD
        ),
        bgcolor=ft.Colors.RED_400 if is_error else ft.Colors.GREEN_400,
        duration=5000,  # Show for 5 seconds
        action="OK",
        action_color=ft.Colors.WHITE,
        margin=ft.margin.only(bottom=20),
        padding=20,
        dismiss_direction=ft.DismissDirection.DOWN,
    )
    page.snack_bar = snack_bar
    page.snack_bar.open = True
    page.update()

def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength and return (is_valid, error_message).
    Password must:
    - Be at least 8 characters long
    - Contain at least one uppercase letter
    - Contain at least one lowercase letter
    - Contain at least one number
    - Contain at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, ""

def main(page: ft.Page):
    # Page setup
    page.title = "Secure Password Manager"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.window_width = 900
    page.window_height = 1500
    page.window_resizable = True
    page.window_maximizable = True
    page.padding = 30
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.bgcolor = ft.Colors.BLUE_GREY_50
    page.theme = ft.Theme(
        color_scheme_seed=ft.Colors.BLUE,
        visual_density=ft.VisualDensity.COMFORTABLE,
    )
    page.expand = True

    # Initialize app state
    master_password_hash_file = "master_pass.json"
    master_password_data = None
    vault_entries = []
    vault_key = None
    _mp_derived_key_temp = None
    editing_entry_index = -1

    # Database connection
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                salt TEXT NOT NULL,
                iv TEXT NOT NULL
            )
        ''')
    conn.commit()

    def load_master_password_data():
        nonlocal master_password_data
        if os.path.exists(master_password_hash_file):
            try:
                with open(master_password_hash_file, 'r') as f:
                    data = json.load(f)
                    data['hashed_password'] = base64.b64decode(data['hashed_password'])
                    data['salt'] = base64.b64decode(data['salt'])
                    data['encrypted_vault_key'] = base64.b64decode(data['encrypted_vault_key'])
                    data['vk_iv'] = base64.b64decode(data['vk_iv'])
                    master_password_data = data
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Error loading master password data: {e}")
                master_password_data = None
        return master_password_data

    def save_master_password_data(hashed_password_bytes, salt_bytes, encrypted_vk_bytes, vk_iv_bytes):
        nonlocal master_password_data
        data = {
            'hashed_password': base64.b64encode(hashed_password_bytes).decode('utf-8'),
            'salt': base64.b64encode(salt_bytes).decode('utf-8'),
            'encrypted_vault_key': base64.b64encode(encrypted_vk_bytes).decode('utf-8'),
            'vk_iv': base64.b64encode(vk_iv_bytes).decode('utf-8')
        }
        with open(master_password_hash_file, 'w') as f:
            json.dump(data, f)
        master_password_data = {
            'hashed_password': hashed_password_bytes,
            'salt': salt_bytes,
            'encrypted_vault_key': encrypted_vk_bytes,
            'vk_iv': vk_iv_bytes
        }

    def load_vault_entries():
        nonlocal vault_entries
        vault_entries = []
        if not vault_key:
            return

        try:
            cursor.execute('SELECT id, site, username, ciphertext, salt, iv FROM entries')
            rows = cursor.fetchall()
            for row in rows:
                db_id, site, username, ciphertext, salt, iv = row
                vault_entries.append({
                    'id': db_id,
                    'site': site,
                    'username': username,
                    'password_enc': {
                        'ciphertext': ciphertext,
                        'salt': salt,
                        'iv': iv
                    }
                })
        except sqlite3.Error as e:
            page.snack_bar = ft.SnackBar(content=ft.Text(f"Database Error: {e}"))
            page.update()

    # Initialize master password data
    master_password_data = load_master_password_data()

    # Login/Set Password View
    master_password = ft.TextField(
        label="Master Password",
        password=True,
        can_reveal_password=True,
        width=400,
        text_align=ft.TextAlign.CENTER,
        border_radius=10,
        focused_border_color=ft.Colors.BLUE,
        prefix_icon=ft.Icons.LOCK,
        on_submit=lambda e: handle_login() if master_password_data else handle_set_password(),
        error_style=ft.TextStyle(color=ft.Colors.RED),
        helper_text="Enter your master password to continue",
        helper_style=ft.TextStyle(color=ft.Colors.GREY_700),
    )

    def handle_login():
        nonlocal vault_key, _mp_derived_key_temp
        debug_operation("Login Attempt", "Starting login process")
        
        entered_password = master_password.value
        
        # Clear any existing error messages
        page.snack_bar = None
        master_password.error_text = None
        page.update()
        
        if not entered_password:
            debug_log("Login failed - Empty password", "WARNING")
            show_error(page, "❌ Please enter your Master Password.")
            return

        try:
            debug_operation("Login", "Loading stored password data")
            stored_mp_salt = master_password_data['salt']
            stored_hashed_password = master_password_data['hashed_password']
            stored_encrypted_vk = master_password_data['encrypted_vault_key']
            stored_vk_iv = master_password_data['vk_iv']

            debug_operation("Login", "Deriving key from entered password")
            entered_mp_derived_key = derive_key(entered_password, stored_mp_salt)

            if entered_mp_derived_key == stored_hashed_password:
                try:
                    debug_operation("Login", "Decrypting vault key")
                    vault_key = decrypt_vault_key(
                        base64.b64encode(stored_encrypted_vk).decode('utf-8'),
                        base64.b64encode(stored_vk_iv).decode('utf-8'),
                        entered_mp_derived_key
                    )
                    _mp_derived_key_temp = entered_mp_derived_key
                    
                    debug_operation("Login", "Loading vault entries")
                    load_vault_entries()
                    
                    debug_operation("Login", "Showing dashboard")
                    show_dashboard()
                    master_password.value = ""
                    show_error(page, "✅ Login successful!", is_error=False)
                    debug_log("Login successful", "INFO")
                    page.update()
                except Exception as e:
                    debug_error(e, "Login - Decryption")
                    show_error(page, f"❌ Decryption Error: {str(e)}")
                    page.update()
            else:
                debug_log("Login failed - Incorrect password", "WARNING")
                show_error(page, "❌ Incorrect Master Password. Please try again.")
                page.update()
        except Exception as e:
            debug_error(e, "Login - General")
            show_error(page, f"❌ Error during login: {str(e)}")
            page.update()

    def handle_set_password():
        nonlocal vault_key, _mp_derived_key_temp
        debug_operation("Set Password", "Starting password setup")
        
        master_pass = master_password.value
        if not master_pass:
            debug_log("Password setup failed - Empty password", "WARNING")
            show_error(page, "Master Password cannot be empty.")
            return

        # Validate password strength
        debug_operation("Set Password", "Validating password strength")
        is_valid, error_message = validate_password(master_pass)
        if not is_valid:
            debug_log(f"Password setup failed - Weak password: {error_message}", "WARNING")
            show_error(page, error_message)
            return

        try:
            debug_operation("Set Password", "Generating salt and derived key")
            mp_salt = os.urandom(16)
            mp_derived_key = derive_key(master_pass, mp_salt)

            debug_operation("Set Password", "Generating vault key")
            vault_key = os.urandom(32)
            encrypted_vk_data = encrypt_vault_key(vault_key, mp_derived_key)

            debug_operation("Set Password", "Saving master password data")
            save_master_password_data(
                hashed_password_bytes=mp_derived_key,
                salt_bytes=mp_salt,
                encrypted_vk_bytes=base64.b64decode(encrypted_vk_data['ciphertext']),
                vk_iv_bytes=base64.b64decode(encrypted_vk_data['iv'])
            )
            vault_key = vault_key
            _mp_derived_key_temp = mp_derived_key

            debug_operation("Set Password", "Loading vault entries")
            master_password.value = ""
            load_vault_entries()
            show_dashboard()
            show_error(page, "Master password set successfully!", is_error=False)
            debug_log("Password setup successful", "INFO")
            page.update()
        except Exception as e:
            debug_error(e, "Set Password")
            show_error(page, f"Error setting password: {str(e)}")
            page.update()

    # Dashboard View
    def show_dashboard():
        page.clean()
        page.add(
            ft.Container(
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.DASHBOARD, size=32, color=ft.Colors.BLUE),
                                ft.Text("Dashboard", size=32, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
                        ft.Container(height=30),
                        ft.ElevatedButton(
                            "Add New Entry",
                            icon=ft.Icons.ADD,
                            on_click=lambda _: show_add_entry(),
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=10),
                                padding=20,
                            ),
                            width=300,
                        ),
                        ft.Container(height=10),
                        ft.ElevatedButton(
                            "Manage Entries",
                            icon=ft.Icons.LIST_ALT,
                            on_click=lambda _: show_view_entries(),
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=10),
                                padding=20,
                            ),
                            width=300,
                        ),
                        ft.Container(height=10),
                        ft.ElevatedButton(
                            "Generate Password",
                            icon=ft.Icons.PASSWORD,
                            on_click=lambda _: show_generate_password(),
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=10),
                                padding=20,
                            ),
                            width=300,
                        ),
                        ft.Container(height=10),
                        ft.ElevatedButton(
                            "Change Master Password",
                            icon=ft.Icons.LOCK_RESET,
                            on_click=lambda _: show_change_master_password(),
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=10),
                                padding=20,
                            ),
                            width=300,
                        ),
                        ft.Container(height=10),
                        ft.ElevatedButton(
                            "Logout",
                            icon=ft.Icons.LOGOUT,
                            on_click=lambda _: show_login(),
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=10),
                                padding=20,
                                color=ft.Colors.RED,
                            ),
                            width=300,
                        ),
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=40,
                border_radius=20,
                bgcolor=ft.Colors.WHITE,
                shadow=ft.BoxShadow(
                    spread_radius=1,
                    blur_radius=15,
                    color=ft.Colors.BLACK12,
                ),
            )
        )

    # Add Entry View
    def show_add_entry():
        page.clean()
        site_field = ft.TextField(
            label="Site Name",
            width=400,
            text_align=ft.TextAlign.CENTER,
            border_radius=10,
            focused_border_color=ft.Colors.BLUE,
            prefix_icon=ft.Icons.WEB,
        )
        username_field = ft.TextField(
            label="Username",
            width=400,
            text_align=ft.TextAlign.CENTER,
            border_radius=10,
            focused_border_color=ft.Colors.BLUE,
            prefix_icon=ft.Icons.PERSON,
        )
        password_field = ft.TextField(
            label="Password",
            password=True,
            can_reveal_password=True,
            width=400,
            text_align=ft.TextAlign.CENTER,
            border_radius=10,
            focused_border_color=ft.Colors.BLUE,
            prefix_icon=ft.Icons.LOCK,
        )

        def generate_password():
            length = 12
            chars = string.ascii_letters + string.digits + string.punctuation
            new_pass = ''.join(random.choices(chars, k=length))
            password_field.value = new_pass
            page.update()

        def save_entry():
            site = site_field.value.strip()
            username = username_field.value.strip()
            plaintext_password = password_field.value

            if not site or not username or not plaintext_password:
                show_error(page, "Please fill all fields!")
                return

            try:
                encrypted_data = encrypt_entry(plaintext_password, vault_key)
                
                # Ensure proper base64 padding before storing
                def pad_base64(s):
                    padding = 4 - (len(s) % 4)
                    if padding != 4:
                        return s + ('=' * padding)
                    return s
                
                ciphertext = pad_base64(encrypted_data['ciphertext'])
                salt = pad_base64(encrypted_data['salt'])
                iv = pad_base64(encrypted_data['iv'])
                
                cursor.execute('''
                    INSERT INTO entries (site, username, ciphertext, salt, iv)
                    VALUES (?, ?, ?, ?, ?)
                ''', (site, username, ciphertext, salt, iv))
                conn.commit()
                
                new_id = cursor.lastrowid
                vault_entries.append({
                    'id': new_id,
                    'site': site,
                    'username': username,
                    'password_enc': {
                        'ciphertext': ciphertext,
                        'salt': salt,
                        'iv': iv
                    }
                })
                show_error(page, f"Entry for '{site}' saved successfully!", is_error=False)
                page.update()
                show_dashboard()
            except Exception as e:
                show_error(page, f"Error saving entry: {e}")

        page.add(
            ft.Container(
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.ADD_CIRCLE, size=32, color=ft.Colors.BLUE),
                                ft.Text("Add New Entry", size=32, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
                        ft.Container(height=30),
                        site_field,
                        ft.Container(height=10),
                        username_field,
                        ft.Container(height=10),
                        password_field,
                        ft.Container(height=20),
                        ft.Row(
                            [
                                ft.ElevatedButton(
                                    "Generate Password",
                                    icon=ft.Icons.REFRESH,
                                    on_click=lambda _: generate_password(),
                                    style=ft.ButtonStyle(
                                        shape=ft.RoundedRectangleBorder(radius=10),
                                        padding=20,
                                    ),
                                ),
                                ft.ElevatedButton(
                                    "Save Entry",
                                    icon=ft.Icons.SAVE,
                                    on_click=lambda _: save_entry(),
                                    style=ft.ButtonStyle(
                                        shape=ft.RoundedRectangleBorder(radius=10),
                                        padding=20,
                                    ),
                                ),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                            spacing=20,
                        ),
                        ft.ElevatedButton(
                            "Back to Dashboard",
                            icon=ft.Icons.ARROW_BACK,
                            on_click=lambda _: show_dashboard(),
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=10),
                                padding=20,
                            ),
                        ),
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=40,
                border_radius=20,
                bgcolor=ft.Colors.WHITE,
                shadow=ft.BoxShadow(
                    spread_radius=1,
                    blur_radius=15,
                    color=ft.Colors.BLACK12,
                ),
            )
        )

    # View Entries View
    def show_view_entries():
        page.clean()
        entries_list = ft.ListView(
            expand=True,
            spacing=10,
            padding=20,
        )

        # Dictionary to store visibility state for each entry
        password_states = {}

        def toggle_password_visibility(idx, text_field):
            print(f"Toggle clicked for entry {idx}")
            try:
                # Initialize state if not exists
                if idx not in password_states:
                    password_states[idx] = False
                
                # Toggle state
                password_states[idx] = not password_states[idx]
                print(f"New visibility state for entry {idx}: {password_states[idx]}")
                
                entry = vault_entries[idx]
                print(f"Decrypting password for entry: {entry['site']}")
                
                # Ensure proper base64 padding
                ciphertext = entry['password_enc']['ciphertext']
                salt = entry['password_enc']['salt']
                iv = entry['password_enc']['iv']
                
                # Add padding if needed
                def pad_base64(s):
                    padding = 4 - (len(s) % 4)
                    if padding != 4:
                        return s + ('=' * padding)
                    return s
                
                ciphertext = pad_base64(ciphertext)
                salt = pad_base64(salt)
                iv = pad_base64(iv)
                
                print(f"Base64 strings padded - Ciphertext: {ciphertext}, Salt: {salt}, IV: {iv}")
                
                decrypted_pass = decrypt_entry(
                    ciphertext,
                    salt,
                    iv,
                    vault_key
                )
                print(f"Password decrypted successfully")
                
                # Update text field
                text_field.value = decrypted_pass if password_states[idx] else "••••••••"
                print(f"Text field updated with: {'password' if password_states[idx] else 'dots'}")
                
                # Update icon
                visibility_button.icon = ft.Icons.VISIBILITY_OFF if password_states[idx] else ft.Icons.VISIBILITY
                print(f"Icon updated to: {'visibility_off' if password_states[idx] else 'visibility'}")
                
                page.update()
                print("Page updated")
            except Exception as e:
                print(f"Error in toggle_password_visibility: {str(e)}")
                page.snack_bar = ft.SnackBar(content=ft.Text(f"Error decrypting password: {e}"))
                page.update()

        def delete_entry(index):
            print(f"Deleting entry at index {index}")
            try:
                entry_to_delete = vault_entries[index]
                print(f"Deleting entry: {entry_to_delete['site']}")
                
                cursor.execute('DELETE FROM entries WHERE id = ?', (entry_to_delete['id'],))
                conn.commit()
                
                # Remove from vault_entries
                vault_entries.pop(index)
                print(f"Entry deleted successfully")
                
                # Refresh the view
                show_view_entries()
            except Exception as e:
                print(f"Error deleting entry: {str(e)}")
                page.snack_bar = ft.SnackBar(content=ft.Text(f"Error deleting entry: {e}"))
                page.update()

        for i, entry in enumerate(vault_entries):
            print(f"Creating entry view for: {entry['site']}")
            password_text = ft.Text("••••••••")
            visibility_button = ft.IconButton(
                icon=ft.Icons.VISIBILITY,
                on_click=lambda _, idx=i, text=password_text: toggle_password_visibility(idx, text),
                tooltip="Toggle Password Visibility",
            )
            
            # Create a delete button with the correct index
            delete_btn = ft.ElevatedButton(
                "Delete",
                icon=ft.Icons.DELETE,
                on_click=lambda _, idx=i: delete_entry(idx),
                style=ft.ButtonStyle(
                    shape=ft.RoundedRectangleBorder(radius=10),
                    color=ft.Colors.RED,
                ),
            )
            
            entries_list.controls.append(
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Row(
                                [
                                    ft.Icon(ft.Icons.WEB, color=ft.Colors.BLUE),
                                    ft.Text(entry['site'], size=20, weight=ft.FontWeight.BOLD),
                                ],
                            ),
                            ft.Text(f"Username: {entry['username']}"),
                            ft.Row(
                                [
                                    ft.Text("Password: "),
                                    password_text,
                                    visibility_button,
                                    ft.IconButton(
                                        icon=ft.Icons.COPY,
                                        on_click=lambda _, idx=i: copy_password(idx),
                                        tooltip="Copy Password",
                                    ),
                                ],
                            ),
                            ft.Row(
                                [
                                    ft.ElevatedButton(
                                        "Edit",
                                        icon=ft.Icons.EDIT,
                                        on_click=lambda _, idx=i: show_edit_entry(idx),
                                        style=ft.ButtonStyle(
                                            shape=ft.RoundedRectangleBorder(radius=10),
                                        ),
                                    ),
                                    delete_btn,
                                ],
                                alignment=ft.MainAxisAlignment.END,
                            ),
                        ],
                    ),
                    padding=20,
                    border_radius=10,
                    bgcolor=ft.Colors.WHITE,
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=ft.Colors.BLACK12,
                    ),
                )
            )
            print(f"Entry view created for: {entry['site']}")

        page.add(
            ft.Container(
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.LIST_ALT, size=32, color=ft.Colors.BLUE),
                                ft.Text("Manage Entries", size=32, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
                        ft.Container(height=20),
                        entries_list,
                        ft.ElevatedButton(
                            "Back to Dashboard",
                            icon=ft.Icons.ARROW_BACK,
                            on_click=lambda _: show_dashboard(),
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=10),
                                padding=20,
                            ),
                        ),
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=40,
                border_radius=20,
                bgcolor=ft.Colors.WHITE,
                shadow=ft.BoxShadow(
                    spread_radius=1,
                    blur_radius=15,
                    color=ft.Colors.BLACK12,
                ),
            )
        )

    def show_password(index):
        try:
            entry = vault_entries[index]
            decrypted_pass = decrypt_entry(
                entry['password_enc']['ciphertext'],
                entry['password_enc']['salt'],
                entry['password_enc']['iv'],
                vault_key
            )
            page.snack_bar = ft.SnackBar(content=ft.Text(f"Password: {decrypted_pass}"))
            page.update()
        except Exception as e:
            page.snack_bar = ft.SnackBar(content=ft.Text(f"Error decrypting password: {e}"))
            page.update()

    def copy_password(index):
        try:
            entry = vault_entries[index]
            decrypted_pass = decrypt_entry(
                entry['password_enc']['ciphertext'],
                entry['password_enc']['salt'],
                entry['password_enc']['iv'],
                vault_key
            )
            page.set_clipboard(decrypted_pass)
            page.snack_bar = ft.SnackBar(content=ft.Text("Password copied to clipboard!"))
            page.update()
        except Exception as e:
            page.snack_bar = ft.SnackBar(content=ft.Text(f"Error copying password: {e}"))
            page.update()

    def delete_entry(index):
        entry_to_delete = vault_entries[index]
        try:
            cursor.execute('DELETE FROM entries WHERE id = ?', (entry_to_delete['id'],))
            conn.commit()
            del vault_entries[index]
            show_view_entries()
        except sqlite3.Error as e:
            page.snack_bar = ft.SnackBar(content=ft.Text(f"Error deleting entry: {e}"))
            page.update()

    # Generate Password View
    def show_generate_password():
        page.clean()
        generated_password = ft.TextField(
            label="Generated Password",
            width=400,
            text_align=ft.TextAlign.CENTER,
            border_radius=10,
            focused_border_color=ft.Colors.BLUE,
            prefix_icon=ft.Icons.PASSWORD,
            read_only=True,
        )

        def generate():
            length = 12
            chars = string.ascii_letters + string.digits + string.punctuation
            new_pass = ''.join(random.choices(chars, k=length))
            generated_password.value = new_pass
            page.update()

        def copy_to_clipboard():
            if generated_password.value:
                page.set_clipboard(generated_password.value)
                page.snack_bar = ft.SnackBar(
                    content=ft.Text("Password copied to clipboard!"),
                    bgcolor=ft.Colors.GREEN,
                )
                page.update()

        page.add(
            ft.Container(
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.PASSWORD, size=32, color=ft.Colors.BLUE),
                                ft.Text("Generate Password", size=32, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
                        ft.Container(height=30),
                        generated_password,
                        ft.Container(height=20),
                        ft.Row(
                            [
                                ft.ElevatedButton(
                                    "Generate",
                                    icon=ft.Icons.REFRESH,
                                    on_click=lambda _: generate(),
                                    style=ft.ButtonStyle(
                                        shape=ft.RoundedRectangleBorder(radius=10),
                                        padding=20,
                                    ),
                                ),
                                ft.ElevatedButton(
                                    "Copy",
                                    icon=ft.Icons.COPY,
                                    on_click=lambda _: copy_to_clipboard(),
                                    style=ft.ButtonStyle(
                                        shape=ft.RoundedRectangleBorder(radius=10),
                                        padding=20,
                                    ),
                                ),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                            spacing=20,
                        ),
                        ft.ElevatedButton(
                            "Back to Dashboard",
                            icon=ft.Icons.ARROW_BACK,
                            on_click=lambda _: show_dashboard(),
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=10),
                                padding=20,
                            ),
                        ),
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=40,
                border_radius=20,
                bgcolor=ft.Colors.WHITE,
                shadow=ft.BoxShadow(
                    spread_radius=1,
                    blur_radius=15,
                    color=ft.Colors.BLACK12,
                ),
            )
        )

    # Change Master Password View
    def show_change_master_password():
        page.clean()
        current_password = ft.TextField(
            label="Current Master Password",
            password=True,
            can_reveal_password=True,
            width=400,
            text_align=ft.TextAlign.CENTER,
            border_radius=10,
            focused_border_color=ft.Colors.BLUE,
            prefix_icon=ft.Icons.LOCK,
            error_style=ft.TextStyle(color=ft.Colors.RED),
            helper_text="Enter your current master password",
            helper_style=ft.TextStyle(color=ft.Colors.GREY_700),
            on_submit=lambda e: new_password.focus(),
        )
        new_password = ft.TextField(
            label="New Master Password",
            password=True,
            can_reveal_password=True,
            width=400,
            text_align=ft.TextAlign.CENTER,
            border_radius=10,
            focused_border_color=ft.Colors.BLUE,
            prefix_icon=ft.Icons.LOCK,
            error_style=ft.TextStyle(color=ft.Colors.RED),
            helper_text="Enter a new strong password",
            helper_style=ft.TextStyle(color=ft.Colors.GREY_700),
            on_submit=lambda e: confirm_password.focus(),
        )
        confirm_password = ft.TextField(
            label="Confirm New Password",
            password=True,
            can_reveal_password=True,
            width=400,
            text_align=ft.TextAlign.CENTER,
            border_radius=10,
            focused_border_color=ft.Colors.BLUE,
            prefix_icon=ft.Icons.LOCK,
            error_style=ft.TextStyle(color=ft.Colors.RED),
            helper_text="Confirm your new password",
            helper_style=ft.TextStyle(color=ft.Colors.GREY_700),
            on_submit=lambda e: change_password(),
        )

        def clear_errors():
            current_password.error_text = None
            new_password.error_text = None
            confirm_password.error_text = None
            page.snack_bar = None
            page.update()

        def change_password():
            debug_operation("Change Password", "Starting password change process")
            
            # Clear any existing errors
            clear_errors()
            
            current = current_password.value
            new = new_password.value
            confirm = confirm_password.value

            # Validate all fields are filled
            if not current or not new or not confirm:
                debug_log("Password change failed - Empty fields", "WARNING")
                show_error(page, "❌ Please fill all fields!")
                if not current:
                    current_password.error_text = "Current password is required"
                if not new:
                    new_password.error_text = "New password is required"
                if not confirm:
                    confirm_password.error_text = "Password confirmation is required"
                page.update()
                return

            # Validate new password strength
            debug_operation("Change Password", "Validating new password strength")
            is_valid, error_message = validate_password(new)
            if not is_valid:
                debug_log(f"Password change failed - Weak password: {error_message}", "WARNING")
                new_password.error_text = error_message
                show_error(page, f"❌ {error_message}")
                page.update()
                return

            # Validate passwords match
            if new != confirm:
                debug_log("Password change failed - Passwords do not match", "WARNING")
                confirm_password.error_text = "Passwords do not match"
                show_error(page, "❌ New passwords do not match!")
                page.update()
                return

            try:
                debug_operation("Change Password", "Loading stored password data")
                stored_mp_salt = master_password_data['salt']
                stored_hashed_password = master_password_data['hashed_password']
                stored_encrypted_vk = master_password_data['encrypted_vault_key']
                stored_vk_iv = master_password_data['vk_iv']

                debug_operation("Change Password", "Verifying current password")
                current_mp_derived_key = derive_key(current, stored_mp_salt)

                if current_mp_derived_key == stored_hashed_password:
                    try:
                        debug_operation("Change Password", "Generating new salt and key")
                        # Generate new salt and derived key for new password
                        new_mp_salt = os.urandom(16)
                        new_mp_derived_key = derive_key(new, new_mp_salt)

                        debug_operation("Change Password", "Re-encrypting vault key")
                        # Re-encrypt vault key with new derived key
                        new_encrypted_vk_data = encrypt_vault_key(vault_key, new_mp_derived_key)

                        debug_operation("Change Password", "Saving new password data")
                        # Save new master password data
                        save_master_password_data(
                            hashed_password_bytes=new_mp_derived_key,
                            salt_bytes=new_mp_salt,
                            encrypted_vk_bytes=base64.b64decode(new_encrypted_vk_data['ciphertext']),
                            vk_iv_bytes=base64.b64decode(new_encrypted_vk_data['iv'])
                        )

                        show_error(page, "✅ Master password changed successfully!", is_error=False)
                        debug_log("Password change successful", "INFO")
                        page.update()
                        show_dashboard()
                    except Exception as e:
                        debug_error(e, "Change Password - Encryption")
                        show_error(page, f"❌ Error changing password: {str(e)}")
                        page.update()
                else:
                    debug_log("Password change failed - Incorrect current password", "WARNING")
                    current_password.error_text = "Incorrect current password"
                    show_error(page, "❌ Current password is incorrect!")
                    page.update()
            except Exception as e:
                debug_error(e, "Change Password - General")
                show_error(page, f"❌ Error during password change: {str(e)}")
                page.update()

        page.add(
            ft.Container(
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.LOCK_RESET, size=32, color=ft.Colors.BLUE),
                                ft.Text("Change Master Password", size=32, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
                        ft.Container(height=30),
                        current_password,
                        ft.Container(height=10),
                        new_password,
                        ft.Container(height=10),
                        confirm_password,
                        ft.Container(height=20),
                        ft.Row(
                            [
                                ft.ElevatedButton(
                                    "Change Password",
                                    icon=ft.Icons.SAVE,
                                    on_click=lambda _: change_password(),
                                    style=ft.ButtonStyle(
                                        shape=ft.RoundedRectangleBorder(radius=10),
                                        padding=20,
                                    ),
                                ),
                                ft.ElevatedButton(
                                    "Back to Dashboard",
                                    icon=ft.Icons.ARROW_BACK,
                                    on_click=lambda _: show_dashboard(),
                                    style=ft.ButtonStyle(
                                        shape=ft.RoundedRectangleBorder(radius=10),
                                        padding=20,
                                    ),
                                ),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                            spacing=20,
                        ),
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=40,
                border_radius=20,
                bgcolor=ft.Colors.WHITE,
                shadow=ft.BoxShadow(
                    spread_radius=1,
                    blur_radius=15,
                    color=ft.Colors.BLACK12,
                ),
            )
        )

    # Login View
    def show_login():
        page.clean()
        
        # Password requirements list with icons
        requirements = [
            ("At least 8 characters", ft.Icons.CHECK_CIRCLE_OUTLINE),
            ("Uppercase letter", ft.Icons.TEXT_FIELDS),
            ("Lowercase letter", ft.Icons.TEXT_FIELDS),
            ("Number", ft.Icons.NUMBERS),
            ("Special character", ft.Icons.STAR)
        ]
        
        # Create requirement text widgets with icons
        requirement_texts = []
        for req, icon in requirements:
            requirement_texts.append(
                ft.Row(
                    [
                        ft.Icon(icon, size=16, color=ft.Colors.GREY_600),
                        ft.Text(
                            req,
                            color=ft.Colors.GREY_600,
                            size=11,
                        ),
                    ],
                    spacing=4,
                )
            )

        # Password strength indicator
        strength_indicator = ft.Container(
            width=400,
            height=3,
            bgcolor=ft.Colors.GREY_300,
            border_radius=2,
        )

        def check_password_strength(e):
            # Only check strength if setting new password
            if master_password_data:
                return
                
            password = master_password.value
            if not password:
                strength_indicator.bgcolor = ft.Colors.GREY_300
                for req in requirement_texts:
                    req.controls[0].color = ft.Colors.GREY_600
                    req.controls[1].color = ft.Colors.GREY_600
                page.update()
                return

            # Check each requirement
            has_length = len(password) >= 8
            has_upper = bool(re.search(r'[A-Z]', password))
            has_lower = bool(re.search(r'[a-z]', password))
            has_number = bool(re.search(r'\d', password))
            has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

            # Update requirement texts with icons
            requirements_status = [has_length, has_upper, has_lower, has_number, has_special]
            for i, (req, status) in enumerate(zip(requirement_texts, requirements_status)):
                req.controls[0].name = ft.Icons.CHECK_CIRCLE if status else ft.Icons.CANCEL
                req.controls[0].color = ft.Colors.GREEN if status else ft.Colors.RED
                req.controls[1].color = ft.Colors.GREEN if status else ft.Colors.RED

            # Calculate strength
            strength = sum(requirements_status)
            if strength <= 2:
                strength_indicator.bgcolor = ft.Colors.RED
            elif strength <= 4:
                strength_indicator.bgcolor = ft.Colors.ORANGE
            else:
                strength_indicator.bgcolor = ft.Colors.GREEN

            page.update()

        # Update master password field
        master_password.on_change = check_password_strength

        # Create the main content
        main_content = [
            ft.Icon(ft.Icons.SECURITY, size=48, color=ft.Colors.BLUE),
            ft.Text("Secure Password Manager", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE),
            ft.Text(
                "Enter your master password to continue" if master_password_data else "Set up your master password",
                size=14,
                color=ft.Colors.GREY_700,
            ),
            ft.Container(height=15),
            master_password,
        ]

        # Add password requirements only when setting new password
        if not master_password_data:
            # Split requirements into two columns
            left_requirements = requirement_texts[:3]
            right_requirements = requirement_texts[3:]
            
            main_content.extend([
                ft.Container(height=8),
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Row(
                                [
                                    ft.Icon(ft.Icons.SECURITY, size=14, color=ft.Colors.GREY_700),
                                    ft.Text("Password Requirements", size=12, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700),
                                ],
                                spacing=4,
                            ),
                            ft.Row(
                                [
                                    ft.Container(
                                        content=ft.Column(
                                            left_requirements,
                                            spacing=2,
                                        ),
                                        padding=ft.padding.only(left=20, top=2),
                                    ),
                                    ft.Container(
                                        content=ft.Column(
                                            right_requirements,
                                            spacing=2,
                                        ),
                                        padding=ft.padding.only(left=20, top=2),
                                    ),
                                ],
                                alignment=ft.MainAxisAlignment.CENTER,
                                spacing=30,
                            ),
                            ft.Container(height=5),
                            ft.Row(
                                [
                                    ft.Icon(ft.Icons.SPEED, size=14, color=ft.Colors.GREY_700),
                                    ft.Text("Password Strength", size=12, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700),
                                ],
                                spacing=4,
                            ),
                            ft.Container(
                                content=strength_indicator,
                                padding=ft.padding.only(left=20, top=2),
                            ),
                        ],
                        spacing=2,
                    ),
                    padding=8,
                    border=ft.border.all(1, ft.Colors.GREY_300),
                    border_radius=8,
                ),
            ])

        main_content.extend([
            ft.Container(height=15),
            ft.ElevatedButton(
                "Continue",
                icon=ft.Icons.ARROW_FORWARD,
                on_click=lambda _: handle_login() if master_password_data else handle_set_password(),
                style=ft.ButtonStyle(
                    shape=ft.RoundedRectangleBorder(radius=10),
                    padding=15,
                ),
                width=400,
            ),
        ])

        # Create a scrollable container for the main content
        scrollable_content = ft.Container(
            content=ft.Column(
                main_content,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                scroll=ft.ScrollMode.AUTO,
            ),
            padding=30,
            border_radius=20,
            bgcolor=ft.Colors.WHITE,
            shadow=ft.BoxShadow(
                spread_radius=1,
                blur_radius=15,
                color=ft.Colors.BLACK12,
            ),
            expand=True,
        )

        # Add the scrollable container to the page
        page.add(
            ft.Container(
                content=scrollable_content,
                expand=True,
                padding=15,
            )
        )

    # Edit Entry View
    def show_edit_entry(index):
        nonlocal editing_entry_index
        editing_entry_index = index
        entry = vault_entries[index]
        
        page.clean()
        site_field = ft.TextField(
            label="Site Name",
            width=400,
            text_align=ft.TextAlign.CENTER,
            border_radius=10,
            focused_border_color=ft.Colors.BLUE,
            prefix_icon=ft.Icons.WEB,
            value=entry['site']
        )
        username_field = ft.TextField(
            label="Username",
            width=400,
            text_align=ft.TextAlign.CENTER,
            border_radius=10,
            focused_border_color=ft.Colors.BLUE,
            prefix_icon=ft.Icons.PERSON,
            value=entry['username']
        )

        try:
            decrypted_password = decrypt_entry(
                entry['password_enc']['ciphertext'],
                entry['password_enc']['salt'],
                entry['password_enc']['iv'],
                vault_key
            )
        except Exception as e:
            decrypted_password = ""
            page.snack_bar = ft.SnackBar(content=ft.Text(f"Error decrypting password: {e}"))
            page.update()

        password_field = ft.TextField(
            label="Password",
            password=True,
            can_reveal_password=True,
            width=400,
            text_align=ft.TextAlign.CENTER,
            border_radius=10,
            focused_border_color=ft.Colors.BLUE,
            prefix_icon=ft.Icons.LOCK,
            value=decrypted_password
        )

        def generate_password():
            length = 12
            chars = string.ascii_letters + string.digits + string.punctuation
            new_pass = ''.join(random.choices(chars, k=length))
            password_field.value = new_pass
            page.update()

        def save_edited_entry():
            site = site_field.value.strip()
            username = username_field.value.strip()
            plaintext_password = password_field.value

            if not site or not username or not plaintext_password:
                show_error(page, "Please fill all fields!")
                return

            try:
                encrypted_data = encrypt_entry(plaintext_password, vault_key)
                
                # Ensure proper base64 padding
                def pad_base64(s):
                    padding = 4 - (len(s) % 4)
                    if padding != 4:
                        return s + ('=' * padding)
                    return s
                
                ciphertext = pad_base64(encrypted_data['ciphertext'])
                salt = pad_base64(encrypted_data['salt'])
                iv = pad_base64(encrypted_data['iv'])
                
                cursor.execute('''
                    UPDATE entries 
                    SET site = ?, username = ?, ciphertext = ?, salt = ?, iv = ?
                    WHERE id = ?
                ''', (site, username, ciphertext, salt, iv, entry['id']))
                conn.commit()
                
                # Update the entry in vault_entries
                vault_entries[index].update({
                    'site': site,
                    'username': username,
                    'password_enc': {
                        'ciphertext': ciphertext,
                        'salt': salt,
                        'iv': iv
                    }
                })
                
                show_error(page, f"Entry for '{site}' updated successfully!", is_error=False)
                page.update()
                show_view_entries()
            except Exception as e:
                show_error(page, f"Error updating entry: {e}")

        page.add(
            ft.Container(
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.EDIT, size=32, color=ft.Colors.BLUE),
                                ft.Text("Edit Entry", size=32, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                        ),
                        ft.Container(height=30),
                        site_field,
                        ft.Container(height=10),
                        username_field,
                        ft.Container(height=10),
                        password_field,
                        ft.Container(height=20),
                        ft.Row(
                            [
                                ft.ElevatedButton(
                                    "Generate Password",
                                    icon=ft.Icons.REFRESH,
                                    on_click=lambda _: generate_password(),
                                    style=ft.ButtonStyle(
                                        shape=ft.RoundedRectangleBorder(radius=10),
                                        padding=20,
                                    ),
                                ),
                                ft.ElevatedButton(
                                    "Save Changes",
                                    icon=ft.Icons.SAVE,
                                    on_click=lambda _: save_edited_entry(),
                                    style=ft.ButtonStyle(
                                        shape=ft.RoundedRectangleBorder(radius=10),
                                        padding=20,
                                    ),
                                ),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                            spacing=20,
                        ),
                        ft.ElevatedButton(
                            "Back to Entries",
                            icon=ft.Icons.ARROW_BACK,
                            on_click=lambda _: show_view_entries(),
                            style=ft.ButtonStyle(
                                shape=ft.RoundedRectangleBorder(radius=10),
                                padding=20,
                            ),
                        ),
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                padding=40,
                border_radius=20,
                bgcolor=ft.Colors.WHITE,
                shadow=ft.BoxShadow(
                    spread_radius=1,
                    blur_radius=15,
                    color=ft.Colors.BLACK12,
                ),
            )
        )

    # Initial view
    show_login()

if __name__ == "__main__":
    ft.app(target=main)
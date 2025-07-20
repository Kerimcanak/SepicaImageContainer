import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
import os
import io # For handling image data in memory as bytes
from PIL import Image, ImageTk, UnidentifiedImageError

# Import the backend module
from sepica_core import SepicaBackend, IMAGE_STORAGE_DIR

APP_NAME = "Sepica Image Container"
APP_ICON_PATH = "main program.png" # Path to your logo image

class SepicaImageContainer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.backend = SepicaBackend() # Instantiate the backend

        self.title(APP_NAME)
        self.geometry("800x600")
        self.min_width = 600
        self.min_height = 400
        self.geometry(f"{self.min_width}x{self.min_height}")
        self.minsize(self.min_width, self.min_height)

        # Set the application icon
        self.set_app_icon(APP_ICON_PATH)

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Hide the main window until login/password setup is complete
        self.withdraw()

        if not self.backend.is_password_set():
            self.show_set_password_dialog()
        else:
            self.show_login_dialog()

    def set_app_icon(self, icon_path):
        """Sets the application icon from a PNG file."""
        try:
            icon_image = Image.open(icon_path)
            # Resize for typical icon sizes if needed (e.g., 32x32 for taskbar, 16x16 for title bar)
            icon_image.thumbnail((128, 128), Image.Resampling.LANCZOS)
            self.app_icon_tk = ImageTk.PhotoImage(icon_image)
            self.iconphoto(True, self.app_icon_tk) # Set for all windows (True)
        except FileNotFoundError:
            messagebox.showwarning("Icon Error", f"Application icon '{icon_path}' not found. Please ensure it's in the same directory as the script.", parent=self)
        except UnidentifiedImageError:
            messagebox.showwarning("Icon Error", f"Could not load '{icon_path}'. It might not be a valid image file.", parent=self)
        except Exception as e:
            messagebox.showwarning("Icon Error", f"An error occurred loading icon: {e}", parent=self)

    def show_set_password_dialog(self):
        """Displays a dialog for the user to set the initial password."""
        dialog = tk.Toplevel(self)
        dialog.title("Set Master Password")
        dialog.geometry("300x150")
        dialog.transient(self) # Make dialog appear on top of main window
        dialog.grab_set()     # Disable interaction with main window
        dialog.protocol("WM_DELETE_WINDOW", self.on_closing) # Close app if dialog is closed

        tk.Label(dialog, text="Set your master password:").pack(pady=10)
        password_entry = tk.Entry(dialog, show="*", width=30)
        password_entry.pack(pady=5)
        password_entry.focus_set()

        def set_and_close():
            password = password_entry.get()
            try:
                self.backend.set_master_password(password)
                dialog.destroy()
                self.init_main_gui() # Initialize main GUI after password is set
                self.deiconify() # Show the main window
            except ValueError as e:
                messagebox.showwarning("Input Error", str(e), parent=dialog)
            except Exception as e:
                messagebox.showerror("Error", f"An unexpected error occurred: {e}", parent=dialog)

        tk.Button(dialog, text="Set Password", command=set_and_close).pack(pady=10)
        self.wait_window(dialog) # Wait for the dialog to close

    def show_login_dialog(self):
        """Displays a dialog for the user to log in."""
        dialog = tk.Toplevel(self)
        dialog.title("Login")
        dialog.geometry("300x150")
        dialog.transient(self)
        dialog.grab_set()
        dialog.protocol("WM_DELETE_WINDOW", self.on_closing)

        tk.Label(dialog, text="Enter master password:").pack(pady=10)
        password_entry = tk.Entry(dialog, show="*", width=30)
        password_entry.pack(pady=5)
        password_entry.focus_set()

        def login_attempt():
            password = password_entry.get()
            if self.backend.verify_master_password(password):
                dialog.destroy()
                self.init_main_gui() # Initialize main GUI after successful login
                self.deiconify() # Show the main window
            else:
                messagebox.showerror("Login Failed", "Incorrect password.", parent=dialog)
                password_entry.delete(0, tk.END) # Clear entry
                password_entry.focus_set()

        tk.Button(dialog, text="Login", command=login_attempt).pack(pady=10)
        self.wait_window(dialog)

    def init_main_gui(self):
        """Initializes the main application GUI components."""
        # Menu Bar
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Change Password...", command=self.change_password)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)

        # Main content frame
        main_frame = ttk.Frame(self, padding="10 10 10 10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Images container frame
        images_frame = ttk.LabelFrame(main_frame, text="Images", padding="10 10 10 10")
        images_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Listbox for images
        self.image_listbox = tk.Listbox(images_frame, selectmode=tk.SINGLE, borderwidth=2, relief="groove")
        self.image_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        self.image_listbox.bind("<<ListboxSelect>>", self.on_image_select)
        self.image_listbox.bind("<Double-Button-1>", lambda e: self.view_image()) # Double click to view

        # Scrollbar for listbox
        scrollbar = ttk.Scrollbar(images_frame, orient="vertical", command=self.image_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.image_listbox.config(yscrollcommand=scrollbar.set)

        # Drag and drop functionality
        # Note: Tkinter's native DND for files often requires a platform-specific
        # library like 'tkdnd' or more complex handling. For simplicity, this
        # implementation uses a basic binding that might need adjustments based on OS.
        # A more robust solution for drag-and-drop would involve external libraries
        # or more advanced Tkinter DND protocols.
        self.image_listbox.drop_target_register(tk.DND_FILES)
        self.image_listbox.dnd_bind('<<Drop>>', self.handle_drop)
        # Visually indicate drag target
        self.image_listbox.bind("<Enter>", lambda e: self.image_listbox.config(bg="lightgray"))
        self.image_listbox.bind("<Leave>", lambda e: self.image_listbox.config(bg="white"))

        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=(5, 0))

        self.upload_button = ttk.Button(buttons_frame, text="Upload...", command=self.upload_images)
        self.upload_button.pack(side=tk.LEFT, padx=5, expand=True)

        self.delete_button = ttk.Button(buttons_frame, text="Delete", command=self.delete_image, state=tk.DISABLED)
        self.delete_button.pack(side=tk.LEFT, padx=5, expand=True)

        self.view_button = ttk.Button(buttons_frame, text="View", command=self.view_image, state=tk.DISABLED)
        self.view_button.pack(side=tk.LEFT, padx=5, expand=True)

        self.download_button = ttk.Button(buttons_frame, text="Download...", command=self.download_image, state=tk.DISABLED)
        self.download_button.pack(side=tk.LEFT, padx=5, expand=True)

        self.populate_image_list()

    def on_image_select(self, event=None):
        """Enables/disables action buttons based on listbox selection."""
        if self.image_listbox.curselection():
            self.delete_button.config(state=tk.NORMAL)
            self.view_button.config(state=tk.NORMAL)
            self.download_button.config(state=tk.NORMAL)
        else:
            self.delete_button.config(state=tk.DISABLED)
            self.view_button.config(state=tk.DISABLED)
            self.download_button.config(state=tk.DISABLED)

    def populate_image_list(self):
        """Populates the listbox with names of stored images from the backend."""
        self.image_listbox.delete(0, tk.END)
        self.image_data_map = {} # Map original name to encrypted filename
        try:
            images = self.backend.get_image_list()
            for img_info in images:
                original_name = img_info['original_name']
                encrypted_filename = img_info['encrypted_filename']
                self.image_listbox.insert(tk.END, original_name)
                self.image_data_map[original_name] = encrypted_filename
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image list: {e}", parent=self)
        self.on_image_select() # Update button states

    def handle_drop(self, event):
        """Handles files dropped onto the image listbox."""
        paths = self.tk.splitlist(event.data) # This handles various path formats from DND
        for path in paths:
            if os.path.isfile(path):
                self.process_uploaded_file(path)
            else:
                messagebox.showwarning("Drag & Drop", f"'{path}' is not a file and cannot be uploaded.", parent=self)
        self.image_listbox.config(bg="white") # Reset background after drop

    def upload_images(self):
        """Opens a file dialog to select images for upload."""
        file_paths = filedialog.askopenfilenames(
            title="Select Images to Upload",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp *.tiff"), ("All files", "*.*")]
        )
        if file_paths:
            for file_path in file_paths:
                self.process_uploaded_file(file_path)

    def process_uploaded_file(self, file_path):
        """Calls backend to encrypt and store a single uploaded file."""
        try:
            original_name = self.backend.upload_image(file_path)
            self.populate_image_list() # Refresh the list
            messagebox.showinfo("Success", f"'{original_name}' encrypted and stored.", parent=self)
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to encrypt and store '{os.path.basename(file_path)}': {e}", parent=self)

    def get_selected_encrypted_filename(self):
        """Returns the encrypted filename of the currently selected image."""
        selected_indices = self.image_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Selection Error", "No image selected.", parent=self)
            return None

        selected_index = selected_indices[0]
        original_name_in_list = self.image_listbox.get(selected_index)
        return self.image_data_map.get(original_name_in_list)

    def view_image(self):
        """Decrypts and displays the selected image in a new window."""
        encrypted_filename = self.get_selected_encrypted_filename()
        if not encrypted_filename:
            return

        original_name = self.image_listbox.get(self.image_listbox.curselection()[0])

        try:
            decrypted_data = self.backend.get_image_data(encrypted_filename)

            # Use PIL to open the image from bytes
            image = Image.open(io.BytesIO(decrypted_data))
            image.thumbnail((800, 600), Image.Resampling.LANCZOS) # Resize for display

            # Create a new Toplevel window for image display
            view_window = tk.Toplevel(self)
            view_window.title(f"Viewing: {original_name}")
            view_window.transient(self)
            view_window.grab_set()

            img_tk = ImageTk.PhotoImage(image)
            img_label = tk.Label(view_window, image=img_tk)
            img_label.image = img_tk # Keep a reference!
            img_label.pack(padx=10, pady=10)

            # Center the view window relative to the main window
            view_window.update_idletasks()
            x = self.winfo_x() + (self.winfo_width() // 2) - (view_window.winfo_width() // 2)
            y = self.winfo_y() + (self.winfo_height() // 2) - (view_window.winfo_height() // 2)
            view_window.geometry(f"+{int(x)}+{int(y)}")

        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt or display '{original_name}': {e}", parent=self)
            self.populate_image_list() # Refresh list in case of missing file

    def delete_image(self):
        """Deletes the selected image and its metadata via the backend."""
        encrypted_filename = self.get_selected_encrypted_filename()
        if not encrypted_filename:
            return

        original_name = self.image_listbox.get(self.image_listbox.curselection()[0])

        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to permanently delete '{original_name}'?", parent=self):
            try:
                deleted_name = self.backend.delete_image(encrypted_filename)
                self.populate_image_list() # Refresh the list
                messagebox.showinfo("Deleted", f"'{deleted_name}' has been permanently deleted.", parent=self)
            except Exception as e:
                messagebox.showerror("Deletion Error", f"Failed to delete '{original_name}': {e}", parent=self)

    def download_image(self):
        """Decrypts and saves the selected image to a user-specified location via the backend."""
        encrypted_filename = self.get_selected_encrypted_filename()
        if not encrypted_filename:
            return

        original_name = self.image_listbox.get(self.image_listbox.curselection()[0])

        save_path = filedialog.asksaveasfilename(
            title=f"Save {original_name} As...",
            initialfile=original_name,
            filetypes=[("All files", "*.*")] # Allow saving with original extension or new
        )
        if not save_path:
            return

        try:
            downloaded_name = self.backend.download_image(encrypted_filename, save_path)
            messagebox.showinfo("Download Complete", f"'{downloaded_name}' downloaded to '{save_path}'.", parent=self)
        except Exception as e:
            messagebox.showerror("Download Error", f"Failed to download '{original_name}': {e}", parent=self)

    def change_password(self):
        """Allows the user to change the master password via the backend."""
        dialog = tk.Toplevel(self)
        dialog.title("Change Password")
        dialog.geometry("350x200")
        dialog.transient(self)
        dialog.grab_set()

        tk.Label(dialog, text="Current Password:").pack(pady=5)
        current_password_entry = tk.Entry(dialog, show="*", width=40)
        current_password_entry.pack(pady=2)
        current_password_entry.focus_set()

        tk.Label(dialog, text="New Password:").pack(pady=5)
        new_password_entry = tk.Entry(dialog, show="*", width=40)
        new_password_entry.pack(pady=2)

        tk.Label(dialog, text="Confirm New Password:").pack(pady=5)
        confirm_new_password_entry = tk.Entry(dialog, show="*", width=40)
        confirm_new_password_entry.pack(pady=2)

        def perform_password_change():
            current_password = current_password_entry.get()
            new_password = new_password_entry.get()
            confirm_new_password = confirm_new_password_entry.get()

            if new_password != confirm_new_password:
                messagebox.showwarning("Input Error", "New passwords do not match.", parent=dialog)
                return

            try:
                self.backend.change_master_password(current_password, new_password)
                messagebox.showinfo("Success", "Password changed and all images re-encrypted.", parent=self)
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to change password: {e}", parent=dialog)

        tk.Button(dialog, text="Change Password", command=perform_password_change).pack(pady=10)
        dialog.wait_window(dialog)

    def on_closing(self):
        """Handles application closing."""
        if messagebox.askokcancel("Quit", "Do you want to quit?", parent=self):
            # No explicit save_config call here, as backend saves on state changes.
            # However, if there were unsaved changes not triggered by a backend call,
            # you'd add a backend.save_state() here.
            self.destroy()

if __name__ == "__main__":
    # Ensure Pillow is installed: pip install Pillow
    # Ensure cryptography is installed: pip install cryptography
    # Ensure Tkinter is available (usually comes with Python)

    app = SepicaImageContainer()
    app.mainloop()

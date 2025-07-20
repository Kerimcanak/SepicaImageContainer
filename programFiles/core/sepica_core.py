# sepica_backend.py

import os
import json
import hashlib
from cryptography.fernet import Fernet, InvalidToken
import base64
import uuid
import shutil
import io # Used for handling image data in memory as bytes

# --- Configuration and Constants ---
CONFIG_FILE = "sepica_config.json"
IMAGE_STORAGE_DIR = "encrypted_images"
PASSWORD_SALT_SIZE = 16 # bytes
KEY_DERIVATION_ITERATIONS = 100000 # For PBKDF2

class SepicaBackend:
    """
    Handles all core logic for the Sepica Image Container,
    including configuration, password management, encryption, and file operations.
    """
    def __init__(self):
        self._hashed_password = None
        self._password_salt = None
        self._image_metadata = {} # {encrypted_filename: {original_name: str, size: int}}
        self._encryption_key = None # Derived from password upon successful login

        self._load_config()
        self._ensure_storage_directory()

    def _ensure_storage_directory(self):
        """Ensures the directory for storing encrypted images exists."""
        if not os.path.exists(IMAGE_STORAGE_DIR):
            os.makedirs(IMAGE_STORAGE_DIR)

    def _load_config(self):
        """Loads application configuration from the JSON file."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self._hashed_password = config.get('hashed_password')
                    # Decode salt from base64 string back to bytes
                    self._password_salt = base64.b64decode(config.get('password_salt')) if config.get('password_salt') else None
                    self._image_metadata = config.get('image_metadata', {})
            except json.JSONDecodeError:
                print(f"Error: Could not read configuration file '{CONFIG_FILE}'. It might be corrupted. Resetting config.")
                self._hashed_password = None
                self._password_salt = None
                self._image_metadata = {}
            except Exception as e:
                print(f"Error: An unexpected error occurred loading config: {e}. Resetting config.")
                self._hashed_password = None
                self._password_salt = None
                self._image_metadata = {}
        else:
            self._hashed_password = None
            self._password_salt = None
            self._image_metadata = {}

    def _save_config(self):
        """Saves current application configuration to the JSON file."""
        config = {
            'hashed_password': self._hashed_password,
            # Encode salt to base64 string for JSON serialization
            'password_salt': base64.b64encode(self._password_salt).decode('utf-8') if self._password_salt else None,
            'image_metadata': self._image_metadata
        }
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except IOError as e:
            print(f"Error: Could not save configuration file: {e}")
            raise # Re-raise to let the caller know about the failure

    def _generate_fernet_key(self, password, salt):
        """Derives a Fernet key from a password and salt using PBKDF2."""
        kdf = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            KEY_DERIVATION_ITERATIONS
        )
        return base64.urlsafe_b64encode(kdf[:32]) # Fernet key must be 32 url-safe base64-encoded bytes

    def _encrypt_data(self, data_bytes, key):
        """Encrypts bytes data using the provided Fernet key."""
        f = Fernet(key)
        encrypted_data = f.encrypt(data_bytes)
        return encrypted_data

    def _decrypt_data(self, encrypted_data_bytes, key):
        """Decrypts bytes data using the provided Fernet key."""
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data_bytes)
        return decrypted_data

    # --- Public API for Frontend ---

    def is_password_set(self):
        """Returns True if a master password has been set, False otherwise."""
        return self._hashed_password is not None

    def set_master_password(self, password):
        """
        Sets the initial master password for the application.
        Generates a new salt and derives the encryption key.
        Raises ValueError if password is empty.
        """
        if not password:
            raise ValueError("Password cannot be empty.")
        self._password_salt = os.urandom(PASSWORD_SALT_SIZE)
        self._hashed_password = hashlib.sha256(password.encode('utf-8') + self._password_salt).hexdigest()
        self._encryption_key = self._generate_fernet_key(password, self._password_salt)
        self._save_config()
        return True

    def verify_master_password(self, password):
        """
        Verifies the provided password against the stored hashed password.
        If successful, sets the internal encryption key.
        Returns True on success, False otherwise.
        """
        if not self._hashed_password or not self._password_salt:
            return False # No password set or corrupted config

        is_valid = hashlib.sha256(password.encode('utf-8') + self._password_salt).hexdigest() == self._hashed_password
        if is_valid:
            self._encryption_key = self._generate_fernet_key(password, self._password_salt)
        return is_valid

    def get_image_list(self):
        """
        Returns a list of dictionaries, each containing 'encrypted_filename'
        and 'original_name' for all stored images.
        """
        return [{'encrypted_filename': k, 'original_name': v['original_name']}
                for k, v in self._image_metadata.items()]

    def upload_image(self, file_path):
        """
        Encrypts and stores an image file.
        Args:
            file_path (str): The path to the original image file.
        Returns:
            str: The original name of the uploaded file.
        Raises:
            Exception: If encryption or storage fails.
        """
        if not self._encryption_key:
            raise Exception("Application not logged in. Encryption key not available.")
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            # Generate a unique filename for the encrypted file
            unique_filename = str(uuid.uuid4())
            encrypted_filepath = os.path.join(IMAGE_STORAGE_DIR, unique_filename)

            with open(file_path, 'rb') as f:
                original_data = f.read()

            encrypted_data = self._encrypt_data(original_data, self._encryption_key)

            with open(encrypted_filepath, 'wb') as f:
                f.write(encrypted_data)

            original_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path) # Original file size
            self._image_metadata[unique_filename] = {
                'original_name': original_name,
                'size': file_size
            }
            self._save_config()
            return original_name
        except Exception as e:
            raise Exception(f"Failed to encrypt and store '{os.path.basename(file_path)}': {e}")

    def get_image_data(self, encrypted_filename):
        """
        Retrieves and decrypts the raw image data for a given encrypted filename.
        Args:
            encrypted_filename (str): The unique filename of the encrypted image.
        Returns:
            bytes: The decrypted image data.
        Raises:
            FileNotFoundError: If the encrypted file does not exist.
            Exception: If decryption fails or key is not available.
        """
        if not self._encryption_key:
            raise Exception("Application not logged in. Encryption key not available.")

        encrypted_filepath = os.path.join(IMAGE_STORAGE_DIR, encrypted_filename)
        if not os.path.exists(encrypted_filepath):
            # Clean up metadata if file is missing
            if encrypted_filename in self._image_metadata:
                del self._image_metadata[encrypted_filename]
                self._save_config()
            raise FileNotFoundError(f"Encrypted image file not found: {encrypted_filename}")

        try:
            with open(encrypted_filepath, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = self._decrypt_data(encrypted_data, self._encryption_key)
            return decrypted_data
        except InvalidToken:
            raise Exception("Decryption failed. The encryption key might be incorrect or the file corrupted.")
        except Exception as e:
            raise Exception(f"Failed to retrieve or decrypt image '{encrypted_filename}': {e}")

    def delete_image(self, encrypted_filename):
        """
        Permanently deletes an encrypted image file and its metadata.
        Args:
            encrypted_filename (str): The unique filename of the encrypted image to delete.
        Returns:
            str: The original name of the deleted file.
        Raises:
            FileNotFoundError: If the encrypted file or its metadata is not found.
            Exception: If deletion fails.
        """
        if encrypted_filename not in self._image_metadata:
            raise FileNotFoundError(f"Metadata for image '{encrypted_filename}' not found.")

        original_name = self._image_metadata[encrypted_filename]['original_name']
        encrypted_filepath = os.path.join(IMAGE_STORAGE_DIR, encrypted_filename)

        try:
            if os.path.exists(encrypted_filepath):
                os.remove(encrypted_filepath) # Indefinitely delete the file
            del self._image_metadata[encrypted_filename]
            self._save_config()
            return original_name
        except Exception as e:
            raise Exception(f"Failed to permanently delete '{original_name}': {e}")

    def download_image(self, encrypted_filename, destination_path):
        """
        Decrypts and saves an image to a specified destination.
        Args:
            encrypted_filename (str): The unique filename of the encrypted image.
            destination_path (str): The full path where the decrypted image should be saved.
        Returns:
            str: The original name of the downloaded file.
        Raises:
            FileNotFoundError: If the encrypted file does not exist.
            Exception: If decryption or saving fails.
        """
        original_name = self._image_metadata.get(encrypted_filename, {}).get('original_name', 'unknown_image')
        try:
            decrypted_data = self.get_image_data(encrypted_filename)
            with open(destination_path, 'wb') as f:
                f.write(decrypted_data)
            return original_name
        except Exception as e:
            raise Exception(f"Failed to download '{original_name}': {e}")

    def change_master_password(self, current_password, new_password):
        """
        Changes the master password and re-encrypts all stored images with the new key.
        Args:
            current_password (str): The user's current master password.
            new_password (str): The new master password to set.
        Returns:
            bool: True if password changed and images re-encrypted successfully.
        Raises:
            ValueError: If passwords are empty or don't match.
            Exception: If current password is incorrect or re-encryption fails.
        """
        if not current_password:
            raise ValueError("Current password cannot be empty.")
        if not new_password:
            raise ValueError("New password cannot be empty.")

        if not self.verify_master_password(current_password):
            raise Exception("Incorrect current password.")

        try:
            old_key = self._encryption_key # The key derived from current_password

            # Temporarily derive the new key without saving the new password yet
            # This ensures we have the new key before committing to the new password
            new_salt = os.urandom(PASSWORD_SALT_SIZE)
            new_key = self._generate_fernet_key(new_password, new_salt)

            # Iterate through all images and re-encrypt them
            for encrypted_filename in list(self._image_metadata.keys()): # Iterate over a copy
                encrypted_filepath = os.path.join(IMAGE_STORAGE_DIR, encrypted_filename)
                if os.path.exists(encrypted_filepath):
                    with open(encrypted_filepath, 'rb') as f:
                        old_encrypted_data = f.read()

                    # Decrypt with old key
                    decrypted_data = self._decrypt_data(old_encrypted_data, old_key)

                    # Encrypt with new key
                    new_encrypted_data = self._encrypt_data(decrypted_data, new_key)

                    # Overwrite the old encrypted file with the new encrypted data
                    with open(encrypted_filepath, 'wb') as f:
                        f.write(new_encrypted_data)

            # If re-encryption is successful for all, then update the main config
            self._password_salt = new_salt
            self._hashed_password = hashlib.sha256(new_password.encode('utf-8') + self._password_salt).hexdigest()
            self._encryption_key = new_key # Update the active encryption key
            self._save_config()
            return True

        except Exception as e:
            # Important: If re-encryption fails mid-way, the state might be inconsistent.
            # A more robust solution would involve a temporary directory for new encrypted files,
            # and only replacing the old ones after all are successfully re-encrypted.
            raise Exception(f"Failed to change password and re-encrypt images: {e}\n"
                            "Your images might be inaccessible if the password change was incomplete. "
                            "Please try again or contact support.")

# Example CLI usage (for testing the backend independently)
if __name__ == "__main__":
    backend = SepicaBackend()

    print("--- Sepica Backend CLI Test ---")

    if not backend.is_password_set():
        print("No master password set. Setting one now.")
        password = input("Enter a new master password: ")
        try:
            backend.set_master_password(password)
            print("Password set successfully.")
        except ValueError as e:
            print(f"Error: {e}")
            exit()
    else:
        print("Master password already set. Please log in.")
        while True:
            password = input("Enter master password: ")
            if backend.verify_master_password(password):
                print("Login successful.")
                break
            else:
                print("Incorrect password. Try again.")

    while True:
        print("\nOptions:")
        print("1. Upload Image")
        print("2. List Images")
        print("3. View Image (decrypt to temp file and open)")
        print("4. Download Image")
        print("5. Delete Image")
        print("6. Change Password")
        print("7. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            file_path = input("Enter path to image file: ")
            try:
                original_name = backend.upload_image(file_path)
                print(f"'{original_name}' uploaded and encrypted.")
            except Exception as e:
                print(f"Error uploading image: {e}")
        elif choice == '2':
            images = backend.get_image_list()
            if not images:
                print("No images stored.")
            else:
                print("Stored Images:")
                for i, img in enumerate(images):
                    print(f"{i+1}. {img['original_name']} (Encrypted ID: {img['encrypted_filename']})")
        elif choice == '3':
            images = backend.get_image_list()
            if not images:
                print("No images to view.")
                continue
            idx_str = input("Enter number of image to view: ")
            try:
                idx = int(idx_str) - 1
                if 0 <= idx < len(images):
                    encrypted_filename = images[idx]['encrypted_filename']
                    original_name = images[idx]['original_name']
                    try:
                        decrypted_data = backend.get_image_data(encrypted_filename)
                        # Save to a temporary file for viewing
                        temp_dir = "temp_view"
                        os.makedirs(temp_dir, exist_ok=True)
                        temp_filepath = os.path.join(temp_dir, original_name)
                        with open(temp_filepath, 'wb') as f:
                            f.write(decrypted_data)
                        print(f"Decrypted '{original_name}' to '{temp_filepath}'. Opening...")
                        os.startfile(temp_filepath) # Opens with default viewer on Windows
                        # For cross-platform, you might need 'xdg-open' or 'open'
                        # import subprocess
                        # if sys.platform == "win32": os.startfile(temp_filepath)
                        # elif sys.platform == "darwin": subprocess.call(["open", temp_filepath])
                        # else: subprocess.call(["xdg-open", temp_filepath])
                    except Exception as e:
                        print(f"Error viewing image: {e}")
                else:
                    print("Invalid image number.")
            except ValueError:
                print("Invalid input.")
        elif choice == '4':
            images = backend.get_image_list()
            if not images:
                print("No images to download.")
                continue
            idx_str = input("Enter number of image to download: ")
            try:
                idx = int(idx_str) - 1
                if 0 <= idx < len(images):
                    encrypted_filename = images[idx]['encrypted_filename']
                    original_name = images[idx]['original_name']
                    download_path = input(f"Enter destination path for '{original_name}': ")
                    try:
                        backend.download_image(encrypted_filename, download_path)
                        print(f"'{original_name}' downloaded to '{download_path}'.")
                    except Exception as e:
                        print(f"Error downloading image: {e}")
                else:
                    print("Invalid image number.")
            except ValueError:
                print("Invalid input.")
        elif choice == '5':
            images = backend.get_image_list()
            if not images:
                print("No images to delete.")
                continue
            idx_str = input("Enter number of image to delete: ")
            try:
                idx = int(idx_str) - 1
                if 0 <= idx < len(images):
                    encrypted_filename = images[idx]['encrypted_filename']
                    original_name = images[idx]['original_name']
                    confirm = input(f"Are you sure you want to permanently delete '{original_name}'? (yes/no): ").lower()
                    if confirm == 'yes':
                        try:
                            deleted_name = backend.delete_image(encrypted_filename)
                            print(f"'{deleted_name}' permanently deleted.")
                        except Exception as e:
                            print(f"Error deleting image: {e}")
                    else:
                        print("Deletion cancelled.")
                else:
                    print("Invalid image number.")
            except ValueError:
                print("Invalid input.")
        elif choice == '6':
            current_password = input("Enter your current master password: ")
            new_password = input("Enter your new master password: ")
            confirm_new_password = input("Confirm your new master password: ")
            if new_password != confirm_new_password:
                print("New passwords do not match.")
                continue
            try:
                backend.change_master_password(current_password, new_password)
                print("Master password changed and all images re-encrypted successfully.")
            except Exception as e:
                print(f"Error changing password: {e}")
        elif choice == '7':
            print("Exiting Sepica Backend CLI Test.")
            break
        else:
            print("Invalid choice. Please try again.")

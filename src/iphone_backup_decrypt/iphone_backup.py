import os.path
import shutil
import sqlite3
import struct
import tempfile
import re

import biplist

from . import google_iphone_dataprotection

__all__ = ["EncryptedBackup", "RelativePath", "RelativePathsLike"]


class RelativePath:
    """Relative paths for commonly accessed files."""

    # Standard iOS file locations:
    ADDRESS_BOOK = "Library/AddressBook/AddressBook.sqlitedb"
    TEXT_MESSAGES = "Library/SMS/sms.db"
    CALL_HISTORY = "Library/CallHistoryDB/CallHistory.storedata"
    NOTES = "Library/Notes/notes.sqlite" 
    NOTESV7 = "Library/Notes/NotesV7.storedata"
    CALENDARS = "Library/Calendar/Calendar.sqlitedb"
    HEALTH = "Health/healthdb.sqlite"
    HEALTH_SECURE = "Health/healthdb_secure.sqlite"
    SAFARI_HISTORY = "Library/Safari/History.db"
    SAFARI_BOOKMARKS = "Library/Safari/Bookmarks.db"

    # Very common external files:
    WHATSAPP_MESSAGES = "ChatStorage.sqlite"
    WHATSAPP_CONTACTS = "ContactsV2.sqlite"



class RelativePathsLike:
    """Relative path wildcards for commonly accessed groups of files."""

    # Standard iOS file locations:
    CAMERA_ROLL = "Media/DCIM/%APPLE/IMG%.%"
    SMS_ATTACHMENTS = "Library/SMS/Attachments/%.%"
    FACEBOOK_MESSENGER = "Library/MessengerMedia/%.%"

    PHOTO_STREAM = "Media/PhotoStreamsData/%.%"

    # WhatsApp makes .thumb files for every media item, so maybe specifically extract JPG or MP4:
    WHATSAPP_ATTACHED_IMAGES = "Message/Media/%.jpg"
    WHATSAPP_ATTACHED_VIDEOS = "Message/Media/%.mp4"
    # But allow full export if desired:
    WHATSAPP_ATTACHMENTS = "Message/Media/%.%"

 
class EncryptedBackup:

    def __init__(self, *, backup_directory, passphrase):
        """
        Decrypt an iOS 13 encrypted backup using the passphrase chosen in iTunes.

        The passphrase and decryption keys will be stored in memory whilst using this code,
        and a temporary decrypted copy of the Manifest database containing a list of all files
        in the backup will be created in a temporary folder. If run on a machine without full-disk
        encryption, this may leak the keys and reduce the overall security of the backup.
        If an exception occurs during program execution, there is a chance this decrypted Manifest
        database will not be removed. Its location is stored in '_temp_decrypted_manifest_db_path'
        which can be printed and manually inspected if desired.

        :param backup_directory:
            The path to the backup directory on disk. On Windows, this is either:
              - '%AppData%\\Apple Computer\\MobileSync\\Backup\\[device-specific-hash]'
              or, for iTunes installed via the Windows Store:
              - '%UserProfile%\\Apple\\MobileSync\\Backup\\[device-specific-hash]'
            The folder should contain 'Manifest.db' and 'Manifest.plist' if it contains a valid backup.
        :param passphrase:
            The passphrase chosen in iTunes when first choosing to encrypt backups.
            If it requires an encoding other than ASCII or UTF-8, a bytes object must be provided.
        """
        # Public state:
        self.decrypted = False
        # Keep track of the backup directory, and more dangerously, keep the backup passphrase as bytes until used:
        self._backup_directory = os.path.expandvars(backup_directory)
        self._passphrase = passphrase if type(passphrase) is bytes else passphrase.encode("utf-8")
        # Internals for unlocking the Keybag:
        self._manifest_plist_path = os.path.join(self._backup_directory, 'Manifest.plist')
        self._manifest_plist = None
        self._manifest_db_path = os.path.join(self._backup_directory, 'Manifest.db')
        self._keybag = None
        self._unlocked = False
        # We need a temporary file for the decrypted database, because SQLite can't open bytes in memory as a database:
        self._temporary_folder = tempfile.mkdtemp()
        self._temp_decrypted_manifest_db_path = os.path.join(self._temporary_folder, 'Manifest.db')
        # We can keep a connection to the index SQLite database open:
        self._temp_manifest_db_conn = None

    def __del__(self):
        self._cleanup()

    def _cleanup(self):
        try:
            if self._temp_manifest_db_conn is not None:
                self._temp_manifest_db_conn.close()
            shutil.rmtree(self._temporary_folder)
        except Exception:
            print("WARN: Cleanup failed. You may want to delete the decrypted temporary file found at:")
            print("    '{}'".format(self._temp_decrypted_manifest_db_path))
            raise

    def fetch_directory_with_most_files(self, limit=10):
        """
        Fetch directories with the most files.
        :param limit: Number of top directories to fetch.
        :return: A list of tuples with directory name and file count.
        """
        # Ensure that we've decrypted the manifest file:
        self._decrypt_manifest_db_file()
        
        # Check if the database connection is initialized
        if self._temp_manifest_db_conn is None:
            raise ConnectionError("Failed to establish a connection to the decrypted Manifest.db.")
        
        try:
            cur = self._temp_manifest_db_conn.cursor()
            
            # Query to count files per directory and order by count
            query = """
            WITH CombinedPaths AS (
                SELECT
                    CASE
                        WHEN relativePath = '' THEN domain
                        ELSE domain || '/' || relativePath
                    END AS fullPath
                FROM Files
            ),
            Directories AS (
                SELECT
                    CASE
                        WHEN INSTR(fullPath, '/') = 0 THEN fullPath
                        ELSE SUBSTR(fullPath, 1, LENGTH(fullPath) - LENGTH(SUBSTR(fullPath, INSTR(fullPath, '/') + 1)))
                    END AS directory
                FROM CombinedPaths
            )
            SELECT
                directory,
                COUNT(*) as num_files
            FROM Directories
            GROUP BY directory
            ORDER BY num_files DESC
            LIMIT ?

            """
            
            cur.execute(query, (limit,))
            result = cur.fetchall()
            cur.close()
            
            return result
        
        except sqlite3.Error as e:
            raise ConnectionError(f"SQLite error occurred: {e}")



    def _read_and_unlock_keybag(self):
        if self._unlocked:
            return self._unlocked
        # Open the Manifest.plist file to access the Keybag:
        with open(self._manifest_plist_path, 'rb') as infile:
            self._manifest_plist = biplist.readPlist(infile)
        self._keybag = google_iphone_dataprotection.Keybag(self._manifest_plist['BackupKeyBag'])
        # Attempt to unlock the Keybag:
        self._unlocked = self._keybag.unlockWithPassphrase(self._passphrase)
        if not self._unlocked:
            raise ValueError("Failed to decrypt keys: incorrect passphrase?")
        # No need to keep the passphrase any more:
        self._passphrase = None
        return True

    def _open_temp_database(self):
        # Check that we have successfully decrypted the file:
        if not os.path.exists(self._temp_decrypted_manifest_db_path):
            return False
        try:
            # Connect to the decrypted Manifest.db database if necessary:
            if self._temp_manifest_db_conn is None:
                self._temp_manifest_db_conn = sqlite3.connect(self._temp_decrypted_manifest_db_path)
            # Check that it has the expected table structure and a list of files:
            cur = self._temp_manifest_db_conn.cursor()
            cur.execute("SELECT count(*) FROM Files;")
            file_count = cur.fetchone()[0]
            cur.close()
            return file_count > 0
        except sqlite3.Error:
            return False

    def _decrypt_manifest_db_file(self):
        if os.path.exists(self._temp_decrypted_manifest_db_path):
            return
        # Ensure we've already unlocked the Keybag:
        self._read_and_unlock_keybag()
        # Decrypt the Manifest.db index database:
        manifest_key = self._manifest_plist['ManifestKey'][4:]
        with open(self._manifest_db_path, 'rb') as encrypted_db_filehandle:
            encrypted_db = encrypted_db_filehandle.read()
        manifest_class = struct.unpack('<l', self._manifest_plist['ManifestKey'][:4])[0]
        key = self._keybag.unwrapKeyForClass(manifest_class, manifest_key)
        decrypted_data = google_iphone_dataprotection.AESdecryptCBC(encrypted_db, key)
        # Write the decrypted Manifest.db temporarily to disk:
        with open(self._temp_decrypted_manifest_db_path, 'wb') as decrypted_db_filehandle:
            decrypted_db_filehandle.write(decrypted_data)
        # Open the temporary database to verify decryption success:
        if not self._open_temp_database():
            raise ConnectionError("Manifest.db file does not seem to be the right format!")

    def _decrypt_inner_file(self, *, file_id, file_bplist):
        # Ensure we've already unlocked the Keybag:
        self._read_and_unlock_keybag()

        # Extract the decryption key from the PList data:
        plist = biplist.readPlistFromString(file_bplist)
        file_data = plist['$objects'][plist['$top']['root'].integer]
        protection_class = file_data['ProtectionClass']
        if "EncryptionKey" not in file_data:
            print(f"File {file_id} is not encrypted.")
            return None  # This file is not encrypted; either a directory or empty.

        encryption_key = plist['$objects'][file_data['EncryptionKey'].integer]['NS.data'][4:]
        inner_key = self._keybag.unwrapKeyForClass(protection_class, encryption_key)

        # Find the encrypted version of the file on disk and decrypt it:
        filename_in_backup = os.path.join(self._backup_directory, file_id[:2], file_id)
        if not os.path.exists(filename_in_backup):
            print(f"Encrypted file {filename_in_backup} does not exist.")
            return None

        with open(filename_in_backup, 'rb') as encrypted_file_filehandle:
            encrypted_data = encrypted_file_filehandle.read()

        # Decrypt the file contents:
        try:
            decrypted_data = google_iphone_dataprotection.AESdecryptCBC(encrypted_data, inner_key)
            return google_iphone_dataprotection.removePadding(decrypted_data)
        except Exception as e:
            print(f"Decryption failed for {file_id}. Error: {e}")
            return None


    def test_decryption(self):
        """Validate that the backup can be decrypted successfully."""
        # Ensure that we've initialised everything:
        if self._temp_manifest_db_conn is None:
            self._decrypt_manifest_db_file()
        return True

    def save_manifest_file(self, output_filename):
        """Save a permanent copy of the decrypted Manifest SQLite database."""
        # Ensure that we've decrypted the manifest file:
        self._decrypt_manifest_db_file()
        # Copy the decrypted file to the output:
        output_directory = os.path.dirname(output_filename)
        if output_directory:
            os.makedirs(output_directory, exist_ok=True)
        shutil.copy(self._temp_decrypted_manifest_db_path, output_filename)

    def extract_file_as_bytes(self, relative_path):
        """
        Decrypt a single named file and return the bytes.

        :param relative_path:
            The iOS 'relativePath' of the file to be decrypted. Common relative paths are provided by the
            'RelativePath' class, otherwise these can be found by opening the decrypted Manifest.db file
            and examining the Files table.
        :return: decrypted bytes of the file.
        """
        # Ensure that we've initialised everything:
        if self._temp_manifest_db_conn is None:
            self._decrypt_manifest_db_file()
        # Use Manifest.db to find the on-disk filename and file metadata, including the keys, for the file.
        # The metadata is contained in the 'file' column, as a binary PList file:
        try:
            cur = self._temp_manifest_db_conn.cursor()
            query = """
                SELECT fileID, file
                FROM Files
                WHERE relativePath = ?
                AND flags=1
                ORDER BY domain, relativePath
                LIMIT 1;
            """
            cur.execute(query, (relative_path,))
            result = cur.fetchone()
        except sqlite3.Error:
            return None
        file_id, file_bplist = result
        # Decrypt the requested file:
        return self._decrypt_inner_file(file_id=file_id, file_bplist=file_bplist)

 
    def extract_file(self, *, relative_path, output_filename):
        """
        Decrypt a single named file and save it to disk.

        This is a helper method and is exactly equivalent to extract_file_as_bytes(...) and then
        writing that data to a file.

        :param relative_path:
            The iOS 'relativePath' of the file to be decrypted. Common relative paths are provided by the
            'RelativePath' class, otherwise these can be found by opening the decrypted Manifest.db file
            and examining the Files table.
        :param output_filename:
            The filename to write the decrypted file contents to.
        """
        # Get the decrypted bytes of the requested file:
        decrypted_data = self.extract_file_as_bytes(relative_path)

        # If the output_filename ends with a '/', it's treated as a directory, and the relative_path's basename is used.
        if output_filename.endswith('/'):
            output_filename = os.path.join(output_filename, os.path.basename(relative_path))

        # Output them to disk:
        output_directory = os.path.dirname(output_filename)
        if output_directory:
            os.makedirs(output_directory, exist_ok=True)
        if decrypted_data is not None:
            with open(output_filename, 'wb') as outfile:
                outfile.write(decrypted_data)


    def extract_files(self, *, relative_paths_like, output_folder):
        """
        Decrypt files matching a relative path query and output them to a folder.

        This method is not really designed to match very loose relative paths like '%' or '%.jpg'.
        Since the folder structure is not preserved, files may be overwritten and/or unclear in origin.
        Use very generic relative path matching at your own risk.

        :param relative_paths_like:
            An iOS 'relativePath' of the files to be decrypted, containing '%' or '_' SQL LIKE wildcards.
            Common relative path wildcards are provided by the 'RelativePathsLike' class, otherwise these can be found
            by opening the decrypted Manifest.db file and examining the Files table.
        :param output_folder:
            The folder to write output files into. Files will be named with their internal iOS filenames and will
            overwrite anything in the output folder with that name.
        """
        # Ensure that we've initialised everything:
        if self._temp_manifest_db_conn is None:
            self._decrypt_manifest_db_file()
        # Use Manifest.db to find the on-disk filename(s) and file metadata, including the keys, for the file(s).
        # The metadata is contained in the 'file' column, as a binary PList file; the filename in 'relativePath':
        try:
            cur = self._temp_manifest_db_conn.cursor()
            query = """
                SELECT fileID, relativePath, file
                FROM Files
                WHERE relativePath LIKE ?
                AND flags=1
                ORDER BY domain, relativePath;
            """
            cur.execute(query, (relative_paths_like,))
            results = cur.fetchall()
        except sqlite3.Error:
            return None
        # Ensure output destination exists then loop through matches:
        os.makedirs(output_folder, exist_ok=True)
        for file_id, matched_relative_path, file_bplist in results:
            filename = os.path.basename(matched_relative_path)
            output_path = os.path.join(output_folder, filename)
            # Decrypt the file:
            decrypted_data = self._decrypt_inner_file(file_id=file_id, file_bplist=file_bplist)
            # Output to disk:
            if decrypted_data is not None:
                with open(output_path, 'wb') as outfile:
                    outfile.write(decrypted_data)

    def fetch_files_from_directory(self, directory):
        """
        Fetch all files underneath a given directory/domain.

        :param directory: The directory or domain to search files in.
        :return: A list of fileIDs of files underneath the given directory.
        """ 

        # Use SQL to fetch all files under the directory:
        try:
            cur = self._temp_manifest_db_conn.cursor()
            
            # If you pass a domain as the directory, adjust the query:
            if directory.endswith('/'):
                domain_name = directory.rstrip('/') 
                query = """
                    SELECT fileID
                    FROM Files
                    WHERE domain = ?
                """
                cur.execute(query, (domain_name,))
            else:
                query = """
                    SELECT fileID
                    FROM Files
                    WHERE relativePath LIKE ? || '%'
                """
                cur.execute(query, (directory,))
            
            return [row[0] for row in cur.fetchall()]
        except sqlite3.Error as e:
            print(f"Error occurred during fetch_files_from_directory: {e}")
            return []


    def download_file(self, file_id, output_folder):
        """
        Download (and decrypt if necessary) the file based on its fileID, then save it to the specified folder.
        
        :param file_id: The unique identifier of the file you want to download.
        :param output_folder: The directory where you want to save the file.
        :return: The path to the saved file or None if there was an error.
        """
        
        # Get the relative path and file metadata for the given fileID
        query = """
            SELECT domain, relativePath, file
            FROM Files
            WHERE fileID = ?
        """
        
        try:
            cur = self._temp_manifest_db_conn.cursor()
            cur.execute(query, (file_id,))
            result = cur.fetchall()

            # Debugging: print the number of rows and the problematic file_id
            #print(f"Number of rows for file_id {file_id}: {len(result)}")
                
            if len(result) == 0:
                print(f"No file found for fileID: {file_id}")
                return None

            domain,relative_path, file_bplist = result[0]
            if not relative_path:
                print(f"Empty relativePath for fileID: {file_id}")
                return None
            #print(f"Relative path for file_id {file_id}: {relative_path}")
         


            file_path_in_backup = os.path.join(self._backup_directory, file_id[:2], file_id) 
            
            # Verify if the source file exists
            if not os.path.exists(file_path_in_backup):
                print(f"Error: Source not found> {relative_path} ::::::: {file_path_in_backup}")
                return None

            #output_file_path = os.path.join(output_folder, os.path.basename(relative_path))
            output_file_path = os.path.join(output_folder, domain, relative_path)

            # Check if the content is a directory
            # Ensure the parent directory exists
            parent_directory = os.path.dirname(output_file_path)
            os.makedirs(parent_directory, exist_ok=True)
            
            file_data_object = biplist.readPlistFromString(file_bplist)
            
            # If the file has encryption data, then decrypt it. Otherwise, just copy it
            if "EncryptionKey" in file_data_object:
                decrypted_content = self._decrypt_inner_file(file_id=file_id, file_bplist=file_bplist)
                # If decrypted_content is None or empty, then there's an error in decryption or fetching
                if decrypted_content is None or len(decrypted_content) == 0:
                    print(f"Error: Empty content for {output_file_path}. Might be an issue with decryption or data retrieval.")
                else:
                    # Write the content to the file
                    with open(output_file_path, 'wb') as out_file:
                        out_file.write(decrypted_content)
            else:
                print(f"File {file_id} is not encrypted. Directly copying..."+ output_file_path)
                shutil.copy2(file_path_in_backup, output_file_path)

            return output_file_path
            
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error: {e}")
            return None



    def extract_all_files_to_structure(self, *, output_folder):
        """
        Decrypt all files and output them to a folder, preserving their relative paths.

        :param output_folder: The folder to write output files into. 
            The relative path structure will be maintained within this directory.
        """
        # Ensure that we've initialised everything:
        if self._temp_manifest_db_conn is None:
            self._decrypt_manifest_db_file()

        # Regular expression to replace invalid filename characters:
        invalid_chars_pattern = re.compile(r'[\\/:*?"<>|]')

        # Use Manifest.db to get all the files
        try:
            cur = self._temp_manifest_db_conn.cursor()
            query = """
                SELECT fileID, relativePath, file
                FROM Files
                WHERE flags=1
                ORDER BY domain, relativePath;
            """
            cur.execute(query)
            results = cur.fetchall()
        except sqlite3.Error:
            print("Error querying the database.")
            return None

        # Loop through matches:
        for file_id, matched_relative_path, file_bplist in results:
            # Sanitize the relative path by replacing invalid characters:
            sanitized_path = invalid_chars_pattern.sub('_', matched_relative_path)

            # Adjust the output path to maintain folder structure:
            output_path = os.path.join(output_folder, sanitized_path)
            output_directory = os.path.dirname(output_path)

            # Ensure output destination exists:
            os.makedirs(output_directory, exist_ok=True)

            # Decrypt the file:
            try:
                decrypted_data = self._decrypt_inner_file(file_id=file_id, file_bplist=file_bplist)
                
                # Output to disk if successfully decrypted:
                if decrypted_data is not None:
                    with open(output_path, 'wb') as outfile:
                        outfile.write(decrypted_data)
            except Exception as e:
                print(f"Error occurred while processing file {matched_relative_path}. Error: {str(e)}")


from iphone_backup_decrypt import EncryptedBackup, RelativePath, RelativePathsLike

passphrase = "sssssss"  # Or load passphrase more securely from stdin, or a file, etc.
backup_path = "C:\\backup\\9fa89e421d6261a32a0d4b871ebe830f5489e900"

backup = EncryptedBackup(backup_directory=backup_path, passphrase=passphrase)

 
########### 
# # Extract all photos from the camera roll:
backup.extract_files(relative_paths_like=RelativePathsLike.PHOTO_STREAM,
                     output_folder="./output/photo_stream")

backup.extract_files(relative_paths_like=RelativePathsLike.SMS_ATTACHMENTS,
                     output_folder="./output/smsattach/")


########### 
# Extract WhatsApp SQLite database and attachments:
backup.extract_file(relative_path=RelativePath.WHATSAPP_MESSAGES,
                    output_filename="./output/whatsapp.sqlite")
backup.extract_files(relative_paths_like=RelativePathsLike.WHATSAPP_ATTACHMENTS,
                     output_folder="./output/whatsapp")


########### 
# This just copies everything from backup to output folder, it's messy but sometimes useful.
try:
    backup.extract_all_files_to_structure(output_folder="./output/all/")

except Exception as e:
    print(f"Error occurred: {e}")

########### 
# This just copies everything from backup to output folder, it's messy but sometimes useful. 

# try:
#     dirs_with_most_files = backup.fetch_directory_with_most_files()
#     print(dirs_with_most_files)

#     # Iterate over directories and download all files under each directory
#     for directory, _ in dirs_with_most_files:
#         files_in_directory = backup.fetch_files_from_directory(directory)
        
#         # Specify the output folder where you want to download the files
#         output_folder = f"./output/all/{directory.replace('/', '_')}/"  # Replace '/' with '_' to avoid subdirectories

#         for file_id in files_in_directory:
#             backup.download_file(file_id, output_folder)

# except Exception as e:
#     print(f"Error occurred: {e}")

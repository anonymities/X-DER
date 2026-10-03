import os
import shutil

def remove_folder(folder_path):
    """
    Delete the specified folder and all its contents
    :param folder_path: Path of the folder to be deleted
    """
    # Delete all files and subfolders first
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        # Delete if it's a file
        if os.path.isfile(file_path):
            os.unlink(file_path)
        # Recursively delete if it's a subfolder
        elif os.path.isdir(file_path):
            shutil.rmtree(file_path)
    # Delete the empty folder itself
    os.rmdir(folder_path)
    print('|' + ' ' * 5 + f"Folder '{folder_path}' has been deleted successfully")
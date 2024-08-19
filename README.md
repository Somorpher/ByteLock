# Diskryp

### verify hash

 SHA256 Digest.
> d1d11d1f78544ee59b155e671f80ec880dab27ae1e6189e1a5614f4bcbe75ecd

Functionalities:

    Command-Line Interface (CLI) Handling:
        The code allows users to supply various command-line arguments to control the program's execution. Parameters include secret keys, target files or directories for encryption/decryption, backup options, and verbosity of output.

    File and Directory Management:
        The program can handle both individual files and entire directories. It reads the contents of a specified target, encrypts or decrypts the data, and saves the results either in the same location or, optionally, in a backup directory.

    Encryption and Decryption:
        It uses an encryption method (Galois/Counter Mode, AES algorithm) to secure data. The user can specify whether to encrypt or decrypt data, and the logic for both processes is built into the respective function calls.

    User Prompts and Feedback:
        The application can operate in a direct execution mode, where it skips user prompts for confirmations, or in an interactive mode where the user is prompted for confirmation before actions are taken.
        Verbose mode provides feedback in the console about the actions being performed, making it easier to track the process flow.

    Backup Creation:
        Before modifying any data, the application can create backups of files or directories, ensuring data safety in case of accidental loss or corruption during the encryption/decryption process.

    Detailed Commands:
        Users can input various commands to change settings like whether to run recursively, to show current configurations, or to exit the application.

    Error Handling:
        The code includes mechanisms to handle various runtime errors gracefully, providing feedback to the user when something goes wrong, thus enhancing usability.

Intended Uses:

    This application is intended for users who need to secure their data by encrypting files before sharing or storing them, especially sensitive information.
    It can also serve to reverse the encryption process to regain access to the original data.
    The backup feature ensures that users can recover their data if needed without losing any original files.

Expected Behavior:

    Upon running the application, users are expected to provide appropriate command-line arguments or interact with the prompt to set parameters for their encryption/decryption tasks.
    The application will verify provided arguments, like ensuring the presence of a secret key and a target path before proceeding with operations.
    Appropriate confirmation prompts will guide the user through the process, especially when critical actions are about to be taken, thereby minimizing the risk of unintended data loss.

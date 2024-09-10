# Diskrypt: File/Dir Encryption Software

[![MIT License](https://img.shields.io/badge/License-MIT-orange.svg)](https://github.com/Somorpher/Diskrypt/blob/main/LICENSE) 


FSController: [FSController](https://github.com/Somorpher/FSController)

ByteCrypt: [ByteCrypt](https://github.com/Somorpher/ByteCrypt)

## Execute from console
![App Screenshot](https://github.com/Somorpher/Diskrypt/blob/main/images/remove_image_metadata_9a87000841f99aecc78ee21c90c5162e_66c278b6a4795.png)

## Command Options
![App Screenshot](https://github.com/Somorpher/Diskrypt/blob/main/images/remove_image_metadata_178e06d8f3e02dd5d30b1aaf62a0c2d7_66c278b6a839a.png)

This C++ code is for a command-line utility that provides file system encryption and decryption capabilities. It's designed to work with both files and directories.

The code starts by including necessary headers for file system operations and encryption/decryption. It then defines some compiler-specific optimization attributes and constants for things like maximum subset size and secret block size thresholds.

Next, it defines an enumeration for operation modes (encryption, decryption, or none) and a struct to hold various flags for the utility, such as whether to backup files before encryption, whether to use recursive execution, and so on.

The main function collects command-line arguments using the GetCLI function, which parses the arguments and sets the corresponding flags. If the direct_execution flag is set and the operation mode is not none, it calls the execute_command function to perform the encryption or decryption.

The GetCLI function takes the command-line arguments and sets the flags accordingly. It also handles cases where the user requests help or wants to exit the program.

The execute_command function performs the actual encryption or decryption. It creates a FSController object to manage file system operations and a ByteCrypt object to handle encryption and decryption. It then checks if the target path is a file or directory and calls the corresponding encryption or decryption function.

The encryption and decryption functions use the gcm algorithm from the ByteCrypt object to encrypt or decrypt the file or directory contents. They also handle errors and exceptions that may occur during the process.

The code also includes several helper functions, such as prompt_path_to_target, prompt_secret_key, and print_current_conf_parameters, which are used to prompt the user for input or print the current configuration parameters.

The print_man and print_man_interface functions print the manual and interface help screens, respectively. The show_target_content function displays the contents of the target path.

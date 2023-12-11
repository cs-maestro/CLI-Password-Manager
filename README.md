# CLI-Password-Manager

Implements a terminal-based password manager program. Features include:
-  Ability it create new passwords for websites. Information includes optional
   username, email address, or phone number for the user option, a password
   string, website url, and a website nickname. For user option, multiple
   choices can be made. E.g. a username string and an email address.
-  Automatically checks for duplicate passwords and warns user.
-  Automatically checks for password strength and gives user a warning.
-  Ability to search for account info based on username, website nickname,
   and password. User can then add new usernames, edit existing entries, and
   view passwords.
- **** Tentative *** Ability to copy password to clipboard, and ability to check duplicates
-  Encrypts password using AES-128 with an Argon2 hash.
-  Ability to import and export password files to another instance of program.

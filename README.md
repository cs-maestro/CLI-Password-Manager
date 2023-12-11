# CLI-Password-Manager

Implements a terminal-based password manager program. Features include:
-  Ability it create new passwords for websites. Information includes optional
   username, email address, or phone number for the userkey option, a password
   string, website url, and a website nickname. For user option, multiple
   choices can be made. E.g. a username string and an email address.
-  Automatically checks for duplicate passwords and warns user. Notifies user
   of password strength and warns user if it is weak.
-  Check for valid url.
-  Automatically checks for password strength and gives user a warning.
-  Ability to search for account info based on userkey, website nickname,
   and password. User can then add new usernames, edit existing entries, and
   view passwords.
-  Ability to copy password to clipboard.
-  Encrypts password using AES-128 with an Argon2 hash.
-  Ability to import and export password files to another instance of program.
-  Associates unique nickname with each url, if a duplicate website nickname is entered,
   then auto fills with associated url. If duplicate url is put for a different nickname,
   forces user to either change the url or nickname.
-  Encrypts files using AES encryption. Passwords are generated using Argon2 hash.
-  Ability to remove/edit information on existing accounts.
-  Automatically checks for duplicate account information and tells user.

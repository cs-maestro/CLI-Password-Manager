# CLI-Password-Manager

The plan for this project is to create a terminal-based local password manager for Haskell. This
program would have several features and functionality from standard password managers, as well as
some additional functionality that would hopefully allow it to stand apart from existing password
managers. Broadly, the main features of this program would include the hashing/encryption of the
password database info behind a master password, searching functionality for passwords in the
database, importing/exporting functionality to share info between computers, suggestions for newly
created and existing passwords, ability to generate random passwords for the user, and the ability to
store passwords under several categories.

The first feature would include the hashing and encryption of data. The plan is to assign each
instance of the program a randomized salt upon the first installation of the program. The user then
creates a master password, which when hashed with the salt generates a key for the password database
encryption. This key will then allow the program to encrypt and decrypt this file. To verify the
authenticity of the password, a MAC-then-encrypt (MtE) scheme will be used as a form of authenticated
encryption. The hashing algorithm for the key generation is planned to be PBKDF2, and the symmetric
AES algorithm will be used for encryption. The hash used to check file integrity in the MtE scheme is
planned to be SHA-2.

Users will be allowed to add new passwords to the program with several associated criteria.
First, each password is associated with a website. This includes a user specified website name and
associated URL pair. Also associated with the password is a generic keyword which can include multiple
subcategories including: username, email, phone number, and miscellaneous. Each password can have
multiple subcategories of general keywords associated with it, but it must have at least one. The user
can also specify an account name so that a website can have multiple passwords associated with it.
Upon generation of the password, the user may be offered several suggestions by the program
to assess the strength of the password. These suggestions could include prompting the user if the
passsword lacks symbols/numbers, if the length is short, and if the password matches any existing
passwords and, if so, how many. Through the search functionality, the user can also request these
prompts for any previously generated password.

Additional functionality could also include the ability of the user to request a prompt stating
how long it would take a hacker to brute-force the password and the ability to generate a random
password for a site and copy it to the user’s clipboard. Options for this random password would include
if it should contain symbols and/or numbers and what the length should be. The user can also request
that the password contains some specified keyword randomly within it.

The user can also search the password database for a given password based on several search
criteria including the literal password string, the website, the general keyword, or any of its
subcategories. If the user searches by site, they can also specify an account name. To prevent accidental
renaming of a website, websites are uniquely identified by their URL. This is done when a person creates
a new password. When the user enters the website name, the program will automatically create a list of
5 URLs that most closely match the given website name. The user can then choose from one of these
URLs or choose to manually enter a URL. This automatic URL list is generated by taking the first five
results from google using the Gogol-custom search SDK for Haskell. Finally, if time permits, we plan to
add import and export features for the password information by adding the ability to export and import
the raw encrypted data file associated with the program.



v0.0.1
Init of PyPass
- Added a few functions to manage passwords/OTP
- Added an option to export/import passwords
- Features are still in development and may not work as expected
- Anti-Brute Force protection was implemented partially
- Added a few tests to check the integrity of the database
- Anti-Bypass by changing the system time was partially implemented

v0.0.2
Bugfixes and improvements
- Fixed a bug where the master password was not set correctly
- Fixed a bug where the master password was not checked correctly
- Fixed a bug where the security hash was not updated correctly
- Fixed a bug where the security hash was not checked correctly
- 256-bit AES-GCM encryption of logins and passwords
- TOTP partially added
- Rebase file structure and removed unnecessary files
- Security improvements

v0.0.3
Bugfixes and optimizations
- Fixed a bug where salt was not generated correctly when the program was started for the first time
- Added explanations for the code to simplify collaboration
- Removal of unnecessary functions

v0.0.4
Added comments and explanations
- Added comments to the code to make it easier to understand
- Added explanations for the functions to simplify collaboration
- TODO : bug fix in list passwords - add a pin ?

v0.0.5
Bugfixes and optimizations 🐛
- New database structure for passwords encryption (in progress) 🏗️
- Fixed a bug where the password and username were not encrypted and decrypted correctly 🛡️
- Encryption and decryption of passwords and usernames are now done separately 🛡️
- Encryption and decryption system improved ✨
- Optimized salt in main (already generated) 🧂
- Updated password_utils.py and security.py to use the new encryption system 🛡️
- New utility functions optimized by @Yoann were added to utils.py 🛠️
- New TODO file added to keep track of the tasks to be done 📝
> Git modifications :
- Added a new branch "list-passwords" to work on the list passwords feature 🌿
- Merging the "list-passwords" branch into the "opti" branch 🌿
- Merging the "opti" branch into the "main" branch 🌿
- Added a new branch "pin" to work on the pin feature 🌿
- Removed branch "facial-recognition" (not used) 🌿





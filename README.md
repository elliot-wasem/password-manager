# password-manager

This is a dmenu-driven password manager that will let you store and retrieve passwords. It will copy the password for your selected account to your clipboard. I make no guarantees about being cryptographically secure. I believe it is secure enough, but I'm waiting on expert opinion still.

## Setup

As it is dmenu-driven, it depends on dmenu! Surprise!!! It also depends on xclip.

Also, I've only tested it on Arch Linux. If you do not provide a script (as explained below), it defaults to `/usr/bin/dmenu`.

This program requires at least the password file you wish to use/generate as an argument, with an optional argument pointing to a dmenu-wrapper script. Please make it a shell script, I'm not sure this program could handle whatever other weird scripts you have cooked up and I don't feel like testing it as such. Please note, if your dmenu-wrapper script has a prompt built into it, my program will likely override that prompt.

```
Usage: ./password-manager <password file> [some-dmenu-wrapper.sh]
```

You will be greeted initially with a prompt to enter master password. If the file does not yet exist, this will become your master password!

## Using the program

Once you have entered a master password, you will be greeted with a lovely prompt with the following options.

### Select

This will let you select an existing account/password pair, and copy the password to your clipboard.

### Add

This will let you add a new account/password pair. If the account name already exists in the file, it will not make any changes, and will simply return you to the previous menu.

### Change

This will let you change an existing account/password pair if it already exists in the file. If it does not exist (say you typed in your own account name instead of selecting from menu), it will add it to the file.

### Delete

This will let you delete an existing account from the password file.

### Purge File

This will let you erase all contents of file, replacing it with all random bytes. The file will still exist.

### Change Master Password

This will allow you to change the master password, which will also rewrite the whole file, re-encrypting it against the new password.

### Exit

This will exit the program.

### ..

Some menus have `..` as an option. This just returns you to the previous menu without making changes.

### \*\*\* Notes \*\*\*

`Add`, `change`, `delete`, `purge`, and `change master password` will prompt you to confirm that you are sure you want to make changes. This defaults to "No", but be careful!


Hitting `ESC` at any time will cancel any changes pending, and will leave the file in the last state, fully exiting the program.

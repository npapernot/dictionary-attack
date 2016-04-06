# Dictionary Attack
This repository contains a simple example of a dictionary attack coded in Java.

## Description of Repository Content

Here are the files you can find in this repository:
* `password.txt` contains a list of passwords that we recover using the attack
* `DictionaryAttack.java` is the source code for the attack
* `english.0` is the dictionary used during the attack to recover passwords

## Description of the `password.txt` file format

The list of passwords that we recover using the attack is a text file in which
each line contains a user account name followed by a password. There are two 
possible line formats: the first one contains an unsalted password while the 
second contains a salted password along with the salt. 

```
username 0 unsaltedpassword
username 1 salt saltedpassword
```

The passwords are hashed using SHA-1 (see attack source code for implementation
in the Java Cryptography Extension). When a salt is used, it is simply concatenated together with the passwords as follows: `salt || password`.

## Description of the attack

The attack simply reads the dictionary line by line and computes 6 different 
possible hashed passwords for the word contained in each line. These 6 possible
hashes are compared to each of the passwords contained in the `password.txt` 
file for a match. If there is a match, we recovered a password. If not, we 
simply keep reading the dictionary line by line. 

The 6 possible hashes computed for each `word` from the dictionary are:
* `SHA1(word)`
* `SHA1(drow)` (reversed word)
* `SHA1(wrd)` (word without vowels)
* `SHA1(salt||word)` (salted word)
* `SHA1(salt||drow)` (salted reversed word)
* `SHA1(salt||wrd)` (salted word without vowels)

Note that the salts used in salted hashes are the ones includes in the 
`password.txt` file.

## How to run the attack

To run the attack, simply compile and run the `DictionaryAttack.java` file.
All paths are hardcoded in the file so you will need to update them before 
you compile the source code. 

The output should be the following:
```
Let's get things started.
joe's password is 'December'
alice's password is 'tfosorciM'
mary's password is 'Monday'
john's password is 'brosba'
bob's password is 'yllacitebahpla'
guy's password is 'ntrstwrthnss'
nick's password is 'uplifting'
adam's password is 'vsblts'
eve's password is 'wrrsm'
andrew's password is 'kcitsdray'
The program terminated.
```

## Note on complexity

Note that this attack is a simple example and could be made far more efficient
using various strategies. One of them would be to precompute the possible 
hashes before checking the password list for matches. Since our password list
and dictionary are fairly small in this example, I did not implement this 
feature.  


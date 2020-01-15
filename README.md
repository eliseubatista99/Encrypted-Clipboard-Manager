# Encrypted-Clipboard-Manager
Group Project: An Encrypted Clipboard Manager made to Computer Security

## Objective

The main goal of this project is to develop a Clipboard manager with some built-in security. These managers are programs that allow you to save your entire history of using Clipboard, and even access previous entries quite easily, being a useful feature and one of the main motivations for its existence.

The problem is that some (if not all) Clipboard managers save the history in a clear text text file, 
including passwords that may be being copied from a password manager to an online form, so
exposed to Trojan horses or even competing users of the system. The program developed in the context of this project is 
intended to solve this problem and add value by supporting the following features:

• Clipboard history must be stored encrypted with a cipher (and cipher mode) of
recognized quality (e.g., Advanced Encryption Standard (AES));
• The encryption key must be generated when the manager is executed and stored only in memory. 
The generation of the encryption key must be done safely;
• the history should be saved to disk (encrypted) every 5 minutes (deleting the previous one);
• hash values ​​must be created for each entry in the history, which must be stored in clear text in a separate file;
• It must be possible to check whether a particular entry exists in the last cipher history file without decrypting 
it and using only hash values.
• a digital signature of the encrypted file must be made when it is stored in the disc (i.e. every 5 minutes). 
To do so, a Rivest, Shamir, and Adleman (RSA) key pair must be generated that accompanies the application. 
This project assumes the development of an application that seeks to get Clipboard entries in the background.
To do so, you might consider running it like a daemon that does CTRL + V every 2 seconds, hoping to find a new entry.
Eventually you can further develop an application for setting some parameters (e.g., how many inputs are supported).

The main application should allow you to view the various entries in the Clipboard 
and also choose which one to go there by double clicking. Note that in the simplest version of the application, 
the history is lost whenever it is terminated (because the encryption key that allows decrypting the file is only stored in memory).

A more elaborate version of the application should have additional functionality, as suggested below:

• The manager must support the generation of encryption keys from a pinch of salt and a master password set by the user upon first use. For this purpose a cipher key derivation function such as
PBKDF2;
• By taking previous functionality for granted, the manager should be able to decipher previous history files.
• By taking the above functionality for granted, the manager should be able to decipher very selectively only the entries selected by the user. This feature requires that a suitable cipher mode be used;
• the manager must support multiple users (each user will have their history);
• signatures must be verified at the user's request;
• allow client programs to use digital certificates to validate digital signatures;
• write a fairly complete help.

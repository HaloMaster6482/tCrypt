# tCrypt

tCrypt is a simple command-line tool for locking files and secret messages.

It keeps one hidden key file in your home folder so you do not need to remember a password every time.

## Highlights

- AES-256-GCM encryption
- One hidden key file stored in your home folder
- Encrypt and decrypt files
- Encrypt and decrypt messages
- Friendly terminal output that is easy to read

## Install

```bash
pip install tcrypt
```

If you are testing a release from TestPyPI, use this instead:

```bash
pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ tcrypt==0.1.0
```

## Usage

The first time you use tCrypt, it creates a hidden key file at `~/.tcrypt.key`.

Check where the key file is:

```bash
tcrypt key path
```

Encrypt a file:

```bash
tcrypt encrypt-file notes.txt
```

Decrypt a file:

```bash
tcrypt decrypt-file notes.tcrypt
```

Encrypt a secret message:

```bash
tcrypt encrypt-message "I hid the treasure under the bed"
```

Decrypt a secret message:

```bash
tcrypt decrypt-message "PASTE_THE_ENCRYPTED_TEXT_HERE"
```

Save the encrypted message to a file:

```bash
tcrypt encrypt-message "Meet me after school" --output message.txt
```

Save a decrypted message to a file:

```bash
tcrypt decrypt-message "PASTE_THE_ENCRYPTED_TEXT_HERE" --output note.txt
```

## How It Works

1. tCrypt creates one hidden key file the first time you run it.
2. That key stays in your home folder so the tool is easy to use later.
3. Your file or message is locked with that key.
4. Only tCrypt can unlock it with the same key file.

## Safety Tips

- Do not delete the hidden key file unless you want to lose access to old encrypted data.
- Keep a backup of `~/.tcrypt.key`.
- Share encrypted messages, not the key file.
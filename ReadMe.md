# LastPass Vault Parser

***WARNING:  
Only use this script on a trusted / secure computer!  
This script does NOT follow secure coding practices, and is NOT meant to withstand ANY kind of attacks.  
Do NOT use this script if you're paranoid.***

---

This script exports your LastPass vault's content into several CSV files. It exports far more information than [LastPass's built-in export function](https://lastpass.com/support.php?cmd=showfaq&id=1206).

Depending on the availability of relevant data in your vault, the following CSV files will be exported:
* **Sites_and_SecureNotes.csv**
* **SitesFormFields.csv** - The complete version. Abridged form fields are already included in _Sites_and_SecureNotes.csv_.
* **FormFills.csv**
* **Applications.csv** - Only exist if you've ever used [LastPass for Applications](https://helpdesk.lastpass.com/lastpass-for-applications/).
* **ApplicationsFields.csv** - Only exist if you've ever used [LastPass for Applications](https://helpdesk.lastpass.com/lastpass-for-applications/).
* **Attachments.csv** - Meta data only. Actual attachments are not available in the vault file.
* **EquivalentDomains.csv**
* **UrlRules.csv**

## Dependencies

To use the Python script directly:
* Python 3.6+
* package *cryptography*  
run `pip install --upgrade cryptography` to install

To use the Windows binary (download on the [releases](https://github.com/cfbao/lastpass-vault-parser/releases) page)
* on Windows 7: Windows update [KB2999226](https://support.microsoft.com/en-gb/help/2999226/update-for-universal-c-runtime-in-windows "Update for Universal C Runtime in Windows") (should have already be installed on an up-to-date system)
* on Windows 8+: None.


## How-to

Download `lpparser` ([.py](https://raw.githubusercontent.com/cfbao/lastpass-vault-parser/v0.1.1/lpparser.py) or
[.exe](https://github.com/cfbao/lastpass-vault-parser/releases/download/v0.1.1/lpparser.exe)), and run it directly.
It will prompt you to enter the path of your vault file, path of the output directory, LastPass account e-mail, (potentially) password iterations, and master password.
`lpparser` works 100% locally and makes absolutely no use of Internet connections.

Ideally, the output directory should be a new or empty directory residing on an encrypted drive or a RAM disk. Sensitive data should never be saved on disk unencrypted.

You may opt to not enter your master password. Then any encrypted data would be exported in the format of  
`!<initialization-vector-b64encoded>|<AES-CBC-encrypted-blob-b64encoded>`  
It should look something like  
`!ztYeRZRUvd/nRq9IuNn8ug==|G7ikJAmh/maa+PR3sQg+NL8ixNR0LKr73/xfKU6wV6Q=`

**LastPass does not encrypt everything in your vault.**
By not entering your master password, you can see what is unencrypted, and make sure no private data is unintentionally leaked.


### What is "vault file" and how do I find/get it?

#### Option 1: Chrome extension database (_Recommended_)
Use the LastPass extension for Chrome, and the extension database file is your vault file.
See this [LastPass FAQ](https://lastpass.com/support.php?cmd=showfaq&id=425) on locating your Chrome extension database.

#### Option 2: Browser network log
1. Open LastPass [login page](https://lastpass.com/?ac=1&lpnorefresh=1) in your browser
2. Press `F12` to open Developer Tools
3. Select the "Network" tab in Developer Tools
4. Start recording network log (if not already started)
5. Log into LastPass through the login page as you normally do
6. Once logged into LastPass, search for "getaccts.php" in the network log, and open this logged event
7. Select the "Response" tab of the logged event, you should see a very long string of random-looking characters.
8. Copy and save this string in a file, which is your vault file.

#### Option 3: LastPass's built-in encrypted export (NOT recommended)
Use any binary installation of LastPass (extension with binary component, LastPass Pocket, etc.) to export an encrypted copy of your vault, which is your vault file.

LastPass's built-in encrypted export contains more information than the plaintext CVS export, but still significantly less information than the first two options. The exported vault format is also slightly different, hence there may be minor parsing errors.

### What is my password iterations?
Typically, you only need to manually enter your password iterations when your vault file is obtained via Option 2.
In this case, you can check your password iterations by searching for "iterations.php" in the same network log.

Alternatively, you can check it via the normal LastPass web interface:  
`Account Settings -> General -> Show Advanced Settings -> Security -> Password Iterations`

Occasionally, if your vault file is obtained via Option 1, the password iterations included with the vault file may be incorrect.
You can override this incorrect value manually by using the command line option `--iterations #`.
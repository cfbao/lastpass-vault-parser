# LastPass Vault Format

### Overall structure of the vault

A LastPass vault consists of multiple data blocks, each with its own structure storing different types of information.
Schematically,

```
vault: {
    data_block;
    data_block;
    ...
    data_block;
};

/* i.e. */

vault = data_block[];
```

### Structure of a data block

```
data_block: {
    byte[4] identifier;  // Four ASCII-encoded capital letters identifying the type of the data block.
    byte[4] size;        // Big-endian 32-bit integer specifying the size of following data.
    byte[size] data;     // Content of this data block. May have internal structures.
};
```

### Some important types of data blocks

Identifier | Description
:--------- | :----------
`LPAV` | Version number of the vault. Must be the first data block to serve as a signature / magic number.
`ENCU` | Encrypted LastPass account email. Used to verify validity of decryption.
`ACCT` | [Sites](https://helpdesk.lastpass.com/adding-a-site/) or [Secure Notes](https://helpdesk.lastpass.com/secure-notes/)
`ACFL` or `ACOF`| Form Fields of Sites
`LPFF` | [Form Fill Profiles](https://helpdesk.lastpass.com/fill-form-basics/)
`FFCF` | [Custom Fields](https://helpdesk.lastpass.com/fill-form-basics/#h3) of Form Fill Profiles
`AACT` | [Applications](https://helpdesk.lastpass.com/lastpass-for-applications/)
`AACF` | Custom Fields of Applications
`ATTA` | Metadata of [Attachments](https://helpdesk.lastpass.com/secure-notes/#h6) to Secure Notes
`EQDN` | [Equivalent Domains](https://helpdesk.lastpass.com/account-settings/#h7)

### Simple and composite data blocks

Data blocks can be categorized into two groups - simple and composite.

* A simple data block's `data` section has no internal structure. It only stores one piece of information.
* A composite data block's `data` section consists of multiple fields:
```
data_block.data: {
    field;
    field;
    ...
    field;
};

/* i.e. */

data_block.data = field[];
```
Each field has the structure
```
field: {
    byte[4] size;       // Big-endian 32-bit integer specifying the size of following data.
    byte[size] data;    // Content of this field. No further internal structures.
};
```

Each field's functionality depends on its position index within the data block.

Of the eleven types of data blocks listed in the previous section, only `LPAV` and `ENCU` are simple data blocks.
The others are all composite data blocks.


### Structures of some types of composite data blocks

Note: only fields whose names are italicized are encrypted. All other fields are NOT encrypted.

#### `ACCT`

Idx | Field Name        | Description
--: | :---              | :--
 0  | aid               | Unique ID for this Site/Secure Note
 1  | _encname_           | Name (encrypted)
 2  | _encgroup_          | Folder (encrypted)
 3  | url               | URL. For Secure Notes this field is `http://sn`
 4  | _extra_             | Notes (encrypted)
 5  | fav               | Added to Favorites (0/1)
 6  | sharedfromaid     | `aid` of the sharer's Site/Secure Note
 7  | _username_          | Username (encrypted)
 8  | _password_          | Password (encrypted)
 9  | pwprotect         | Require Password Repromt (0/1)
10  | genpw             | Is an auto-saved generated password (0/1)
11  | sn                | Is a Secure Note (0/1)
12  | last_touch        | Last used (UNIX timestamp)
13  | autologin         | AutoLogin (0/1)
14  | never_autofill    | Disable AutoFill (0/1)
15  | realm_data        | ???
16  | fiid              | ??? (an unknown ID. Typically identical to `aid`)
17  | custom_js         | JavaScript injected to webpage to find username/password fields
18  | submit_id         | ???
19  | captcha_id        | ???
20  | urid              | ???
21  | basic_auth        | Is a [basic authentication](https://lastpass.com/support.php?cmd=showfaq&id=275) site? (0/1)
22  | method            | `method` attribute of the login form
23  | action            | `action` attribute of the login form
24  | groupid           | ???
25  | deleted           | (0/1)
26  | _attachkey_         | Encryption key for attachments (encrypted)
27  | attachpresent     | Attachments present (0/1)
28  | individualshare   | Is individually shared (as opposed to in a shared folder) (0/1)
29  | notetype          | The type of the note (Generic / Bank Account / Custom etc.)
30  | noalert           | (0/1)
31  | last_modified_gmt | Last modified (UNIX timestamp)
32  | hasbeenshared     | Shared with others (0/1)
33  | last_pwchange_gmt | Last password change (UNIX timestamp)
34  | created_gmt       | Created (UNIX timestamp)
35  | vulnerable        | (0/1)
36  | pwch              | Auto change password supported (0/1)
37  | breached          | (0/1)
38  | template          | Custom template used (JSON format)

Only `encname`, `encgroup`, `extra`, `username`, `password` and `attachkey` are encrypted.

---

*to be continued...*

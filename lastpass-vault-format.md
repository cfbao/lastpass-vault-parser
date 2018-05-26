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

The number of fields in a given type of composite data block is fixed, and each field's functionality depends on its position index within the data block.

Of the eleven types of data blocks listed in the previous section, only `LPAV` and `ENCU` are simple data blocks.
The others are all composite data blocks.


### Structures of some types of composite data blocks

*to be continued...*

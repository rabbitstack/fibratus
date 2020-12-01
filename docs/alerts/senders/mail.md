# Mail

The mail alert sender emits alert notifications through the `SMTP` protocol.

### Configuration {docsify-ignore}

The `mail` alert sender configuration is located in the `alertsenders.mail` section.

#### enabled

Indicates if the alert sender is enabled.

**default**: `false`

#### host

Represents the host name of the SMTP server where the alert notification is sent.

#### port

Represents the port number of the SMTP server.

**default**: `25`

#### user

Specifies the user name when authenticating to the SMTP server.

#### password

Specifies the password when authenticating to the SMTP server.

#### from

Determines the sender's email address.

#### to

Specifies the list of the recipient email addresses.

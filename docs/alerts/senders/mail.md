# Mail

The mail alert sender emits alert notifications through the `SMTP` protocol.

!> If you are using a Gmail SMTP provider, you might need to configure [App Passwords](https://support.google.com/accounts/answer/185833?hl=en) for your account

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

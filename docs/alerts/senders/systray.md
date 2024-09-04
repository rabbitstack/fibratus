# Systray

The `systray` alert sender sends alerts to the systray notification area. 

### Configuration {docsify-ignore}

The `systray` alert sender configuration is located in the `alertsenders.systray` section.

#### enabled

Indicates whether the `systray` alert sender is enabled.

**default**: `true`

#### sound

Indicates if the associated sound is played when the balloon notification is shown.

**default**: `true`

#### quiet-mode

Instructs not to display the balloon notification if the current user is in quiet time. During this time, most notifications should not be sent or shown. This lets a user become accustomed to a new computer system without those distractions. Quiet time also occurs for each user after an operating system upgrade or clean installation.

**default**: `false`


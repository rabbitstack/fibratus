# Slack

The `slack` alert sender forwards alerts to Slack workspaces. You'll have to [activate](https://slack.com/intl/en-es/help/articles/115005265063-Incoming-webhooks-for-Slack) incoming webhooks and associate the webhook to your Slack workspace to be able to emit the alerts.

### Configuration {docsify-ignore}

The `slack` alert sender configuration is located in the `alertsenders.slack` section.

#### enabled

Indicates whether the `slack` alert sender is enabled.

**default**: `false`

#### url

Represents the Webhook URL of the workspace where alerts will be dispatched. The Webhook URL has the following format: `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`.

#### workspace

The name of the Slack workspace where alerts are routed.

#### channel

Is the slack channel in which to post alerts.

#### emoji

Represents the emoji icon surrounded in `:` characters for the Slack bot.

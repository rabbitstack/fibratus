# Rules

CLI filters offer a decent amount of flexibility when digging into the event flux, but they fall short to express complex filtering decisions. This is where rules come to the rescue. Rules are a collection of grouped filters defined in `yaml` files. Each group contains a set of attributes that dictate whether the event passes through the stream or gets dropped. Specifically, the following attributes describe a group:

- **name** associates a meaningful name to the group such as `Suspicious process terminations`
- **selector** indicates the event type or event category that a certain filter group can accept. For example,`CreateProcess` or `registry`
- **enabled** specifies whether the group is active
- **policy** determines the action that's taken on behalf of the incoming event. There are two types of policies: `include` and `exclude`. Include policy filters the event if one of the filters in the group matches, even though this behavior can be tweaked by setting the `relation` attribute. On the other hand, the exclude policy drops the event when a match occurs in the group.
- **relation** controls the group matching criteria. Possible values for the group relation are `and` and `or`. When the `and` relation type is specified, all filters in the group have to match for the event to get accepted. Conversely, the `or` relation type requires only one filter in the group to evaluate to true for accepting the event.
- **filters** contain an array of filtering expressions. Each expression is composed of a descriptive filter name, definition, and an optional action that is executed when the rule is triggered.

### Loading rules {docsify-ignore}

Rules reside inside `%PROGRAM FILES%\Fibratus\Config\Rules` directory.

### Defining rules {docsify-ignore}

### Templating {docsify-ignore}

### Actions {docsify-ignore}

# Paths

As you may have already noticed, different entities can appear in filter fields. For example, `ps` is the root entity that designates the source of process-related values. To access the value from the entity, the __path__ expression is used as a sequence of period-delimited segments that yield the final value. Thus, the `ps.name` field path gives the process name. Paths can be nested, like `ps.parent.handles`, to collect all handle names of the parent process.

Paths can also be constructed in combination with an array or map indexing. Let's take a look at such paths.

### Process ancestry {docsify-ignore}

### Portable Executable {docsify-ignore}

### Environment variables {docsify-ignore}

### Handles {docsify-ignore}

### Modules {docsify-ignore}
# Profiling

[pprof](https://golang.org/pkg/net/http/pprof/) is an extremely useful profiling facility that lets you collect CPU profiles, traces and heap allocation profiles among others. With `pprof` it is easy to spot top CPU consumers or find opportunities for code optimizations.

To get the profile, you can use the `go tool pprof` tool. The pprof HTTP handlers are exposed on `localhost:8482` by default. To override the TCP port or the transport protocol, modify the `api.transport` configuration option. For example, getting the CPU profile could be accomplished with the following command:

```
$ go tool pprof http://localhost:8482/debug/pprof/profile
```

# prodaccess


## Testing

You can run against a local authservice like this:

```bash
go build
./prodaccess -grpc localhost:1214 -tls=false -web http://localhost:1214
```

# Custom Modifications

## Dynamic Account

Based on an opaque token from the client with the following format:

```go
type AccountUser struct {
  AccountName  string `json:"accountName"`
  UserName     string `json:"userName"`
  UserPassword string `json:"userPassword"`
}
```

the backend utilizing auth callouts needs the ability to dynamically create an account.

The client, which must be assumed to be immutable when it comes to credentials, must be able to reconnect even if the backend nats configuration changes.  This means, that we change the signing keys.

We do have an example where this can be done using the `decentralized model` but there is a show stopper issue where the client is required to pass a **sentinel.creds** file that is signed by a private key of a current config.  If we need to repave the backend config with new signing keys, the sentinel.creds file cannot be updated and thus **bricks** the client.  

The credentials are wholy owned and managed by an external entity.

## Running the POC

### nats-server

```powershell
go build .
$env:SERVER_NAME = "Development";  ./nats-server.exe -n "internal-server" -m 8222 -js -debug -c "./examples/centralized/server.conf"
```

## callout-service

```powershell
go build .\examples\centralized\app\.
.\app.exe  callout centralized service
```

## callout-client w/ opaque token

```powershell
go build .\examples\centralized\app\.
.\app.exe  callout centralized client --user.name bob --user.password bob --account.name myaccount
.\app.exe  callout centralized client --user.name bob --user.password bob --account.name myaccount2
.\app.exe  callout centralized client --user.name bob --user.password bob --account.name myaccount3

```

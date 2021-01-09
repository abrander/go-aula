# go-aula

Unusable golang client for the Aula API.

[![GoDoc][1]][2]

[1]: https://godoc.org/github.com/abrander/go-aula?status.svg
[2]: https://godoc.org/github.com/abrander/go-aula

```go
package main

import (
    "github.com/abrander/go-aula"
)

func main() {
    c := aula.NewClient()
    c.Authenticate("username", "password")

    // Do stuff...

    c.Logout()
}
```
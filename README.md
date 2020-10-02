# Go data protection

This library strives to implement a data protection layer, using key rotation and support for distributed key stores.

# Disclaimer: This project is Work In Progress!

## Example

```go
package main

import (
    "fmt"
    "github.com/ourstudio-se/go-dataprotection"
)

func main() {
    p, _ := dataprotection.New(dataprotection.AES256_HMACSHA256)

    protected, _ := p.Protect([]byte("my-secret!"))
    unprotected, _ := p.Unprotect(protected)

    fmt.Println(string(unprotected))
}
```

## Example with keystore on Azure Blob Storage

```go
package main

import (
    "fmt"
    "github.com/ourstudio-se/go-dataprotection"
    "github.com/ourstudio-se/go-dataprotection/azure"
)

func main() {
    p, err := dataprotection.New(dataprotection.AES256_HMACSHA256,
        azure.WithBlob(
            azure.WithCredentials("ACCOUNT_NAME", "ACCOUNT_KEY"),
            azure.WithContainer("my-secret-container")))

    protected, err := p.Protect([]byte("my-secret!"))
    unprotected, err := p.Unprotect(protected)

    fmt.Println(string(unprotected))
}
```

launchkey-go
============

This project is a work in progress SDK for (https://launchkey.com). This project started as a result of my desire to learn Go. The SDK has the same interface exposed by the Python SDK.

## SDK Code Snippets
Get started using this SDK by trying out the following code snippets and reading the official documentation at (https://launchkey.com/docs/api/authentication-flow/).

~~~ go
package main

import "github.com/rakhra/launchkey-go"
import "io/ioutil"
import "fmt"

func main() {
  privateKeyFilePath := "Path"
  privateKeyByteArray , _ := ioutil.ReadFile(privateKeyFilePath)
  privateKey := string(privateKeyByteArray)

  config := launchkey.LaunchKeyConfig {
    AppKey        : "APP KEY",
    SecretKey     : "SECRET KEY",
    PrivateKey    : "PRIVATE KEY",
  }

  api := launchkey.New(config)

  //Ping request
  launchKeyTime, publicKey := api.Ping()
  fmt.Println(launchKeyTime, publicKey)

  //Auth request
  username := "Username"
  authRequest, apiErr := api.Auth(username, true)
  fmt.Println(authRequest, apiErr)

  //Poll request
  auth, userHash, apiErr := api.Poll(authRequest)
  fmt.Println(auth, userHash, apiErr)

  //Authorisation check request
  authorised, apiErr := api.IsAuthorised(authRequest, auth)
  fmt.Println(authorised, apiErr)

  //Logout request
  success, apiErr := api.Logout(authRequest)
  fmt.Println(success, apiErr)
~~~

package launchkey

import (
  "encoding/json"
  "crypto/rsa"
  "net/http"
  "net/url"
  "strconv"
  "strings"
  "errors"
)

const (
  DefaultApiHost = "api.launchkey.com"
  DefaultApiVersion = "v1"
)

type PinHandler interface {
  ValidatePins([]string, string) bool
}

type LaunchKeyAPIError struct {
  StatusCode     int `json:"status_code"`
  MessageCode    int `json:"message_code"`
  Message        string `json:"message"`
}

type LaunchKeyConfig struct {
  Version        string
  Host           string
  AppKey         string
  SecretKey      string
  PrivateKey     string
}

type LaunchKey struct {
  PinHandler

  Version        string
  Host           string
  AppKey         string
  SecretKey      string
  PrivateKey     *rsa.PrivateKey
  Scheme         string
}

type PingResponse struct {
  DateStamp      string  `json:"date_stamp,omitempty"`
  Key            string  `json:"key,omitempty"`
  LaunchkeyTime  string  `json:"launchkey_time,omitempty"`
}

type AuthResponse struct {
  AuthRequest    string  `json:"auth_request,omitempty"`
}

type NotifyResponse struct {
  Message        string  `json:"message"` 
}

type PollResponse struct {
  Auth           string  `json:"auth,omitempty"`
  UserHash       string  `json:"user_hash,omitempty"`
}

type DecryptedAuth struct {
  AppPins        string  `json:"app_pins"`
  AuthRequest    string  `json:"auth_request"`
  DeviceID       string  `json:"device_id"`
  Response       string  `json:"response"`
}

func New(config LaunchKeyConfig) *LaunchKey {
  if config.AppKey == "" || config.SecretKey == "" || config.PrivateKey == "" {
    errors.New("Uninitialised LaunchKeyConfig. Ensure values are set on AppKey, SecretKey and PrivateKey.")
  }

  if config.Host == "" {
    config.Host = DefaultApiHost
  }

  if config.Version == "" {
    config.Version = DefaultApiVersion
  }

  launchKey := LaunchKey {
    AppKey : config.AppKey,
    SecretKey : config.SecretKey,
    Version : config.Version,
    Host : config.Host,
    Scheme : "https",
  }

  launchKey.PrivateKey = StringToPrivateKey(config.PrivateKey)
  if launchKey.PrivateKey == nil {
    panic("Malformed private key")
  }


  return &launchKey
}

func (api *LaunchKey) ValidatePins(pins []string, device string) bool {
  return true
}

func (api *LaunchKey) createEndPoint(path string) *url.URL {
  u := url.URL {
    Scheme : api.Scheme,
    Host : api.Host,
    Path : "/" + api.Version + "/" + path,
  }
  return &u
}

func (api *LaunchKey) Ping() (launchKeyTime string, publicKey string) {
  url := api.createEndPoint("ping")
  response, err := http.Get(url.String())
  if err != nil {
    panic(err)
  }
  
  pingResponse := PingResponse{}
  err = json.NewDecoder(response.Body).Decode(&pingResponse)
  if err != nil {
    panic(err)
  }

  return pingResponse.LaunchkeyTime, pingResponse.Key
}

func (api *LaunchKey) prepareAuth() (signature string, encryptedMessage string) {
  launchKeyTime, key := api.Ping()
  signature, encryptedMessage = SignMessage(key, launchKeyTime, api.SecretKey, api.PrivateKey)
  if signature == "" || encryptedMessage == "" {
    panic("Failed to encrypt secret with private key")
  }

  return
}

func (api *LaunchKey) Auth(username string, session bool) (authRequest string, apiError *LaunchKeyAPIError) {
  signature, secret_key := api.prepareAuth()

  values := make(url.Values)
  values.Set("app_key", api.AppKey)
  values.Set("secret_key", secret_key)
  values.Set("signature", signature)
  values.Set("session", strconv.FormatBool(session))
  values.Set("username", username)

  url := api.createEndPoint("auths")
  response, err := http.PostForm(url.String(), values)

  if err != nil {
    return
  }

  apiError = &LaunchKeyAPIError{}
  apiError.StatusCode = (response.StatusCode)
  
  if response.StatusCode >= 300 {
    err = json.NewDecoder(response.Body).Decode(&apiError)

    if err != nil {
      apiError.Message = err.Error()
    }
    return
  } 

  authResponse := AuthResponse{}
  err = json.NewDecoder(response.Body).Decode(&authResponse)

  if err != nil {
    apiError.Message = err.Error()
    return
  }

  return authResponse.AuthRequest, nil
}

func (api *LaunchKey) Logout(authRequest string) (success bool, err *LaunchKeyAPIError) {
  return api.Notify("Revoke", true, authRequest)
}

func (api *LaunchKey) IsAuthorised(authRequest string, authPackage string) (validPin bool, err *LaunchKeyAPIError) {    
  validPin = false
  
  decryptedPackage := string(DecryptMessage(authPackage, api.PrivateKey))
  if decryptedPackage == "" {

    return false, &LaunchKeyAPIError{Message : "Decryption error"}
  }

  decryptedAuth := DecryptedAuth{}
  jsonDecodeErr := json.NewDecoder(strings.NewReader(decryptedPackage)).Decode(&decryptedAuth)
  
  if jsonDecodeErr != nil {
    err = &LaunchKeyAPIError{ Message : jsonDecodeErr.Error() }
    return 
  }

  if authRequest != decryptedAuth.AuthRequest {
    _, err = api.Notify("Authenticate", validPin, authRequest)
    return
  }

  pins := strings.Split(decryptedAuth.AppPins, ",")
  validPin = api.ValidatePins(pins, decryptedAuth.DeviceID)

  if validPin {
    validPin, err = api.Notify("Authenticate", decryptedAuth.Response == "true", authRequest)
  }
  
  return
}

func (api *LaunchKey) Poll(authRequest string) (auth string, userHash string, apiError *LaunchKeyAPIError) {
  signature, secret_key := api.prepareAuth()

  values := make(url.Values)
  values.Set("app_key", api.AppKey)
  values.Set("secret_key", secret_key)
  values.Set("signature", signature)
  values.Set("auth_request", authRequest)

  url := api.createEndPoint("poll")
  url.RawQuery = values.Encode()

  response, err := http.Get(url.String())

  if err != nil {
    panic(err)
  }

  apiError = &LaunchKeyAPIError{}
  apiError.StatusCode = (response.StatusCode)

  if response.StatusCode >= 300 {
    err = json.NewDecoder(response.Body).Decode(&apiError)

    if err != nil {
      apiError.Message = err.Error()
    }
    return "", "", apiError
  } 

  pollResponse := &PollResponse{}
  err = json.NewDecoder(response.Body).Decode(&pollResponse)

  if err != nil {
    apiError.Message = err.Error()
    return "", "", apiError
  }

  return pollResponse.Auth, pollResponse.UserHash, nil
}

func (api *LaunchKey) Notify(action string, status bool, authRequest string) (success bool, apiError *LaunchKeyAPIError) {
  success = false
  signature, secret_key := api.prepareAuth()

  values := make(url.Values)
  values.Set("app_key", api.AppKey)
  values.Set("secret_key", secret_key)
  values.Set("signature", signature)
  values.Set("action", action)
  values.Set("status", strconv.FormatBool(status))
  values.Set("auth_request", authRequest)

  url := api.createEndPoint("logs")

  client := &http.Client{}

  request, err := http.NewRequest("PUT", url.String(), strings.NewReader(values.Encode()))
  request.Header.Set("Content-Type",  "application/x-www-form-urlencoded")

  if err != nil {
    return
  }

  response, err := client.Do(request)

  if err != nil {
    return
  }
  
  apiError = &LaunchKeyAPIError{}
  apiError.StatusCode = (response.StatusCode)

  
  if response.StatusCode >= 300 {
    err = json.NewDecoder(response.Body).Decode(&apiError)

    if err != nil {
      apiError.Message = err.Error()
    }
    return
  } 
    
  notifyResponse := NotifyResponse{}
  err = json.NewDecoder(response.Body).Decode(&notifyResponse)
  
  if err != nil {
    apiError.Message = err.Error()
    return
  }

  success = (notifyResponse.Message == "Successfully updated")
  return success, nil
}

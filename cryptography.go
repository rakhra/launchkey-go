package launchkey

import (
  "crypto"
  "crypto/rand"
  "crypto/rsa"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/x509"
  "encoding/base64"
  "encoding/pem"
  "encoding/json"
)

type SecretKey struct {
    Secret   string  `json:"secret"`
    Stamped  string  `json:"stamped"`
}

func SignMessage(publickey string, time string, secretKey string, privateKey *rsa.PrivateKey) (string, string) {   
  secret := constructSecretKey(secretKey, time)
  publicKeyObj := extractPublicRSAKeyFromPEM([]byte(publickey))
  encryptedmessage := encryptWithAPIPublicKey(publicKeyObj, []byte(secret))
  signedMessage := signWithPrivateKey(privateKey, encryptedmessage) 

  return string(base64Encode(signedMessage)), string(base64Encode(encryptedmessage))
}

func DecryptMessage(message string, privateKey *rsa.PrivateKey) []byte {
  decodedMessage := base64Decode(message)
  decryptedMessage, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, []byte(decodedMessage), nil)
  
  if err != nil {
    return nil
  }

  return decryptedMessage
}

func StringToPrivateKey(privateKey string) *rsa.PrivateKey {
  pem, _ := pem.Decode([]byte(privateKey))
  if pem == nil {
    return nil
  }

  privateKeyObj, err := x509.ParsePKCS1PrivateKey(pem.Bytes)
  if err != nil {
    return nil
  }

  return privateKeyObj
}

func base64Encode(data []byte) string {
  return base64.StdEncoding.EncodeToString(data)
}

func base64Decode(data string) string {
  x, _ := base64.StdEncoding.DecodeString(data)
  return string(x)
}

func signWithPrivateKey(privateKey *rsa.PrivateKey, message []byte) []byte {
  hash := sha256.New()
  hash.Write(message)
  d := hash.Sum(nil)
  
  signedMessage, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, d)
  if err != nil {
    return nil
  }

  return signedMessage
}

func encryptWithAPIPublicKey(publicKey *rsa.PublicKey, message []byte) []byte {
  encryptedMessage, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, message, nil)
  if err != nil {
    return nil
  }

  return encryptedMessage
}

func constructSecretKey(secretKey string, launchkey_time string) string {
  secret := &SecretKey {
      Secret:  secretKey,
      Stamped: launchkey_time,
  }
  jsonSecret, err := json.Marshal(secret)

  if err != nil {
    return ""
  }
  
  return string(jsonSecret)
}

func extractPublicRSAKeyFromPEM(publicKeyByteArray []byte) *rsa.PublicKey {
  pem, _ := pem.Decode(publicKeyByteArray)
  if pem == nil {
    return nil
  }

  key, err := x509.ParsePKIXPublicKey(pem.Bytes)
  if err != nil {
     return nil
  }

  publicKeyObj, ok := key.(*rsa.PublicKey)
  if !ok {
    return nil   
  }

  return publicKeyObj
}

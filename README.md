# RijndaelCryptographyKt

## Setup

- build.gradle

```groovy
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}
```

- app/build.gradle

```groovy
implementation 'com.github.prongbang:RijndaelCryptographyKt:1.0.0'
```

## How to use

```kotlin
val rijndaelCryptography = RijndaelCryptography()
val secretKey = "secret69"
val cipherText = ""
val plaintext = rijndaelCryptography.decrypt(cipherText, secretKey)
```

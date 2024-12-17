# JwtEasy basic use

This library allow to generate and get information from jwt as a easy tool to implemened on your code

## How to start using as a service

To start using as a service you need to register in your dependency injection class, like you can see below:

use from que library
``` C#
using JwtEasy;
```
or 
``` C#
global using JwtEasy;
```

as you prefer and then register on you dependency injection 

```
services.AddScoped<IJwtGenerator, JwtGenerator>();
```

After that you need to invert de control in the constructor class you with to use 

``` C#
public MyClass(IJwtGenerator jwtGenerator)
{
    _jwtGenerator = jwtGenerator;
}
```

## How to start using as a class instance

Just declare a new instance as any other class, as can see below
``` C#
var jwtGenerator = new JwtGenerator();
```

## Required methods

To be able generate tokens with this library, use the required methods below:

``` C#
var token = _jwtGenerator
    .WithSecret("your secret comes here")
    .WithSigningAlgorithm(SecurityAlgorithms.HmacSha256Signature) // you prefered security algorithm comes here
    .GenerateToken(); // use this method to generate a jwt

    // By default a token generated like this get 7 days of expiration
```

> This mehtods are required to be able get a token if you dont implement some of this methods a Exception will happens.

If you want to know you jwt is expired or not use the method from the service or instance IsTokenExpired, returning a boolean result
``` C#
_jwtGenerator.IsTokenExpired(token);
```
remember to pass the token to be validated

## 

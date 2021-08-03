# CSRF

CSRF stands for cross-site request forgery; it is also called XSRF, a one-click attack, and session riding.
It involves an attacker exploiting a user's established trust with some site in a browser.
Attackers exploit the trust a site has for a user by sending unauthorized commands to the site on behalf of the user.

Typically, attackers trick users to send requests to the site in question.
Perhaps the attacker is able to get the user to open a link on a page controlled by the attacker.
This link could execute some action on behalf of the authenticated user unbeknownst to them.

Consider, for example, a case where a user is authenticated to their bank's website.
The user could be fooled to click on a link that sends a transfer request to their bank's site.
Since the user is authenticated, the bank site would presume that this transaction is safe.
However, an attacker owning this malicious link would be able to direct the transfer to an account of their choosing.

This is a package is designed to protect against such attacks in Vapor.

## Further Reading

* OWASP.org has a [good resource on CSRF](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
* Wikipedia, as usual, has a [good overview](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Prevention)

# Protecting Against CSRF Attacks

There are a few ways to protect against this sort of vulnerability.
Since the attack exploits the site's trust of some user, most prevention techniques add authentication information to each request.
Doing so helps the site to disambiguate between authorized and unauthorized requests.

The direction taken by this package is to use sessions. 
The session will hold a secret.
The secret will be used to create a hashed token.
The token will be sent back to clients in the response's header.
Tokens will last as long as the session is viable.

For example, the server will generate a token and set the `"csrf-token"` key in the header like so:

```swift
response.headers.add(name: "csrf-token", value: "some-very-secret-token")
```

Clients are then responsible for sending this key and token with each request for the duration of their session.

The `CSRF` middleware will then guarantee three things:

1. That there is a session
2. That the request contains a key (there are a number of keys used for CSRF prevention)
3. That the key's token matches the secret held by the session 

If any of these conditions fail, then the `CSRF` middleware will throw an error describing the problem.

# Using CSRF in Vapor

The following provides instructions on how to use this package on your site.

## Usage

1. Add the CSRF to your `Package.swift`

```swift
dependencies: [
    ...,
   .package(url: "https://github.com/vapor-community/CSRF.git", from: "3.0.0")
]
```

2. Add `SessionsMiddleware` and `CSRF` middlware in `configure.swift` (or your route group…)

```swift
app.middleware.use(app.sessions.middleware)
app.middleware.use(CSRF())
```

This will create an instance with two important defaults:

* `ignoredMethods` will be set to `[.GET, .HEAD, .OPTIONS]`. These methods will not be submitted to the checks mentioned above. This is fine because these methods are not used to change server state.
* `defaultTokenRetrieval` will be set to `((Request) throws -> Future<String>)`. That is, it will be a function, provided by default, that will take in a `Request` and return a `Future<String>` holding the token if it is found; otherwise, the method will throw an error.

You can customize either of these properties on `CSRF` by passing your preferred values to this initializer.

3. Create the token and set it in the response header

```swift
router.get("test-no-session") { request in
    let response = ...
    response.headers.add(name: "csrf-token", value: CSRF.createToken(from: request))
    return response
}
```

## Usage with Leaf and forms

To use this package in combination with Leaf to protect forms, there is a tag provided for convenience:

* Add `CSRFFormFieldTag` in `configure.swift`

```swift
app.leaf.tags["csrfFormField"] = CSRFFormFieldTag()
```

* Use `CSRFFormFieldTag` in Leaf templates, e.g. like this

```html
<form method="post">

<input type="text" name="username">
<input type="text" name="password">
[…]

#csrfFormField()

<input type="submit" value="Login">
</form>
```

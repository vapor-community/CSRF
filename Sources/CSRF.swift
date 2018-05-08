import Crypto
import Vapor

public typealias TokenRetrievalHandler = ((Request) throws -> Future<String>)

/// Middleware to protect against cross-site request forgery attacks.
public struct CSRF: Middleware, Service {
    private let ignoredMethods: [HTTPMethod]
    private var tokenRetrieval: TokenRetrievalHandler
    private let hasher = CryptoHasher()
    
    struct CryptoHasher {
        func make(_ data: LosslessDataConvertible) throws -> String {
            return try MD5.hash(data).hexEncodedString()
        }
    }

    /// Creates an instance of CSRF middleware to protect against this sort of attack.
    /// - parameter ignoredMethods: An `OptionSet` representing the various HTTP methods. Add methods to this parameter to represent the HTTP verbs that you would like to opt out of CSRF protection.
    /// - parameter tokenRetrieval: How should this type retrieve the CSRF token? Pass nothing if you would like the default retrieval behavior.
    /// - note: See `CSRF.defaultTokenRetrieval(from:)` for the default retrieval mechanism.
    public init(ignoredMethods: [HTTPMethod] = [.GET, .HEAD, .OPTIONS],
         tokenRetrieval: TokenRetrievalHandler? = nil) {
        self.ignoredMethods = ignoredMethods
        self.tokenRetrieval = tokenRetrieval ?? CSRF.defaultTokenRetrieval
    }
    
    public func respond(to request: Request, chainingTo next: Responder) throws -> Future<Response> {
        let method = request.http.method
        
        if ignoredMethods.contains(method) {
            return try next.respond(to: request)
        }
        
        let secret = try createSecret(from: request)
        
        return try tokenRetrieval(request).flatMap(to: Response.self) { token in
            let valid = try self.validate(token, with: secret)
            if valid {
                return try next.respond(to: request)
            } else{
                throw Abort(.forbidden, reason: "Invalid CSRF token.")
            }
        }
    }
    
    /// Creates a token from a given `Request`. Call this method to generate a CSRF token to assign to your key of choice in the header and pass the token back to the caller via the response.
    /// - parameter request: The `Request` used to either find the secret in, or the request used to generate the secret.
    /// - returns: `Bytes` representing the generated token.
    /// - throws: An error that may arise from either creating the secret from the request or from generating the token.
    public func createToken(from request: Request) throws -> String {
        let secret = try createSecret(from: request)
        let saltBytes = try CryptoRandom().generateData(count: 8)
        let saltString = saltBytes.hexEncodedString()
        return try generateToken(from: secret, with: saltString)
    }
    
    private func generateToken(from secret: String, with salt: String) throws -> String {
        let saltPlusSecret = salt + "-" + secret
        let token = try hasher.make(saltPlusSecret)
        return salt + "-" + token
    }
    
    private func validate(_ token: String, with secret: String) throws -> Bool {
        guard let salt = token.components(separatedBy: "-").first else {
            throw Abort(.forbidden, reason: "The provided CSRF token is in the wrong format.")
        }
        let expectedToken = try generateToken(from: secret, with: salt)
        return expectedToken == token
    }
    
    private func createSecret(from request: Request) throws -> String {
        
        let session = try request.session()

        guard let secret = session["CSRFSecret"] else {
            let random = CryptoRandom()
            let secretData = try random.generateData(count: 16)
            let secret = secretData.hexEncodedString()
            session["CSRFSecret"] = secret
            return secret
        }
        
        return secret
    }
    
    private static func defaultTokenRetrieval(from request: Request) throws -> Future<String> {
        
        let promise = request.eventLoop.newPromise(String.self)
        let csrfKeys: Set<String> = ["_csrf", "csrf-token", "xsrf-token", "x-csrf-token", "x-xsrf-token", "x-csrftoken"]
        let requestHeaderKeys = Set(request.http.headers.map { $0.name })
        
        let intersection = csrfKeys.intersection(requestHeaderKeys)
        
        if let matchingKey = intersection.first, let token = request.http.headers[matchingKey].first {
            promise.succeed(result: token)
            return promise.futureResult
        }
        
        request.content.get(at: "_csrf")
            .catchMap { error in
                throw Abort(.forbidden, reason: "No CSRF token provided.")
            }
            .cascade(promise: promise)
        
        return promise.futureResult
    }
}

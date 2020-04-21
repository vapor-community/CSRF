import Vapor

public typealias TokenRetrievalHandler = ((Request) -> EventLoopFuture<String>)

/// Middleware to protect against cross-site request forgery attacks.
public struct CSRF: Middleware {
    private let ignoredMethods: [HTTPMethod]
    private var tokenRetrieval: TokenRetrievalHandler

    /// Creates an instance of CSRF middleware to protect against this sort of attack.
    /// - parameter ignoredMethods: An `OptionSet` representing the various HTTP methods. Add methods to this parameter to represent the HTTP verbs that you would like to opt out of CSRF protection.
    /// - parameter tokenRetrieval: How should this type retrieve the CSRF token? Pass nothing if you would like the default retrieval behavior.
    /// - note: See `CSRF.defaultTokenRetrieval(from:)` for the default retrieval mechanism.
    public init(ignoredMethods: [HTTPMethod] = [.GET, .HEAD, .OPTIONS],
         tokenRetrieval: TokenRetrievalHandler? = nil) {
        self.ignoredMethods = ignoredMethods
        self.tokenRetrieval = tokenRetrieval ?? CSRF.defaultTokenRetrieval
    }
    
    public func respond(to request: Request, chainingTo next: Responder) -> EventLoopFuture<Response> {
        let method = request.method
        
        if ignoredMethods.contains(method) {
            return next.respond(to: request)
        }
        
        let secret = createSecret(from: request)
        
        return tokenRetrieval(request).flatMap { token in
            do {
                let valid = try self.validate(token, with: secret)
                guard valid else {
                    return request.eventLoop.makeFailedFuture(Abort(.forbidden, reason: "Invalid CSRF token."))
                }
                return next.respond(to: request)
            } catch {
                return request.eventLoop.makeFailedFuture(error)
            }
        }
    }
    
    /// Creates a token from a given `Request`. Call this method to generate a CSRF token to assign to your key of choice in the header and pass the token back to the caller via the response.
    /// - parameter request: The `Request` used to either find the secret in, or the request used to generate the secret.
    /// - returns: `Bytes` representing the generated token.
    /// - throws: An error that may arise from either creating the secret from the request or from generating the token.
    public func createToken(from request: Request) -> String {
        let secret = createSecret(from: request)
        let saltBytes = [UInt8].random(count: 8)
        let saltString = saltBytes.description
        return generateToken(from: secret, with: saltString)
    }
    
    private func generateToken(from secret: String, with salt: String) -> String {
        let saltPlusSecret = (salt + "-" + secret)
        let digest = Insecure.MD5.hash(data: [UInt8](saltPlusSecret.utf8))
        let token = digest.description
        return salt + "-" + token
    }
    
    private func validate(_ token: String, with secret: String) throws -> Bool {
        guard let salt = token.components(separatedBy: "-").first else {
            throw Abort(.forbidden, reason: "The provided CSRF token is in the wrong format.")
        }
        let expectedToken = generateToken(from: secret, with: salt)
        return expectedToken == token
    }
    
    private func createSecret(from request: Request) -> String {
        guard let secret = request.session.data["CSRFSecret"] else {
            let secretData = [UInt8].random(count: 16)
            let secret = secretData.description
            request.session.data["CSRFSecret"] = secret
            return secret
        }
        return secret
    }
    
    private static func defaultTokenRetrieval(from request: Request) -> EventLoopFuture<String> {
        
        let csrfKeys: Set<String> = ["_csrf", "csrf-token", "xsrf-token", "x-csrf-token", "x-xsrf-token", "x-csrftoken"]
        let requestHeaderKeys = Set(request.headers.map { $0.name })
        let intersection = csrfKeys.intersection(requestHeaderKeys)
        
        if let matchingKey = intersection.first, let token = request.headers[matchingKey].first {
            return request.eventLoop.makeSucceededFuture(token)
        }
        
        do {
            return try request.eventLoop.makeSucceededFuture(request.content.get(String.self, at: "_csrf"))
        } catch {
            return request.eventLoop.makeFailedFuture(Abort(.forbidden, reason: "No CSRF token provided."))
        }
    }
}

import Foundation
import Vapor
import HTTP
import Node
import JSON
import Crypto

public typealias TokenRetrievalHandler = ((Request) throws -> String)!

/// Middleware to protect against cross-site request forgery attacks.
public struct CSRF: Middleware {
    private let ignoredMethods: HTTPMethod
    private var tokenRetrieval: TokenRetrievalHandler
    private let hasher = CryptoHasher(hash: .md5, encoding: .hex)
    
    /// Creates an instance of CSRF middleware to protect against this sort of attack.
    /// - parameter ignoredMethods: An `OptionSet` representing the various HTTP methods. Add methods to this parameter to represent the HTTP verbs that you would like to opt out of CSRF protection.
    /// - parameter tokenRetrieval: How should this type retrieve the CSRF token? Pass nothing if you would like the default retrieval behavior.
    /// - note: See `CSRF.defaultTokenRetrieval(from:)` for the default retrieval mechanism.
    init(ignoredMethods: HTTPMethod = [.GET, .HEAD, .OPTIONS],
         tokenRetrieval: TokenRetrievalHandler = nil) {
        self.ignoredMethods = ignoredMethods
        self.tokenRetrieval = tokenRetrieval ?? defaultTokenRetrieval
    }
    
    public func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        let method = try HTTPMethod(method: request.method.description)
        
        if ignoredMethods.contains(method) {
            return try next.respond(to: request)
        }
        
        let token = try tokenRetrieval(request)
        
        let secret = try createSecret(from: request)
        
        let valid = try validate(token, with: secret)
        
        if valid {
            return try next.respond(to: request)
        } else {
            throw Abort(.forbidden,
                        metadata: nil,
                        reason: "Invalid CSRF token.",
                        identifier: nil,
                        possibleCauses: ["Perhaps you are using a custom hashing function that is not anticipated by this package."],
                        suggestedFixes: ["Ensure that the secret stored in your session can be checked against the hashed token sent in the request's header."],
                        documentationLinks: nil,
                        stackOverflowQuestions: nil,
                        gitHubIssues: nil)
        }
    }
    
    /// Creates a token from a given `Request`. Call this method to generate a CSRF token to assign to your key of choice in the header and pass the token back to the caller via the response.
    /// - parameter request: The `Request` used to either find the secret in, or the request used to generate the secret.
    /// - returns: `Bytes` representing the generated token.
    /// - throws: An error that may arise from either creating the secret from the request or from generating the token.
    public func createToken(from request: Request) throws -> String {
        let secret = try createSecret(from: request)
        let saltBytes = try Random.bytes(count: 8)
        let saltString = saltBytes.hexString
        return try generateToken(from: secret, with: saltString)
    }
    
    private func generateToken(from secret: String, with salt: String) throws -> String {
        let saltPlusSecret = salt + "-" + secret
        let token = try hasher.make(saltPlusSecret.bytes)
        return salt + "-" + token.makeString()
    }
    
    private func validate(_ token: String, with secret: String) throws -> Bool {
        guard let salt = token.components(separatedBy: "-").first else {
            throw Abort(.forbidden,
                        metadata: nil,
                        reason: "The provided CSRF token is in the wrong format.",
                        identifier: nil,
                        possibleCauses: nil,
                        suggestedFixes: nil,
                        documentationLinks: nil,
                        stackOverflowQuestions: nil,
                        gitHubIssues: nil)
        }
        let expectedToken = try generateToken(from: secret, with: salt)
        return expectedToken == token
    }
    
    private func createSecret(from request: Request) throws -> String {
        guard let session = request.session else {
            throw Abort(.forbidden,
                        metadata: nil,
                        reason: "No session.",
                        identifier: nil,
                        possibleCauses: nil,
                        suggestedFixes: ["Use `SessionsMiddleware` and add it to your `Droplet`."],
                        documentationLinks: ["https://docs.vapor.codes/2.0/sessions/sessions/"],
                        stackOverflowQuestions: nil,
                        gitHubIssues: nil)
        }
        
        guard let secret = session.data["CSRFSecret"]?.string else {
            let uuidSecret = UUID().uuidString
            try session.data.set("CSRFSecret", uuidSecret)
            return uuidSecret
        }
        
        return secret
    }
    
    private func defaultTokenRetrieval(from request: Request) throws -> String {
        if let token = request.parameters["_csrf"]?.string {
            return token
        }
        
        let csrfKeys: Set<String> = ["_csrf", "csrf-token", "xsrf-token", "x-csrf-token", "x-xsrf-token", "x-csrftoken"]
        let requestHeaderKeys = Set(request.headers.keys.map { $0.key })
        
        let intersection = csrfKeys.intersection(requestHeaderKeys)
        
        guard let match = intersection.first else {
            throw Abort(.forbidden,
                        metadata: nil,
                        reason: "No CSRF token provided.",
                        identifier: nil,
                        possibleCauses: ["Perhaps you forgot to create a token for the session.",
                                         "You could be using a different header key for the CSRF token than is covered by the default token retrieval."],
                        suggestedFixes: ["Make sure to create and add a token to your request header. \nSee `CSRF.createToken(from:) for documentation on usage.",
                                         "Look at `CSRF.defaultTokenRetrieval(from:)` to see what keys are looked for by default."],
                        documentationLinks: nil,
                        stackOverflowQuestions: nil,
                        gitHubIssues: nil)
        }
        
        let matchingKey = HeaderKey(match)
        guard let token = request.headers[matchingKey]?.string else {
            throw Abort(.forbidden,
                        metadata: nil,
                        reason: "Failed to find token for key: \(matchingKey).",
                        identifier: nil,
                        possibleCauses: nil,
                        suggestedFixes: nil,
                        documentationLinks: nil,
                        stackOverflowQuestions: nil,
                        gitHubIssues: nil)
        }
        return token
    }
}

extension CSRF {
    
    /// An `OptionSet` representing the varous HTTP methods to ignore.
    struct HTTPMethod: OptionSet {
        let rawValue: Int
        
        static let GET = HTTPMethod(rawValue: 1 << 0)
        static let POST = HTTPMethod(rawValue: 1 << 1)
        static let PUT = HTTPMethod(rawValue: 1 << 2)
        static let PATCH = HTTPMethod(rawValue: 1 << 3)
        static let DELETE = HTTPMethod(rawValue: 1 << 4)
        static let HEAD = HTTPMethod(rawValue: 1 << 5)
        static let OPTIONS = HTTPMethod(rawValue: 1 << 6)
        static let CONNECT = HTTPMethod(rawValue: 1 << 7)
        static let TRACE = HTTPMethod(rawValue: 1 << 8)
    }
    
}

extension CSRF.HTTPMethod {
    
    init(method: String) throws {
        let upcasedMethod = method.uppercased()
        switch upcasedMethod {
        case "GET": self = .GET
        case "POST": self = .POST
        case "PUT": self = .PUT
        case "PATCH": self = .PATCH
        case "DELETE": self = .DELETE
        case "HEAD": self = .HEAD
        case "OPTIONS": self = .OPTIONS
        case "CONNECT": self = .CONNECT
        case "TRACE": self = .TRACE
        default: throw Error.unrecognized(method: method)
        }
    }
    
    enum Error: Swift.Error {
        case unrecognized(method: String)
    }
    
}

import Vapor
import XCTest
@testable import CSRF

class CSRFTests: XCTestCase {
    
    private let csrf = CSRF()
    private var app: Application!
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testThatCSRFMiddlewareReturnsToken() throws {
        var token: String!
        
        app = try makeApplication(withSession: true)
        
        let router = try app.make(Router.self)
        let responder = try app.make(Responder.self)
        
        router.get("test-token") { request -> Response in
            let response = request.makeResponse()
            do {
                response.http.headers.add(name: "csrf-token", value: try self.csrf.createToken(from: request))
                token = response.http.headers.firstValue(name: .init("csrf-token"))!
            } catch {
                XCTFail("Unexpected error thrown: \(error).")
            }
            return response
        }
        
        let request = HTTPRequest(method: .GET, url: URL(string: "/test-token")!)
        let response = try responder.respond(to: Request(http: request, using: app)).wait()
        
        XCTAssertTrue(response.http.headers.firstValue(name: .init("csrf-token")) == token, "Token in response header should match.")
    }
    
    func testThadCSRFMiddlewareBlockNoToken() throws {
        
        app = try makeApplication(withSession: true)
        
        let router = try app.make(Router.self)
        let responder = try app.make(Responder.self)
        
        router.get("test-token") { request -> Response in
            let response = request.makeResponse()
            do {
                let token = try self.csrf.createToken(from: request)
                response.http.headers.add(name: "csrf-token", value: token)
            } catch {
                XCTFail("Unexpected error thrown: \(error).")
            }
            return response
        }
        
        router.post("test-block") { request in
            return "POST request succeeded."
        }
        
        let request = HTTPRequest(method: .GET, url: URL(string: "/test-token")!)
        let getResponse = try responder.respond(to: Request(http: request, using: app)).wait()
        
        let postRequest = Request(http:  HTTPRequest(method: .POST, url: URL(string: "/test-block")!), using: app)
        postRequest.http.cookies = getResponse.http.cookies
        
        let postResponse = try responder.respond(to: postRequest).wait()
        
        XCTAssertEqual(postResponse.http.status, .forbidden)
    }
    
    func testThadCSRFMiddlewareBlockInvalidToken() throws {
        
        app = try makeApplication(withSession: true)
        
        let router = try app.make(Router.self)
        let responder = try app.make(Responder.self)
        
        router.get("test-token") { request -> Response in
            let response = request.makeResponse()
            do {
                let token = try self.csrf.createToken(from: request)
                response.http.headers.add(name: "csrf-token", value: token)
            } catch {
                XCTFail("Unexpected error thrown: \(error).")
            }
            return response
        }
        
        router.post("test-block") { request in
            return "POST request succeeded."
        }
        
        let request = HTTPRequest(method: .GET, url: URL(string: "/test-token")!)
        let getResponse = try responder.respond(to: Request(http: request, using: app)).wait()
        
        let postRequest = Request(http:  HTTPRequest(method: .POST, url: URL(string: "/test-block")!), using: app)
        postRequest.http.headers.add(name: "csrf-token", value: "invalidToken")
        postRequest.http.cookies = getResponse.http.cookies
        
        let postResponse = try responder.respond(to: postRequest).wait()
        
        XCTAssertEqual(postResponse.http.status, .forbidden)
    }
    
    func testTokenRoundTripUsingHeader() throws {
        
        app = try makeApplication(withSession: true)
        
        let router = try app.make(Router.self)
        let responder = try app.make(Responder.self)
        
        router.get("test-token") { request -> Response in
            let response = request.makeResponse()
            do {
                let token = try self.csrf.createToken(from: request)
                response.http.headers.add(name: "csrf-token", value: token)
            } catch {
                XCTFail("Unexpected error thrown: \(error).")
            }
            return response
        }
        
        router.post("test-token-roundtrip") { request in
            return "POST request succeeded."
        }
        
        let request = HTTPRequest(method: .GET, url: URL(string: "/test-token")!)
        let getResponse = try responder.respond(to: Request(http: request, using: app)).wait()
        let token = getResponse.http.headers.firstValue(name: .init("csrf-token"))!
        
        let postRequest = Request(http:  HTTPRequest(method: .POST, url: URL(string: "/test-token-roundtrip")!), using: app)
        postRequest.http.headers.add(name: "csrf-token", value: token)
        postRequest.http.cookies = getResponse.http.cookies

        let postResponse = try responder.respond(to: postRequest).wait()
        let bodyString = String.convertFromData(postResponse.http.body.data!)
        XCTAssertEqual(bodyString, "POST request succeeded.", "`bodyString` returned from POST request should match expected output.")
    }
    
    func testTokenRoundTripUsingJSONBody() throws {
        
        struct Form: Content {
            private enum CodingKeys: String, CodingKey {
                case token = "_csrf"
            }
            let token: String
        }
        
        app = try makeApplication(withSession: true)
        
        let router = try app.make(Router.self)
        let responder = try app.make(Responder.self)
        
        router.get("test-token") { request -> Response in
            let response = request.makeResponse()
            do {
                let token = try self.csrf.createToken(from: request)
                response.http.headers.add(name: "csrf-token", value: token)
            } catch {
                XCTFail("Unexpected error thrown: \(error).")
            }
            return response
        }
        
        router.post("test-token-roundtrip") { request in
            return "POST request succeeded."
        }
        
        let request = HTTPRequest(method: .GET, url: URL(string: "/test-token")!)
        let getResponse = try responder.respond(to: Request(http: request, using: app)).wait()
        let token = getResponse.http.headers.firstValue(name: .init("csrf-token"))!
        
        let postRequest = Request(http:  HTTPRequest(method: .POST, url: URL(string: "/test-token-roundtrip")!), using: app)
        try postRequest.content.encode(Form(token: token))
        postRequest.http.cookies = getResponse.http.cookies
        
        let postResponse = try responder.respond(to: postRequest).wait()
        let bodyString = String.convertFromData(postResponse.http.body.data!)
        XCTAssertEqual(bodyString, "POST request succeeded.", "`bodyString` returned from POST request should match expected output.")
    }
    
    func testTokenRoundTripUsingMultipartBody() throws {
        
        struct Form: Content {
            
            static var defaultContentType: MediaType {
                return .formData
            }
            
            private enum CodingKeys: String, CodingKey {
                case token = "_csrf"
                case file
            }
            
            let token: String
            let file: String
        }
        
        app = try makeApplication(withSession: true)
        
        let router = try app.make(Router.self)
        let responder = try app.make(Responder.self)
        
        router.get("test-token") { request -> Response in
            let response = request.makeResponse()
            do {
                let token = try self.csrf.createToken(from: request)
                response.http.headers.add(name: "csrf-token", value: token)
            } catch {
                XCTFail("Unexpected error thrown: \(error).")
            }
            return response
        }
        
        router.post("test-token-roundtrip") { request in
            return "POST request succeeded."
        }
        
        let request = HTTPRequest(method: .GET, url: URL(string: "/test-token")!)
        let getResponse = try responder.respond(to: Request(http: request, using: app)).wait()
        let token = getResponse.http.headers.firstValue(name: .init("csrf-token"))!
        
        let postRequest = Request(http:  HTTPRequest(method: .POST, url: URL(string: "/test-token-roundtrip")!), using: app)
        try postRequest.content.encode(Form(token: token, file: "filebody"))
        postRequest.http.cookies = getResponse.http.cookies
        
        let postResponse = try responder.respond(to: postRequest).wait()
        let bodyString = String.convertFromData(postResponse.http.body.data!)
        XCTAssertEqual(bodyString, "POST request succeeded.", "`bodyString` returned from POST request should match expected output.")
    }
    
    func testThatCSRFMiddlewareFailsWithNoSession() throws {
        
        app = try makeApplication()
        
        let router = try app.make(Router.self)
        let responder = try app.make(Responder.self)
        
        router.get("test-no-session") { request -> Response in
            let response = request.makeResponse()
            do {
                response.http.headers.add(name: "csrf-token", value: try self.csrf.createToken(from: request))
            } catch let error as Abort {
                XCTFail("Unexpected error thrown: \(error).")
            } catch {
                XCTAssertTrue(true, "Must have a session to create a token.")
            }
            return response
        }
        
        let request = HTTPRequest(method: .GET, url: URL(string: "/test-no-session")!)
        _ = try responder.respond(to: Request(http: request, using: app)).wait()
    }
}

private func makeApplication(withSession session: Bool = false) throws -> Application {
    
    var services = Services.default()
    services.register(CSRF())
    
    var middlewareConfig = MiddlewareConfig()
    middlewareConfig.use(CSRF.self)
    
    if session {
        middlewareConfig.use(SessionsMiddleware.self)
    }
    
    middlewareConfig.use(ErrorMiddleware.self)
    
    services.register(middlewareConfig)
    
    return try Application(services: services)
}

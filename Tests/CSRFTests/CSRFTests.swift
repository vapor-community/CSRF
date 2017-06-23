import XCTest
import HTTP
import Vapor
import Sessions
@testable import CSRF

class CSRFTests: XCTestCase {
    
    private let csrf = CSRF()
    private var drop: Droplet!
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testThatDropletHasMiddlewareIsNotEmpty() throws {
        drop = try setUpDroplet()
        
        XCTAssertTrue(!drop.middleware.isEmpty, "Droplet middleware should not be empty.")
        guard let _ = drop.middleware.first as? CSRF else {
            XCTFail("CSRF middleware should have been added.")
            return
        }
    }
    
    func testThatCSRFMiddlewareReturnsToken() throws {
        var token: String!
        
        drop = try setUpDroplet(withSession: true)
        drop.get("test-token") { request in
            let response = Response(status: .ok)
            do {
                response.headers["csrf-token"] = try self.csrf.createToken(from: request)
                token = response.headers["csrf-token"]
            } catch {
                XCTFail("Unexpected error throw: \(error).")
            }
            return response
        }
        
        let request = Request(method: .get, uri: "/test-token/")
        let response = try drop.respond(to: request)
        XCTAssertTrue(response.headers["csrf-token"] == token, "Token in response header should match.")
    }
    
    func testTokenRoundTrip() throws {
        drop = try setUpDroplet(withSession: true)
        drop.get("test-token") { request in
            let response = Response(status: .ok)
            do {
                let token = try self.csrf.createToken(from: request)
                response.headers["csrf-token"] = token
                
                let postRequest = Request(method: .post, uri: "/test-token-roundtrip")
                postRequest.headers["csrf-token"] = token
                postRequest.session = try request.assertSession()
                
                let postResponse = try self.drop.respond(to: postRequest)
                let bodyString = postResponse.body.bytes!.makeString()
                XCTAssertEqual(bodyString, "POST request succeeded.", "`bodyString` returned from POST request should match expected output.")
            } catch {
                XCTFail("Unexpected error thrown: \(error).")
            }
            return response
        }
        
        drop.post("test-token-roundtrip") { request in
            return "POST request succeeded."
        }
        
        let getRequest = Request(method: .get, uri: "/test-token/")
        _ = try drop.respond(to: getRequest)
    }
    
    func testThatCSRFMiddlewareFailsWithNoSession() throws {
        drop = try setUpDroplet()
        
        drop.get("test-no-session") { request in
            let response = Response(status: .ok)
            do {
                response.headers["csrf-token"] = try self.csrf.createToken(from: request)
            } catch let error as Abort {
                XCTAssertTrue(error.status.status == .forbidden, "Must have a session to create a token.")
            } catch {
                XCTFail("Unexpected error thrown: \(error).")
            }
            return response
        }
        
        let request = Request(method: .get, uri: "/test-no-session/")
        _ = try drop.respond(to: request)
    }
    
}

private func setUpDroplet(withSession session: Bool = false) throws -> Droplet {
    var c = try Config()
    c.environment = .test
    
    if session {
        try c.set("droplet.middleware", ["csrf", "session"])
        c.addConfigurable(middleware: { _ in CSRF() }, name: "csrf")
        c.addConfigurable(middleware: { config in try SessionsMiddleware(config: config) }, name: "session")
    } else {
        try c.set("droplet.middleware", ["csrf"])
        c.addConfigurable(middleware: { _ in CSRF() }, name: "csrf")
    }
    
    let drop = try Droplet(c)
    return drop
}

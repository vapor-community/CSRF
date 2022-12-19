import Vapor
import Leaf

/// A `LeafTag` creating a simple hidden HTML form input, allowing easy use of `CSRF` in HTML forms.
///
/// The tag doesn't require any special setup except the one described in the README.md for the `CSRF` module itself.
public struct CSRFFormFieldTag: UnsafeUnescapedLeafTag {
    
    /// Initializes a `CSRFFormFieldTag`.
    ///
    /// No Special setup needed, so this is just purely to make the class publicly instantiatable.
    public init() {}
    
    /// Renders a simple hidden HTML form input, allowing easy use of `CSRF` in HTML forms.
    ///
    /// Requried by the `LeafTag` protocol.
    /// - Parameter ctx: The `LeafContext` providing `CSRFFormFieldTag` access to the current `Request`.
    ///   This is needed to create a CSRF token.
    /// - Throws: Throws`Error.noRequestInContext` when the provided `LeafContext` doesn't contain a request.
    /// - Returns: Returns a `LeafData`instance, representing the rendered form field tag..
    public func render(_ ctx: LeafContext) throws -> LeafData {
        
        try ctx.requireParameterCount(0)
        
        guard let req = ctx.request else {
            throw Error.noRequestInContext
        }
        
        let csrfToken = CSRF.createToken(from: req)
        let formFieldHtml = "<input type='hidden' name='_csrf' value='\(csrfToken)'>"
        
        return LeafData.string(formFieldHtml)
    }
}

public extension CSRFFormFieldTag {
    /// This enum contains all Errors thrown by `CSRFFormFieldTag`.
    enum Error: Swift.Error {
        /// This error is thrown by `CSRFFormFieldTag.render(_:)` if the passed `LeafContext` doesn't contain an associated `Request`.
        case noRequestInContext
    }
}

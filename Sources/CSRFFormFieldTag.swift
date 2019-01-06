import Vapor

public final class CSRFFormFieldTag: TagRenderer {
    public init() {}

    public func render(tag: TagContext) throws -> EventLoopFuture<TemplateData> {
        try tag.requireNoBody()
        try tag.requireParameterCount(0)
        guard let request = tag.container as? Request else {
            throw Abort(.internalServerError, reason: "Container of Tag is not of type Request")
        }

        let csrfToken = try tag.container.make(CSRF.self).createToken(from: request)
        let formFieldHtml = "<input type='hidden' name='_csrf' value='\(csrfToken)'>"

        return Future.map(on: tag) {
            .string(formFieldHtml)
        }
    }
}

//
//  CSRFFormFieldTag.swift
//  
//
//  Created by Nicolas Da Mutten on 15.04.21.
//

import Vapor
import Leaf

public struct CSRFFormFieldTag: LeafTag {

	public init() {}

	public func render(_ ctx: LeafContext) throws -> LeafData {

		struct CSRFFormFieldTagError: Error {}

		try ctx.requireParameterCount(0)

		guard let req = ctx.request else {
			throw CSRFFormFieldTagError()
		}

		let csrfToken = CSRF.createToken(from: req)
		let formFieldHtml = "<input type='hidden' name='_csrf' value='\(csrfToken)'>"

		return LeafData.string(formFieldHtml)
	}
}

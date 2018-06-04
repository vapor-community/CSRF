import XCTest

import CSRFTests

var tests = [XCTestCaseEntry]()
tests += CSRFTests.__allTests()

XCTMain(tests)

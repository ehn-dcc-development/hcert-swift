import XCTest

import hcertTests

var tests = [XCTestCaseEntry]()

tests += hcertTests.allTests()
XCTMain(tests)

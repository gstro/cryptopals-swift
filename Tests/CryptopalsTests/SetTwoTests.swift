import Foundation
import XCTest
import Files
import Cryptor
import Extensions
import CryptoSwift

import Cryptopals

class SetTwoTests: XCTestCase {

    // Implement PKCS#7 padding
    func testChallengeNine() {
        let yellow    = CryptoUtils.byteArray(from: "YELLOW SUBMARINE")
        let expectedY = yellow + Array(repeating: 0x04, count: 4)
        let paddedY   = yellow.pkcs7(20)
        XCTAssert(paddedY == expectedY)

        let blue      = CryptoUtils.byteArray(from: "BLUE SUBMARINE")
        let expectedB = blue + Array(repeating: 0x06, count: 6)
        let paddedB   = blue.pkcs7(10)
        XCTAssert(paddedB == expectedB)
    }
}

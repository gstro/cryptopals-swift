import Foundation
import XCTest
import Files
import Cryptor
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

    // Implement CBC Mode
    func testChallengeTen() {
        let key = CryptoUtils.byteArray(from: "YELLOW SUBMARINE")
        let iv  = Array(repeating: UInt8(0x0), count: 16)

        let testPlain  = "For sale: baby shoes, never worn"
        let plainBytes = CryptoUtils.byteArray(from: testPlain)
        guard let testEnc = Utils.cbc(plainBytes, keyBytes: key, iv: iv, op: .encrypt)
            else { return XCTFail("Could not encrypt") }

        guard let testDec = Utils.cbc(testEnc, keyBytes: key, iv: iv, op: .decrypt),
            let plain = testDec.utf8()
            else { return XCTFail("Could not decrypt") }

        XCTAssert(testPlain == plain)

        guard let content = Utils.fileContents(named: "cp10.txt"),
              let decoded = Data(base64Encoded: content, options: .ignoreUnknownCharacters)
            else { return XCTFail("Could not decode content") }

        guard let decrypted = Utils.cbc(decoded.bytes, keyBytes: key, iv: iv, op: .decrypt),
              let plaintext = decrypted.utf8()
            else { return XCTFail("Could not decrypt") }

        print("plaintext: \(plaintext)")
        XCTAssert(true)
    }
}

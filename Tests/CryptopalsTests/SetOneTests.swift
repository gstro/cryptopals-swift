import Foundation
import XCTest
import Files
import Cryptor
import CryptoSwift

import Cryptopals

// Prevent printing results from
// continuous integration build
#if CI_BUILD
    func println(_ object: Any) {}
    func print(_ object: Any){}
#endif

class SetOneTests: XCTestCase {

    // Convert hex to base64
    func testChallengeOne() {
        let hexTest  = "49276d206b696c6c696e6720796f757220627261696e206c" +
                       "696b65206120706f69736f6e6f7573206d757368726f6f6d"
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        let result   = String.hexToBase64(hexTest)
        XCTAssert(result == expected)
    }

    // Fixed XOR
    func testChallengeTwo() {
        let hexTest1 = "1c0111001f010100061a024b53535009181c"
        let hexTest2 = "686974207468652062756c6c277320657965"
        let expected = "746865206b696420646f6e277420706c6179"
        let result   = String.xor(hexString1: hexTest1, hexString2: hexTest2).hexString()
        XCTAssert(result == expected)
    }

    // Single-byte XOR cypher
    func testChallengeThree() {
        let encoded = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        let decoded = CryptoUtils.byteArray(fromHex: encoded)
        let key     = Utils.solveSingleByteXor(decoded)?.key

        XCTAssertNotNil(key)
        key.map { print("Key: \(UnicodeScalar($0))") }
    }

    // Detect single-character XOR
    func testChallengeFour() {
        guard let lines = Utils.fileContents(named: "cp4.txt")?
            .components(separatedBy: .newlines) else { return XCTFail() }

        // find best scoring key for each line
        let tested = lines.flatMap { line -> (line: String, key: UInt8, score: Int)? in
            let plain  = CryptoUtils.byteArray(fromHex: line)
            let scored = Utils.solveSingleByteXor(plain)
            return scored.map { (line: line, key: $0.key, score: $0.score) }
        }

        // use best scoring key overall to decode associated line
        let phrase = tested
            .sorted { $0.score > $1.score }
            .first
            .flatMap { max -> String? in
                let xor: [UInt8] = CryptoUtils.byteArray(fromHex: max.line).map { $0 ^ max.key }
                let data: Data   = CryptoUtils.data(from: xor)
                return data.string(encoding: .utf8)
        }

        XCTAssertNotNil(phrase)
        phrase.map { print("phrase: \($0)") }
    }

    // Implement repeating-key XOR
    func testChallengeFive() {
        let key      = "ICE"
        let plain    = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623" +
                       "d63343c2a26226324272765272a282b2f20430a652e2c652a" +
                       "3124333a653e2b2027630c692b20283165286326302e27282f"
        let result   = plain.xor(repeatedKey: key).hexString()
        XCTAssert(result == expected)
    }

    // Break repeating-key XOR
    func testChallengeSix() {
        let result   = "this is a test".hamming("wokka wokka!!!")
        let expected = 37

        // test hamming function
        XCTAssert(result == expected)

        guard let content = Utils.fileContents(named: "cp6.txt"),
              let decoded = Data(base64Encoded: content, options: .ignoreUnknownCharacters)
            else { return XCTFail("cannot decode content") }

        // try key sizes from 2 to 40
        let decodedBytes = [UInt8](decoded)
        let scores       = (2..<40).map { Utils.scoreKeySize($0, bytes: decodedBytes) }
        let topScores    = scores
            .enumerated()
            .sorted { $0.1 < $1.1 }
            .map { ($0.offset + 2, $0.element) }

        // get best scoring key size
        guard let keySize = topScores.first?.0
            else { return XCTFail("No keySize found.") }

        // transpose lines and solve for each chunk
        let chunked    = decodedBytes.chunks(keySize)
        let transposed = (0..<chunked.count)
            .map { iter in chunked.flatMap { $0.item(at: iter) } }
            .flatMap { Utils.solveSingleByteXor($0)?.key }

        // generate key phrase and decode full text
        let data: Data  = CryptoUtils.data(from: Array(transposed.prefix(keySize)))
        guard let key   = data.string(encoding: .utf8),
              let full  = decoded.string(encoding: .utf8),
              let plain = full.xor(repeatedKey: key).utf8()
            else { return XCTFail("cannot decode text") }

        print("key: \(key)")
        print("decoded: \(plain)")

        XCTAssert(true)
    }

    // AES in ECB mode
    func testChallengeSeven() {
        guard let content = Utils.fileContents(named: "cp7.txt"),
              let decoded = Data(base64Encoded: content, options: .ignoreUnknownCharacters)
            else { return XCTFail("cannot decode content") }

        let key = CryptoUtils.byteArray(from: "YELLOW SUBMARINE")
        XCTAssert(key.hexString() == "59454c4c4f57205355424d4152494e45")

        guard let aes = try? AES.init(key: key, blockMode: .ECB, padding: .noPadding)
            else { return XCTFail("could not create AES") }

        guard let bytes = try? aes.decrypt(decoded.bytes),
              let plain = bytes.utf8()
            else { return XCTFail("could not decrypt message") }

        print(plain)
        XCTAssert(true)
    }

    // Detect AES in ECB mode
    func testChallengeEight() {
        guard let content = Utils.fileContents(named: "cp8.txt")
            else { return XCTFail("cannot read content") }

        let repeated = content.lines().filter { Utils.repeatsBytes($0, sized: 16) }
        XCTAssert(repeated.count == 1)
        print(repeated[0])
    }
}

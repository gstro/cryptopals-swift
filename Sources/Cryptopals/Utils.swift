import Foundation
import Cryptor
import Extensions
import Files
import CryptoSwift

public struct Utils {

    // MARK: - Private properties and functions.

    /**
     English language character frequencies, source:
     http://www.macfreek.nl/memory/Letter_Distribution
    */
    private static let charFreq: [Character: Int] = [
        "a": 653,
        "b": 126,
        "c": 223,
        "d": 328,
        "e": 1026,
        "f": 198,
        "g": 162,
        "h": 498,
        "i": 567,
        "j": 10,
        "k": 56,
        "l": 331,
        "m": 203,
        "n": 571,
        "o": 616,
        "p": 150,
        "q": 8,
        "r": 499,
        "s": 532,
        "t": 752,
        "u": 228,
        "v": 80,
        "w": 170,
        "x": 14,
        "y": 143,
        "z": 5,
        " ": 1829
    ]

    /**
     Grades the given string, based on known character frequencies for the
     English language, with larger values indicating higher likelihood for the
     phrase to be valid words.

     - Parameter str: The string to score.
     - Returns: An integer representing the score. Larger numbers indicate
        higher likelihood of valid words.
    */
    private static func score(_ str: String) -> Int {
        return str.lowercased()
            .charactersArray
            .reduce(0) { $0 + (charFreq[$1] ?? 0) }
    }

    /**
     Scores a given byte as an XOR key against the given bytes.

     - Parameters:
        - key: A byte to test as an XOR key against a byte array.
        - bytes: A byte array used for testing the key.
     - Returns: A named-value tuple of the provided key and its score.
     */
    private static func testKey(_ key: UInt8, bytes: [UInt8]) -> (key: UInt8, score: Int) {
        let xorBytes   = bytes.xor(key)
        let data: Data = CryptoUtils.data(from: xorBytes)
        guard let decoded = String(data: data, encoding: .utf8)
            else { return (key: key, score: 0) }

        return (key: key, score: score(decoded))
    }

    // MARK: - Public properties and functions.

    /**
     Supplies the contents of a file as a string if the file can be read,
     otherwise nil.

     - Note: For compatibility with xcode and swiftpm,
        store all resources in ~/Cryptopals/Resources. For 
        continuous integration, store files in project root/Resources,
        and pass CI_BUILD flag to tester

     - Parameter named: The filename to read.
     - Returns: The file contents as a string or nil.
    */
    public static func fileContents(named: String) -> String? {
        #if CI_BUILD
        return try? Folder
            .current
            .subfolder(named: "Resources")
            .file(named: named)
            .readAsString()
        #else
        return try? Folder
            .home
            .subfolder(named: "Cryptopals")
            .subfolder(named: "Resources")
            .file(named: named)
            .readAsString()
        #endif
    }

    /**
     Cycles through the range of UInt8 values, testing each byte against the
     given byte array, and supplies the best scoring key if one was found,
     otherwise nil.
    
     - Parameter bytes: The byte array to use for scoring possible keys.
     - Returns: A named-value tuple of the highest scoring key and its score, 
        or nil if none was found.
    */
    public static func solveSingleByteXor(_ bytes: [UInt8]) -> (key: UInt8, score: Int)? {
        return [UInt8](UInt8.min...UInt8.max)
            .map { testKey($0, bytes: bytes) }
            .sorted { $0.score > $1.score }
            .first
    }

    /**
     Gives the score of a given key size for an array of bytes based on the
     hamming distance after breaking the array into sized chunks. Lower scores
     indicate higher likelihood of key size used.

     - Parameters:
        - keySize: The size of the key to use for scoring.
        - bytes: The array of bytes to use for scoring.
     - Returns: Score indicating possibility that provided key size is correct.
    */
    public static func scoreKeySize(_ keySize: Int, bytes: [UInt8]) -> Int {
        let chunkCount = bytes.count / keySize
        return (0..<(chunkCount - 1)).reduce(0) { (acc, iter) in
            let chunk = Array(bytes[(iter * keySize)..<((iter + 2) * keySize)])
            let first = Array(chunk.prefix(upTo: keySize))
            let last  = Array(chunk.suffix(from: keySize))
            return acc + first.hamming(last)
        } / chunkCount / keySize
    }

    /**
     Checks the given line for repeating chunks of bytes of the given size.

     - Parameters:
        - line: The line to check for repeating bytes
        - sized: The chunk size to divide the line.
     - Returns: If the provided line repeated bytes chunks of the given size
    */
    public static func repeatsBytes(_ line: String, sized: Int) -> Bool {
        var counts = [String: Int]()
        return CryptoUtils
            .byteArray(fromHex: line)
            .chunks(sized)
            .contains { counts.updateValue(1, forKey: $0.hexString()) != nil }
    }

    /**
     CBC Mode crypto operations.
    */
    public enum CbcOp {
        case encrypt
        case decrypt

        fileprivate func run(_ block: [UInt8], prev: [UInt8], ecb: AES) -> ([UInt8], [UInt8])? {
            switch self {
            case .encrypt:
                guard let cypherBlock: [UInt8] = try? ecb.encrypt(prev.xor(block))
                    else { return nil }
                return (cypherBlock, cypherBlock)
            case .decrypt:
                guard let decrypted = try? ecb.decrypt(block)
                    else { return nil }
                return (prev.xor(decrypted), block)
            }
        }
    }

    /**
     Run a CBC Mode crypto operation.

     - Parameters:
        - bytes: The bytes on which to perform the operation.
        - keyBytes: The bytes for the key used in the operation.
        - iv: The initialization vector.
        - op: The selected CBC operation to perform.
     - Returns: The transformed bytes if successful, or nil if unsuccessful.
    */
    public static func cbc(_ bytes: [UInt8], keyBytes: [UInt8], iv: [UInt8], op: CbcOp) -> [UInt8]? {
        func go(_ acc: [[UInt8]], rem: [[UInt8]], previous: [UInt8], ecb: AES) -> [[UInt8]]? {
            guard let block = rem.first
                else { return acc }

            guard let (next, prev) = op.run(block, prev: previous, ecb: ecb)
                else { return nil }

            return go(acc + [next], rem: Array(rem.dropFirst()), previous: prev, ecb: ecb)
        }

        guard let ecb = try? AES(key: keyBytes, iv: nil, blockMode: .ECB, padding: NoPadding())
            else { return nil }

        let padSize = keyBytes.count
        let chunked = bytes.chunks(padSize)

        return go([], rem: chunked, previous: iv, ecb: ecb)?.reduce([], +)
    }
}

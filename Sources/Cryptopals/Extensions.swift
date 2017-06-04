import Foundation
import Cryptor
import Extensions

// MARK: - Array Extensions
public extension Array {
    /**
     Partitions the array into sub-arrays of a given size.

     - Note: The last sub-array will be shorter if the base array is not
     evenly divided by the given chunk size.

     - Parameter chunkSize: The size of the sub-arrays to create
     - Returns: An array of sub-arrays of a given size.
    */
    func chunks(_ chunkSize: Int) -> [[Element]] {
        return stride(from: 0, to: count, by: chunkSize)
            .map { Array(self[$0..<Swift.min($0 + chunkSize, count)]) }
    }
}

// MARK: - Array Extensions (BitwiseOperations)
public extension Array where Element: BitwiseOperations {
    /**
     Performs an XOR operation on every element with the provided element.

     - Parameter key: The single element to XOR against.
     - Returns: An array of elements that have been XOR'd.
    */
    func xor(_ key: Element) -> [Element] {
        return map { $0 ^ key }
    }

    /**
     Performs an XOR operation on each element of this array with the elements
     of the given array in step.

     - Parameter otherData: The array of elements to use for XOR operations.
     - Returns: An array of elements that have been XOR'd.
    */
    func xor(_ otherData: [Element]) -> [Element] {
        return zip(self, otherData).map(^)
    }
}

// MARK: - Array Extensions (UInt8)
public extension Array where Element == UInt8 {
    /**
     Creates a String of the bytes in hexidecimal format.

     - Returns: The hexidecimal representation of this array as a String.
    */
    func hexString() -> String {
        return CryptoUtils.hexString(from: self)
    }

    /**
     Creates a UTF8 representation of the bytes as a String, or nil
     if the encoding cannot be performed.

     - Returns: A UTF8 encoded string or nil.
    */
    func utf8() -> String? {
        let data: Data = CryptoUtils.data(from: self)
        return String(data: data, encoding: .utf8)
    }

    /**
     Calculates the Hamming (or edit) distance between the byte arrays.

     - Parameter bytes: Another UInt8 array to compare bits.
     - Returns: The number of bits that were different between the two arrays.
    */
    func hamming(_ bytes: [UInt8]) -> Int {
        return zip(self, bytes).reduce(0) { $0 + $1.0.hamming($1.1) }
    }
}

// MARK: - UInt8 Extensions
public extension UInt8 {
    /**
     Calculates the Hamming (or edit) distance between the two bytes.

     - Parameter byte: Another UInt8 to compare bits.
     - Returns: The number of bits that were different between the two bytes.
    */
    func hamming(_ byte: UInt8) -> Int {
        let difference = self ^ byte
        return (0..<8).reduce(0) { $0 + Int((difference >> $1) & 1) }
    }
}

// MARK: - String Extensions
public extension String {
    /**
     Conversion from hexidecimal string to base64 encoded string.

     - Parameter hexString: Hexidecimal formatted string.
     - Returns: A base64 representation of the data.
    */
    static func hexToBase64(_ hexString: String) -> String {
        let data: Data = CryptoUtils.data(fromHex: hexString)
        return data.base64EncodedString()
    }

    /**
     Performs an XOR operation of the underlying data of two hexidecimal
     formatted strings and provide the resulting bytes.

     - Warning: No validation is performed to ensure Parameters are
        actually hex strings.
     - Parameters:
        - hexString1: The first hex-formatted string to XOR.
        - hexString2: The second hex-formatted string to XOR.
     - Returns: The array of bytes after the XOR operation.
    */
    static func xor(hexString1: String, hexString2: String) -> [UInt8] {
        let hex1 = CryptoUtils.byteArray(fromHex: hexString1)
        let hex2 = CryptoUtils.byteArray(fromHex: hexString2)
        return hex1.xor(hex2)
    }

    /**
     Performs an XOR operation by repeating the provided key to match the
     length of this String, and supplies the resulting bytes.

     - Parameter repeatedKey: A key string to repeat for the XOR operation.
     - Returns: The array of bytes after the XOR operation.
    */
    func xor(repeatedKey: String) -> [UInt8] {
        let keyLen      = repeatedKey.characters.count
        let plainLen    = characters.count
        let repeatCount = Int(ceil(Double(plainLen) / Double(keyLen)))
        let extended    = String(repeating: repeatedKey, count: repeatCount)
        let plainBytes  = CryptoUtils.byteArray(from: self)
        let extBytes    = CryptoUtils.byteArray(from: extended)
        return plainBytes.xor(extBytes)
    }

    /**
     Calculates the Hamming (or edit) distance between the two strings,
     assuming utf8 encoding.

     - Parameter str: Another String to compare bits.
     - Returns: The number of bits that were different between the two strings.
    */
    func hamming(_ str: String) -> Int {
        return CryptoUtils.byteArray(from: self)
            .hamming(CryptoUtils.byteArray(from: str))
    }
}

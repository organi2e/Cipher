//
//  Crypt.swift
//  cipher
//
//  Created by Kota Nakano on 8/20/19.
//  Copyright © 2019 organi2e. All rights reserved.
//
import Foundation
import CommonCrypto
enum Cryption: String, CaseIterable {
	case AES128 = "AES128"
	case AES192 = "AES192"
	case AES256 = "AES256"
	case BlowFish = "BlowFish"
	case CAST = "CAST"
	case DES = "DES"
	case RC2 = "RC2"
	case RC4 = "RC4"
}
extension Cryption {
	enum ErrorCases: Error {
		case encryption(status: CCCryptorStatus)
		case decryption(status: CCCryptorStatus)
		case derivation(status: CCCryptorStatus)
	}
}
extension Cryption {
	var length: Int {
		switch self {
		case.AES128:
			return Int(kCCKeySizeAES128)
		case.AES192:
			return Int(kCCKeySizeAES192)
		case.AES256:
			return Int(kCCKeySizeAES256)
		case.BlowFish:
			return Int(kCCKeySizeMaxBlowfish)
		case.CAST:
			return Int(kCCKeySizeMaxCAST)
		case.DES:
			return Int(kCCKeySizeDES)
		case.RC2:
			return Int(kCCKeySizeMaxRC2)
		case .RC4:
			return Int(kCCKeySizeMaxRC4)
		}
	}
	var algorithm: CCAlgorithm {
		switch self {
		case.AES128, .AES192, .AES256:
			return CCAlgorithm(kCCAlgorithmAES)
		case.BlowFish:
			return CCAlgorithm(kCCAlgorithmBlowfish)
		case.CAST:
			return CCAlgorithm(kCCAlgorithmCAST)
		case.DES:
			return CCAlgorithm(kCCAlgorithmDES)
		case.RC2:
			return CCAlgorithm(kCCAlgorithmRC2)
		case.RC4:
			return CCAlgorithm(kCCAlgorithmRC4)
		}
	}
	var options: CCOptions {
		switch self {
		case.AES128, .AES192, .AES256, .BlowFish, .CAST, .DES, .RC2, .RC4:
			return CCOptions(kCCOptionPKCS7Padding)
		}
	}
}
extension Cryption {
	func encrypt(data: Data, pass: Data) throws -> Data {
		let offset: Int = MemoryLayout<Int>.size
		let keylen: Int = length
		let result: Data = Data(count: offset + keylen + data.count + keylen)
		let status: CCCryptorStatus = result.withUnsafeBytes {
			guard let addr: UnsafeRawPointer = $0.baseAddress else {
				return CCCryptorStatus(kCCUnspecifiedError)
			}
			let size: UnsafePointer = addr.assumingMemoryBound(to: Int.self)
			let ivec: UnsafeRawPointer = addr.advanced(by: offset)
			let done: UnsafeRawPointer = ivec.advanced(by: keylen)
			guard SecRandomCopyBytes(kSecRandomDefault, keylen, UnsafeMutableRawPointer(mutating: ivec)) == 0 else {
				return CCCryptorStatus(kCCUnspecifiedError)
			}
			return pass.withUnsafeBytes { pass in
				return data.withUnsafeBytes { data in
					CCCrypt(CCOperation(kCCEncrypt),
							algorithm,
							options,
							pass.baseAddress,
							pass.count,
							ivec,
							data.baseAddress,
							data.count,
							UnsafeMutableRawPointer(mutating: done),
							data.count + keylen,
							UnsafeMutablePointer(mutating: size))
				}
			}
		}
		guard status == kCCSuccess else {
			throw ErrorCases.encryption(status: status)
		}
		let length: Int = result.withUnsafeBytes {
			$0.load(as: Int.self)
		}
		return result.subdata(in: offset..<offset+keylen+length)
	}
}
extension Cryption {
	func decrypt(data: Data, pass: Data) throws -> Data {
		let offset: Int = MemoryLayout<Int>.stride
		let keylen: Int = length
		let result: Data = Data(count: offset + data.count)
		let status: CCCryptorStatus = result.withUnsafeBytes {
			guard let addr: UnsafeRawPointer = $0.baseAddress else {
				return CCCryptorStatus(kCCUnspecifiedError)
			}
			let size: UnsafePointer = addr.assumingMemoryBound(to: Int.self)
			let done: UnsafeRawPointer = addr.advanced(by: offset)
			return pass.withUnsafeBytes { pass in
				return data.withUnsafeBytes { data in
					CCCrypt(CCOperation(kCCDecrypt),
							algorithm,
							options,
							pass.baseAddress,
							pass.count,
							data.baseAddress,
							data.baseAddress?.advanced(by: keylen),
							data.count - keylen,
							UnsafeMutableRawPointer(mutating: done),
							data.count,
							UnsafeMutablePointer(mutating: size))
				}
			}
		}
		guard status == kCCSuccess else {
			throw ErrorCases.decryption(status: status)
		}
		let length: Int = result.withUnsafeBytes {
			$0.load(as: Int.self)
		}
		return result.subdata(in: offset..<offset+length)
	}
}
extension Cryption {
	func genkey(phrase: String, salt: Data, round: Int) throws -> Data {
		let result: Data = Data(count: length)
		let status: CCCryptorStatus = result.withUnsafeBytes {
			let result: UnsafeBufferPointer<UInt8> = $0.bindMemory(to: UInt8.self)
			return salt.withUnsafeBytes {
				let salt: UnsafeBufferPointer<UInt8> = $0.bindMemory(to: UInt8.self)
				return CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
											phrase,
											phrase.count,
											salt.baseAddress,
											salt.count,
											CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
											UInt32(round),
											UnsafeMutablePointer(mutating: result.baseAddress),
											result.count)
			}
		}
		guard status == kCCSuccess else {
			throw ErrorCases.derivation(status: status)
		}
		return result
	}
}

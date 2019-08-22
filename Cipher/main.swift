//
//  main.swift
//  cipher
//
//  Created by Kota Nakano on 8/20/19.
//  Copyright © 2019 organi2e. All rights reserved.
//
import Foundation
enum ErrorCases: Error {
	case noAlgorithm(rawValue: String)
	case noPassphrase
	case noMode
	case noData
	case invalidMode(rawValue: String)
}
let verboseKey: String = "--verbose"
let vKey: String = "-v"
let modeKey: String = "--mode"
let mKey: String = "-m"
let phraseKey: String = "--phrase"
let pKey: String = "-p"
let algorithmKey: String = "--algorithm"
let aKey: String = "-a"
let algorithmValue: String = Cryption.AES256.rawValue
let roundKey: String = "--round"
let rKey: String = "-r"
let roundValue: Int = 42
let optarg: Optarg = Optarg(option: [verboseKey: 0,
									 vKey: 0,
									 modeKey: 1,
									 mKey: 1,
									 phraseKey: 1,
									 pKey: 1,
									 algorithmKey: 1,
									 aKey: 1,
									 roundKey: 1,
									 rKey: 1])
extension FileHandle {
	func write(string: String) {
		switch string.data(using: .utf8) {
		case.some(let data):
			write(data)
		case.none:
			Darwin.write(fileDescriptor, string, string.count)
		}
	}
}
do {
	let verbose: Bool = optarg.has(key: verboseKey) || optarg.has(key: vKey)
	let algorithm: String = optarg.value(for: algorithmKey) ?? optarg.value(for: aKey) ?? algorithmValue
	guard let cryption: Cryption = Cryption(rawValue: algorithm) else {
		throw ErrorCases.noAlgorithm(rawValue: algorithm)
	}
	let round: Int = optarg.value(for: roundKey) ?? optarg.value(for: rKey) ?? roundValue
	let salt: Data = Data(count: cryption.length)
	guard let phrase: String = optarg.value(for: phraseKey) ?? optarg.value(for: pKey) else {
		throw ErrorCases.noPassphrase
	}
	guard let mode: String = optarg.value(for: modeKey) ?? optarg.value(for: mKey) else {
		throw ErrorCases.noMode
	}
	let pass: Data = try cryption.genkey(phrase: phrase, salt: salt, round: round)
	switch mode {
	case "E", "EN", "ENC", "Enc", "Encrypt", "e", "en", "enc", "encrypt", "encryption":
		if verbose {
			let summary: [String: String] = ["Mode": "Encryption",
											 "Algorithm": cryption.rawValue,
											 "Passphrase": String(repeating: "*", count: phrase.count),
											 "Salt": salt.description,
											 "Round": round.description]
			FileHandle.standardError.write(string: summary.map { "\($0): \($1)" }.joined(separator: "\r\n") + "\r\n")
		}
		FileHandle.standardInput.readabilityHandler = {
			do {
				let data: Data = $0.availableData
				switch data.count {
				case 0:
					$0.closeFile()
					CFRunLoopStop(CFRunLoopGetMain())
				default:
					try FileHandle.standardOutput.write(cryption.encrypt(data: data, pass: pass))
				}
			} catch {
				FileHandle.standardError.write(string: "runtime err.: \(error)")
			}
		}
	case "D", "DE", "DEC", "Dec", "Decrypt", "d", "de", "dec", "decrypt", "decryption":
		if verbose {
			let summary: [String: String] = ["Mode": "Decryption",
											 "Algorithm": cryption.rawValue,
											 "Passphrase": String(repeating: "*", count: phrase.count),
											 "Salt": salt.description,
											 "Round": round.description]
			FileHandle.standardError.write(string: summary.map { "\($0): \($1)" }.joined(separator: "\r\n") + "\r\n")
		}
		FileHandle.standardInput.readabilityHandler = {
			do {
				let data: Data = $0.availableData
				switch data.count {
				case 0:
					$0.closeFile()
					CFRunLoopStop(CFRunLoopGetMain())
				default:
					try FileHandle.standardOutput.write(cryption.decrypt(data: data, pass: pass))
				}
			} catch {
				FileHandle.standardError.write(string: "runtime err.: \(error)")
			}
		}
	case let rawValue:
		throw ErrorCases.invalidMode(rawValue: rawValue)
	}
	CFRunLoopRun()
} catch ErrorCases.noAlgorithm(let rawValue) {
	let algorithms: [String] = Cryption.allCases.map { $0.rawValue }
	FileHandle.standardError.write(string: "invalid algorithm: \(rawValue)\r\nchoose from: \(algorithms)\r\n")
} catch ErrorCases.invalidMode(let rawValue) {
	FileHandle.standardError.write(string: "invalid mode: \(rawValue)\r\n")
} catch ErrorCases.noPassphrase {
	FileHandle.standardError.write(string: "no passphrase specified by using \(phraseKey) or \(pKey) option\r\n")
} catch {
	FileHandle.standardError.write(string: "runtime err.: \(error)\r\n")
}

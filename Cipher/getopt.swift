//
//  getopt.swift
//  cipher
//
//  Created by Kota Nakano on 8/20/19.
//  Copyright © 2019 organi2e. All rights reserved.
//
import Foundation
public class Optarg {
	let cache: [String: [String]]
	public let error: [String: Int]
	public let arguments: [String]
	public init(option o: [String: Int], arguments a: [String] = Array(ProcessInfo.processInfo.arguments.dropFirst())) {
		let (opt, res, k, r): ([String: [String]], [String], String, Int) = a.reduce(([:], [], "", 0)) {
			if 0 < $0.3 {
				return ($0.0.merging([$0.2: [$1]]) { $0 + $1 }, $0.1, $0.2, $0.3 - 1)
			} else if let count: Int = o[$1] {
				return ($0.0.merging([$1: []]) { $0 + $1 }, $0.1, $1, count)
			} else {
				return ($0.0, $0.1 + [$1], $0.2, $0.3)
			}
		}
		cache = opt
		error = 0 < r ? [k: r] : [:]
		arguments = res
	}
}
extension Optarg {
	func has(key: String) -> Bool {
		return cache.keys.contains(key)
	}
	func count(for key: String) -> Int? {
		return cache[key]?.count
	}
	func value(for key: String) -> [String]? {
		return cache[key]
	}
	func value<T>(for key: String) -> T? where T: Optval {
		guard let value: String = cache[key]?.first else {
			return nil
		}
		return T(value)
	}
	func value<T>(for key: String, at index: Int) -> T? where T: Optval {
		guard let array: [String] = cache[key], array.indices.contains(index) else {
			return nil
		}
		return T(array[index])
	}
}
public protocol Optval {
	init?(_: String)
}
extension String: Optval {}
extension Int: Optval {}
extension UInt: Optval {}
extension Float: Optval {}
extension Double: Optval {}
extension Decimal: Optval {
	public init?(_ string: String) {
		self.init(string: string)
	}
}
extension URL: Optval {
	public init?(_ string: String) {
		self.init(fileURLWithPath: string)
	}
}

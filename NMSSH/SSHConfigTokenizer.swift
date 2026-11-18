//
//  SSHConfigTokenizer.swift
//  NMSSH
//
//  A Swift port of the ssh_config line tokenizers in OpenSSH's misc.c (revision 1.223):
//  strdelim_internal(), which splits off a line's keyword, and argv_split(), which splits its
//  arguments. Derived from OpenSSH; modified from the original by porting it to Swift.
//
//  Original notice from misc.c:
//
//  Copyright (c) 2000 Markus Friedl.  All rights reserved.
//  Copyright (c) 2005-2020 Damien Miller.  All rights reserved.
//  Copyright (c) 2004 Henning Brauer <henning@openbsd.org>
//
//  Permission to use, copy, modify, and distribute this software for any
//  purpose with or without fee is hereby granted, provided that the above
//  copyright notice and this permission notice appear in all copies.
//
//  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

import Foundation

/// Splits ssh_config lines the way OpenSSH does. Works on bytes.
@_spi(Testing)
public enum SSHConfigTokenizer {
    private static let space = UInt8(ascii: " ")
    private static let tab = UInt8(ascii: "\t")
    private static let cr = UInt8(ascii: "\r")
    private static let lf = UInt8(ascii: "\n")
    private static let doubleQuote = UInt8(ascii: "\"")
    private static let singleQuote = UInt8(ascii: "'")
    private static let backslash = UInt8(ascii: "\\")
    private static let equals = UInt8(ascii: "=")
    private static let hash = UInt8(ascii: "#")

    /// WHITESPACE in misc.c.
    static func isWhitespace(_ c: UInt8) -> Bool {
        return c == space || c == tab || c == cr || c == lf
    }

    // MARK: - strdelim

    /// A cursor over a line, consumed one token at a time like the `char **` that
    /// strdelim_internal() advances. `remainder` is nil once the C pointer would be NULL.
    public struct Cursor {
        public private(set) var remainder: [UInt8]?

        public init(_ line: [UInt8]) {
            remainder = line
        }

        public init(_ line: String) {
            self.init(Array(line.utf8))
        }

        /// The next token, splitting on whitespace or, with `splitEquals`, a single `=`. A
        /// token may contain a double-quoted part, with the quotes removed. Returns nil at the
        /// end of the line or for an unterminated quote. Follows strdelim_internal().
        public mutating func next(splitEquals: Bool = true) -> [UInt8]? {
            guard let s = remainder else {
                return nil
            }
            guard let idx = s.firstIndex(where: {
                SSHConfigTokenizer.isWhitespace($0) || $0 == doubleQuote || (splitEquals && $0 == equals)
            }) else {
                remainder = nil
                return s
            }

            if s[idx] == doubleQuote {
                // Remove the opening quote and look for the closing one after it.
                var unquoted = s
                unquoted.remove(at: idx)
                guard let close = unquoted[idx...].firstIndex(of: doubleQuote) else {
                    remainder = nil
                    return nil
                }
                let token = Array(unquoted[..<close])
                remainder = Array(unquoted[SSHConfigTokenizer.skippingWhitespace(unquoted, from: close + 1)...])
                return token
            }

            // Allow only one '=' to be skipped.
            let sawEquals = splitEquals && s[idx] == equals
            let token = Array(s[..<idx])
            var p = SSHConfigTokenizer.skippingWhitespace(s, from: idx + 1)
            if splitEquals && p < s.count && s[p] == equals && !sawEquals {
                p = SSHConfigTokenizer.skippingWhitespace(s, from: p + 1)
            }
            remainder = Array(s[p...])
            return token
        }

        public mutating func nextString(splitEquals: Bool = true) -> String? {
            return next(splitEquals: splitEquals).map { String(decoding: $0, as: UTF8.self) }
        }
    }

    /// The index of the first non-whitespace byte at or after `start`.
    static func skippingWhitespace(_ s: [UInt8], from start: Int) -> Int {
        var i = start
        while i < s.count && isWhitespace(s[i]) {
            i += 1
        }
        return i
    }

    // MARK: - argv_split

    /// Splits `s` into arguments, honoring single and double quotes and the escapes `\\`,
    /// `\"`, `\'`, and (outside quotes) `\ `. With `terminateOnComment`, a `#` that starts an
    /// argument ends the line. Returns nil for an unterminated quote. Follows argv_split().
    public static func splitArguments(_ s: [UInt8], terminateOnComment: Bool) -> [[UInt8]]? {
        var argv = [[UInt8]]()
        var i = 0
        let n = s.count
        while i < n {
            // Skip leading whitespace.
            if s[i] == space || s[i] == tab {
                i += 1
                continue
            }
            if terminateOnComment && s[i] == hash {
                break
            }
            // Start of a token.
            var quote: UInt8 = 0
            var arg = [UInt8]()
            while i < n {
                let c = s[i]
                if c == backslash {
                    let next: UInt8? = i + 1 < n ? s[i + 1] : nil
                    if let next, next == singleQuote || next == doubleQuote || next == backslash ||
                        (quote == 0 && next == space) {
                        i += 1
                        arg.append(next)
                    } else {
                        // Unrecognized escape: keep the backslash.
                        arg.append(c)
                    }
                } else if quote == 0 && (c == space || c == tab) {
                    break
                } else if quote == 0 && (c == doubleQuote || c == singleQuote) {
                    quote = c
                } else if quote != 0 && c == quote {
                    quote = 0
                } else {
                    arg.append(c)
                }
                i += 1
            }
            argv.append(arg)
            if i >= n {
                if quote != 0 {
                    // Ran out of string looking for the closing quote.
                    return nil
                }
                break
            }
            // Step over the whitespace that ended the token.
            i += 1
        }
        return argv
    }

    public static func splitArguments(_ s: String, terminateOnComment: Bool) -> [String]? {
        return splitArguments(Array(s.utf8), terminateOnComment: terminateOnComment)?
            .map { String(decoding: $0, as: UTF8.self) }
    }
}

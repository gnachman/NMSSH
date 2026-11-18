//
//  SSHConfigExpansion.swift
//  NMSSH
//
//  A Swift port of vdollar_percent_expand() from OpenSSH's misc.c (revision 1.223), which
//  expands %-tokens and ${ENVIRONMENT} references in ssh_config values. Derived from OpenSSH;
//  modified from the original by porting it to Swift and taking the environment as a
//  parameter.
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

/// Expands %-tokens and ${VARIABLE} references as ssh_config does.
@_spi(Testing)
public enum SSHConfigExpansion {
    public enum Failure: Error, Equatable {
        /// `${` with no closing `}`.
        case unclosedVariable
        /// `${}`.
        case emptyVariableName
        /// A `%` at the end of the string.
        case trailingPercent
        /// A `%` followed by a character that isn't a known token.
        case unknownToken(Character)
        /// A referenced environment variable isn't set. OpenSSH reports this separately from
        /// the others, which it calls parse errors.
        case missingVariable(String)

        /// Whether OpenSSH would set `*parseerror` for this failure.
        public var isParseError: Bool {
            if case .missingVariable = self {
                return false
            }
            return true
        }
    }

    private static let percent = UInt8(ascii: "%")
    private static let dollar = UInt8(ascii: "$")
    private static let openBrace = UInt8(ascii: "{")
    private static let closeBrace = UInt8(ascii: "}")

    /// Expands `string`. With `percentTokens`, each `%c` is replaced by the value whose key
    /// contains `c`, and `%%` becomes `%`; a nil `percentTokens` leaves `%` alone. With
    /// `environment`, each `${NAME}` is replaced by that variable; a nil `environment` leaves
    /// `$` alone. Follows vdollar_percent_expand().
    ///
    /// As in OpenSSH, a missing variable doesn't stop the scan, so a later parse error is
    /// still reported in preference to it.
    public static func expand(_ string: String,
                              percentTokens: KeyValuePairs<String, String>? = nil,
                              environment: [String: String]? = nil) -> Result<String, Failure> {
        let s = Array(string.utf8)
        var out = [UInt8]()
        var missing: String?
        var i = 0
        while i < s.count {
            if let environment, s[i] == dollar, i + 1 < s.count, s[i + 1] == openBrace {
                let nameStart = i + 2
                guard let close = s[nameStart...].firstIndex(of: closeBrace) else {
                    return .failure(.unclosedVariable)
                }
                if close == nameStart {
                    return .failure(.emptyVariableName)
                }
                let name = String(decoding: s[nameStart..<close], as: UTF8.self)
                if let value = environment[name] {
                    out.append(contentsOf: value.utf8)
                } else if missing == nil {
                    missing = name
                }
                i = close + 1
                continue
            }

            guard let percentTokens, s[i] == percent else {
                out.append(s[i])
                i += 1
                continue
            }
            i += 1
            if i >= s.count {
                return .failure(.trailingPercent)
            }
            if s[i] == percent {
                out.append(percent)
                i += 1
                continue
            }
            let token = s[i]
            guard let replacement = percentTokens.first(where: { $0.key.utf8.contains(token) })?.value else {
                return .failure(.unknownToken(Character(Unicode.Scalar(token))))
            }
            out.append(contentsOf: replacement.utf8)
            i += 1
        }
        if let missing {
            return .failure(.missingVariable(missing))
        }
        return .success(String(decoding: out, as: UTF8.self))
    }
}

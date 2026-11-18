//
//  SSHConfigPattern.swift
//  NMSSH
//
//  A Swift port of the wildcard matching in OpenSSH's match.c (revision 1.46), used to match
//  Host and Match patterns in ssh_config. Derived from OpenSSH; modified from the original by
//  porting it to Swift. Function-level comments name the upstream function each part follows.
//
//  Original notices from match.c:
//
//  Author: Tatu Ylonen <ylo@cs.hut.fi>
//  Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
//                     All rights reserved
//  Simple pattern matching, with '*' and '?' as wildcards.
//
//  As far as I am concerned, the code I have written for this software
//  can be used freely for any purpose.  Any derived versions of this
//  software must be clearly marked as such, and if the derived work is
//  incompatible with the protocol description in the RFC file, it must be
//  called by a name other than "ssh" or "Secure Shell".
//
//  Copyright (c) 2000 Markus Friedl.  All rights reserved.
//  Copyright (c) 2026 Damien Miller.  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//  1. Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//  2. Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
//  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
//  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
//  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
//  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
//  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

import Foundation

/// Wildcard matching as ssh_config does it. Everything works on bytes, as OpenSSH does, so
/// case folding is ASCII-only.
@_spi(Testing)
public enum SSHConfigPattern {
    /// The result of matching against a comma-separated pattern list.
    public enum ListMatch: Equatable {
        /// A negated subpattern matched. This wins over any positive match.
        case negative
        /// No subpattern matched.
        case none
        /// A non-negated subpattern matched and no negated one did.
        case positive
    }

    private static let star = UInt8(ascii: "*")
    private static let question = UInt8(ascii: "?")
    private static let bang = UInt8(ascii: "!")
    private static let comma = UInt8(ascii: ",")

    /// The longest subpattern match_pattern_list accepts, from the size of its `sub` buffer
    /// less the terminating NUL. A longer one never matches.
    private static let maximumSubpatternLength = 1023

    // MARK: - match_pattern

    /// Whether `string` matches `pattern`, where `*` matches any run of characters and `?`
    /// matches any one. Follows match_pattern(), which simulates an NFA with one state per
    /// pattern character plus an accepting state.
    public static func matches(_ string: [UInt8], pattern: [UInt8]) -> Bool {
        let m = pattern.count
        if m == 0 {
            return string.isEmpty
        }
        var states = [Bool](repeating: false, count: m + 1)
        var nextStates = states
        states[0] = true
        epsilonClosure(&states, pattern: pattern)

        for c in string {
            for i in 0...m {
                nextStates[i] = false
            }
            for i in 0..<m where states[i] {
                if pattern[i] == star {
                    // '*' matches any character, so stay in state i.
                    nextStates[i] = true
                } else if pattern[i] == question || pattern[i] == c {
                    nextStates[i + 1] = true
                }
            }
            epsilonClosure(&nextStates, pattern: pattern)
            swap(&states, &nextStates)
            if !states.contains(true) {
                return false
            }
        }
        return states[m]
    }

    /// Follows epsilon_closure(): from an active '*' state you can move to the next state
    /// without consuming input. A single forward pass suffices because the grammar has no
    /// backward jumps.
    private static func epsilonClosure(_ states: inout [Bool], pattern: [UInt8]) {
        for i in 0..<pattern.count where states[i] && pattern[i] == star {
            states[i + 1] = true
        }
    }

    public static func matches(_ string: String, pattern: String) -> Bool {
        return matches(Array(string.utf8), pattern: Array(pattern.utf8))
    }

    // MARK: - match_pattern_list

    /// Matches `string` against a comma-separated list of subpatterns, each optionally preceded
    /// by `!` to negate it. With `lowercasePattern`, ASCII letters in the pattern (not the
    /// string) are lowercased first. Follows match_pattern_list().
    public static func matchesList(_ string: [UInt8],
                                   patternList pattern: [UInt8],
                                   lowercasePattern: Bool) -> ListMatch {
        var gotPositive = false
        var i = 0
        let len = pattern.count
        while i < len {
            let negated = pattern[i] == bang
            if negated {
                i += 1
            }
            var sub = [UInt8]()
            while i < len && sub.count < maximumSubpatternLength && pattern[i] != comma {
                sub.append(lowercasePattern ? asciiLowercased(pattern[i]) : pattern[i])
                i += 1
            }
            if sub.count >= maximumSubpatternLength {
                return .none
            }
            if i < len && pattern[i] == comma {
                i += 1
            }
            if matches(string, pattern: sub) {
                if negated {
                    return .negative
                }
                gotPositive = true
            }
        }
        return gotPositive ? .positive : .none
    }

    public static func matchesList(_ string: String,
                                   patternList: String,
                                   lowercasePattern: Bool) -> ListMatch {
        return matchesList(Array(string.utf8),
                           patternList: Array(patternList.utf8),
                           lowercasePattern: lowercasePattern)
    }

    // MARK: - match_hostname

    /// Matches a host name against a pattern list, ignoring ASCII case on both sides. Follows
    /// match_hostname().
    public static func matchesHostname(_ host: String, patternList: String) -> ListMatch {
        return matchesList(Array(host.utf8).map(asciiLowercased),
                           patternList: Array(patternList.utf8),
                           lowercasePattern: true)
    }

    // MARK: - Helpers

    /// tolower() in the C locale.
    static func asciiLowercased(_ c: UInt8) -> UInt8 {
        if c >= UInt8(ascii: "A") && c <= UInt8(ascii: "Z") {
            return c + 32
        }
        return c
    }
}

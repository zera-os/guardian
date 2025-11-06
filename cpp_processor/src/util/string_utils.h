#pragma once

#include <string>

// Normalizes a string by:
//  - removing zero-width and BOM characters (U+200B/200C/200D, U+FEFF)
//  - converting non-breaking spaces (U+00A0) to regular spaces
//  - converting tabs/newlines to spaces
//  - collapsing consecutive whitespace to a single space
//  - trimming leading/trailing whitespace
std::string sanitize_string(const std::string &input);



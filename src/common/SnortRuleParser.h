 /*
 * Copyright (C) 2017 Felix Erlacher
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
//TODO
//convert more than the first 128 ascii character (minus nonprintable chars)

#ifndef SNORTRULEPARSER_H_
#define SNORTRULEPARSER_H_

    #include <iostream>
    #include <fstream>
    #include <string>
    #include <stdlib.h>
    #include <stdint.h>
    #include <vector>
    #include "common/msg.h"

class SnortRuleParser
{
public:

    SnortRuleParser();
    ~SnortRuleParser();

    class ruleBody{
        public:
        std::string msg;
        std::vector<bool> negatedContent;
        std::vector<std::string> contentOriginal;
        std::vector<bool> containsHex;
        std::vector<bool> contentNocase;
        std::vector<std::string> content;
        std::vector<std::string> contentModifierHTTP;
        std::vector<std::string> pcre;
        std::vector<bool> negatedPcre;
        std::string sid;
        std::string rev;
    };

    class snortRule {
        public:
        std::string header;
        SnortRuleParser::ruleBody body;
    };

std::vector<SnortRuleParser::snortRule> parseMe(const char* fileName);
void printSnortRule(SnortRuleParser::snortRule* rule);
void compareVectorSizes(SnortRuleParser::snortRule* rule);


};

#endif /*SNORTRULEPARSER_H_*/

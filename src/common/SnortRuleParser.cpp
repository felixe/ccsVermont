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
 *
 * Reads Snort rules and puts interesting fields in a struct for further usage.
 * This is rather a READER than a parser, as it assumes a basic structure of rules and does not
 * do in-depth checks of structure.
 *
 */

#include "SnortRuleParser.h"
//hardly any rule will use more than 10 content keywords
#define VECTORRESERVE 10

std::size_t bodyStartPosition;

SnortRuleParser::SnortRuleParser(){
}

SnortRuleParser::~SnortRuleParser(){
}

/**
* writes error message to stderr
*/
void parsingError(int line, std::string parsingPart){
    THROWEXCEPTION("SnortRuleParser: Error on line %d of rulesfile, failed to parse %s. This does not seem to be a valid Snort rule. Aborting!",line, parsingPart.c_str());
}

/**
* compares the vector sizes of the vectors in the given rule, if sizes do not match than there is a bug in the parser
*/
void SnortRuleParser::compareVectorSizes(SnortRuleParser::snortRule* rule){
    if(rule->body.content.size()!=rule->body.contentOriginal.size()
    ||rule->body.content.size()!=rule->body.negatedContent.size()
    ||rule->body.content.size()!=rule->body.containsHex.size()
    ||rule->body.content.size()!=rule->body.contentModifierHTTP.size()
    ||rule->body.content.size()!=rule->body.contentNocase.size()
    ||rule->body.negatedPcre.size()!=rule->body.pcre.size()){
    	//fprintf(stderr,"content: %lu, contentOriginal: %lu, negatedContent: %lu, containsHex: %lu, ContentModifierHttp: %lu, contentNocase %d\n",
        //	rule->body.content.size(),rule->body.contentOriginal.size(),rule->body.negatedContent.size(),rule->body.containsHex.size(),rule->body.contentModifierHTTP.size(),
		//  rule->body.contentNocase.size());
        THROWEXCEPTION("SnortRuleParser: There was an error in rule parsing, parsed content vectors do not match in size. This should not have happened. Aborting!");
            }
}

/**
*prints SnortRuleParser::snortRule struct to stdout
*/
void SnortRuleParser::printSnortRule(SnortRuleParser::snortRule* rule){

    //plausability checks:
    compareVectorSizes(rule);

    fprintf(stdout,"Action:\t\t\t\t%s\n",rule->header.action.c_str());
    fprintf(stdout,"Protocol:\t\t\t%s\n",rule->header.protocol.c_str());
    fprintf(stdout,"From:\t\t\t\t%s\n",rule->header.from.c_str());
    fprintf(stdout,"FromPort:\t\t\t%s\n",rule->header.fromPort.c_str());
    fprintf(stdout,"To:\t\t\t\t%s\n",rule->header.to.c_str());
    fprintf(stdout,"ToPort:\t\t\t\t%s\n",rule->header.toPort.c_str());
    if(rule->header.bidirectional){
    	fprintf(stdout,"Direction:\t\t\t<>\n");
    }else{
    	fprintf(stdout,"Direction:\t\t\t->\n");
    }

    fprintf(stdout,"Message:\t\t\t%s\n",rule->body.msg.c_str());

    //loop through content related vectors
    for(unsigned long i=0;i<rule->body.content.size();i++){
        if(rule->body.negatedContent[i]==true){
            fprintf(stdout,"NOT ");
        }
        //fprintf(stdout,"ContentOriginal:\t%s\n",rule->body.contentOriginal[i].c_str());
        if(rule->body.containsHex[i]==true){
            fprintf(stdout,"Content (hex converted):\t%s\n",rule->body.content[i].c_str());
        }else{
            fprintf(stdout,"Content:\t\t\t\"%s\"\n",rule->body.content[i].c_str());
        }
        fprintf(stdout,"ContentModifierHttp:\t\t%s\n",rule->body.contentModifierHTTP[i].c_str());
        if(rule->body.contentNocase[i]==true){
            fprintf(stdout,"Nocase:\t\t\t\ttrue\n");
        }else{
            fprintf(stdout,"Nocase:\t\t\t\tfalse\n");
        }
    }

    //loop through pcre related vectors
    for(unsigned long j=0;j<rule->body.pcre.size();j++){
        if(rule->body.negatedPcre[j]==true){
            fprintf(stdout,"NOT ");
        }
        fprintf(stdout,"pcre:\t\t\t\t%s\n",rule->body.pcre[j].c_str());
    }

    fprintf(stdout,"Sid:\t\t\t\t%s\n",rule->body.sid.c_str());
    fprintf(stdout,"Sid rev:\t\t\t%s\n",rule->body.rev.c_str());
    fprintf(stdout,"\n");
}

/**
* returns a string of x Xs
*/
std::string xtimesx(int x){
    std::string returnString="";
    for(int i=0;i<x;i++){
        returnString=returnString+"X";
    }
    return(returnString);
}

/**
*   replaces escaped chars in given text
*   according to the snort manual only 3 chars have to be escaped inside a content rule: ;,",\
*/
std::string replaceEscapedChars(std::string* text){
    std::string returnString;
    std::size_t startPosition;

    returnString=*text;

    //first replace escaped backslash(\\)
    startPosition=returnString.find("\\");
    while(startPosition!=std::string::npos){
        returnString.replace(startPosition,2,"XX");
        startPosition=returnString.find("\\");
    }

    //replace escaped quotes(\")
    startPosition=returnString.find("\\\"");
    while(startPosition!=std::string::npos){
        returnString.replace(startPosition,2,"XX");
        startPosition=returnString.find("\\\"");
    }

    //replace escaped semicolon(\;)
    startPosition=returnString.find("\\;");
    while(startPosition!=std::string::npos){
        returnString.replace(startPosition,2,"XX");
        startPosition=returnString.find("\\;");
    }

    return returnString;
}

/**
* This function replaces everything in quotes of the given string with Xs, this includes also escaped characters
* this can be used in keyword search to avoid finding keywords in escaped strings
*/
std::string replaceQuotedText(std::string* quotedText){
    std::size_t startPosition;
    std::size_t endPosition;
    std::string quotedTextReplaced;

    //replace all escaped chars
    quotedTextReplaced=replaceEscapedChars(quotedText);

    //replace everything else that is quoted
    startPosition=std::string::npos;
    startPosition=quotedTextReplaced.find("\"",0);
    endPosition=quotedTextReplaced.find("\"",startPosition+1);
    while(startPosition!=std::string::npos&&endPosition!=std::string::npos){
        quotedTextReplaced.replace(startPosition,endPosition-startPosition+1,xtimesx(endPosition-startPosition+1));
        startPosition=quotedTextReplaced.find("\"",0);
        endPosition=quotedTextReplaced.find("\"",startPosition+1);
    }

    return quotedTextReplaced;
}

/**
*parses the rule msg from given line and writes it to given SnortRuleParser::snortRule class
*/
void parseMsg(std::string* line, int* linecounter, SnortRuleParser::snortRule* tempRule){
    std::size_t startPosition=line->find("msg:",0)+4;
    std::size_t endPosition=line->find(";",startPosition);
    if(startPosition==(std::string::npos+4)||endPosition==std::string::npos){
        parsingError(*linecounter,"msg");
    }
    tempRule->body.msg=line->substr(startPosition+1,(endPosition-startPosition)-2);
}

/**
*parses the rule header from given line and writes it to given SnortRuleParser::snortRule class
*/
void parseHeader(std::string* line, int* linecounter, SnortRuleParser::snortRule* tempRule){
    std::string headerString;
    std::string from;
    std::string to;
    std::size_t start;
    std::size_t end;

    start=line->find("(");
    if(start==std::string::npos){
        parsingError(*linecounter, "header");
    }
    headerString=line->substr(0,start);
    end=headerString.find(" ");
    tempRule->header.action=headerString.substr(0,end);
    headerString.erase(0,end+1);

    //TODO: skip rule if it does not apply to tcp
    end=headerString.find(" ");
    tempRule->header.protocol=headerString.substr(0,end);
    headerString.erase(0,end+1);

    end=headerString.find("<>");
    if(end==std::string::npos){
    	end=headerString.find("->");
    	if(end==std::string::npos){
    		parsingError(*linecounter,"header direction sign");
    	}
    	tempRule->header.bidirectional=false;
    }else{
    	tempRule->header.bidirectional=true;
    }


	from=headerString.substr(0,end-1);
	to=headerString.substr(end+3,headerString.size());

	end=from.find(" ");
	if(end==std::string::npos){
		parsingError(*linecounter,"no space between from address and port");
	}
	tempRule->header.from=from.substr(0,end);
	tempRule->header.fromPort=from.substr(end+1,from.size());

	end=to.find(" ");
	if(end==std::string::npos){
		parsingError(*linecounter,"no space between to address and port");
	}
	tempRule->header.to=to.substr(0,end);
	tempRule->header.toPort=to.substr(end+1,from.size());


}

/**
* parses rule content (also multiple contents) from given line and writes it to given tempRule class in the corresponding vector of contents,
* it also converts hex characters to ascii characters, if possible, if not it omits them in the output content
*/
void parseContent(std::string* line, int* linecounter, SnortRuleParser::snortRule* tempRule){
    std::size_t startPosition;
    std::size_t endPosition;
    std::size_t hexStartPosition;
    std::size_t hexEndPosition=0;
    std::string hexContent;
    std::string contentOrig;
    std::string contentHexFree;
    std::string tempContent;
    std::string byte;
    //we have to copy the line because we are messing around with it
    std::string lineCopy=*line;
    //this string is the same as line copy, only quotet text is replaces by X. length is the same!
    std::string lineCopySearch=replaceQuotedText(&lineCopy);
    char tempChar;
    std::size_t tempPosition;
    int contentCounter=0;

    //on the first check there should definitively be at least one content
    startPosition=lineCopySearch.find("content:",bodyStartPosition)+8;
    endPosition=lineCopySearch.find(";",startPosition);
    if(startPosition==(std::string::npos+8)||endPosition==std::string::npos){
        parsingError(*linecounter,"content");
    }

    //loop to detect multiple content keywords, same check as above is repeated, will be true first time for sure, but we dont want to call parsingError the other times
    while(startPosition!=(std::string::npos+8)&&endPosition!=std::string::npos){
        contentHexFree="";
        //check if content is negated BWARE: than also modifiers are negated!!!
        if(lineCopy.substr(startPosition,1)=="!"){
            tempRule->body.negatedContent.push_back(true);
            //cut away negation sign
            lineCopy.erase(startPosition,1);
            lineCopySearch.erase(startPosition,1);
            //because we erase one character, the endPosition moves back on char
            endPosition--;
        }else{
            tempRule->body.negatedContent.push_back(false);
        }

        contentOrig=lineCopy.substr(startPosition,(endPosition-startPosition));
        //cut away quotes
        contentOrig=contentOrig.substr(1,(contentOrig.size()-2));

        //for debug and functionality check purposes write original content
        tempRule->body.contentOriginal.push_back(contentOrig);
        //check if it contains hex
        hexStartPosition=contentOrig.find("|");

        //is checked again below, but necessary here too
        if(hexStartPosition!=std::string::npos||contentOrig.find("|",hexStartPosition+1)!=std::string::npos){
            tempRule->body.containsHex.push_back(1);
            //if it contains hex than add hexfree content before hex content to contentHexFree
            contentHexFree=contentHexFree+contentOrig.substr(0,hexStartPosition);
        }else{
            tempRule->body.containsHex.push_back(0);
            //if it does not contain hex at all add it now to hex free content
            contentHexFree=contentHexFree+contentOrig;
        }
        //find all hex codes and convert them to ascii
        while(hexStartPosition!=std::string::npos){
            hexEndPosition=contentOrig.find("|",hexStartPosition+1);
            if(hexEndPosition==std::string::npos){
                msg(MSG_DEBUG,"content no hex=\t\t\t%s\n\t\t\talready converted content=\t%s",contentOrig.c_str(),contentHexFree.c_str());
                parsingError(*linecounter,"hex content (no termination sign)");
            }
            //copying hex string and cutting off first pipe sign
            hexContent=contentOrig.substr(hexStartPosition+1,(hexEndPosition-hexStartPosition)-1);
            //remove spaces from hex string
            tempPosition=hexContent.find(" ");
            while(tempPosition!=std::string::npos){
                hexContent.erase(tempPosition,1);
                tempPosition=hexContent.find(" ",tempPosition);
            }

            std::string asciiString;
            //transform hex to ascii loop, as it always consumes two chars we have to move over two chars after every loop
            //todo ev. convert line break/line feed hex codes to OS specific signs, convert more than 128 ascii signs
            for (uint16_t i=0;i<(hexContent.length());i=i+2){
                char * pEnd;
                byte = hexContent.substr(i,2);
                tempChar=(char) (int)strtol(byte.c_str(), &pEnd, 16);
                if(isprint(tempChar)){
                    asciiString.push_back(tempChar);
                }//if not printable ignore char
            }
            //adding converted string to content
            contentHexFree=contentHexFree+asciiString;
            //content now does not contain previous hex anymore, but may contain pipe sign if converted from hex
            hexStartPosition=contentOrig.find("|",hexEndPosition+1);
            //if more hex, than get content in between last and next hex string
            if(hexStartPosition!=std::string::npos){
                contentHexFree=contentHexFree+contentOrig.substr(hexEndPosition+1,hexStartPosition-hexEndPosition-1);
            //if this was last hex (and here we had at least one hex string) add possible tailing hex free string to content
            }else{
                contentHexFree=contentHexFree+contentOrig.substr(hexEndPosition+1,contentOrig.size()-hexEndPosition+1);
            }
        }//while hex loop
        //add the summed up content to the rule class
        tempRule->body.content.push_back(contentHexFree);
        //erase content keyword, so that loop can find next content keyword or break
        lineCopy.erase(startPosition-8,8);
        //to keep same length do the same for search string
        lineCopySearch.erase(startPosition-8,8);
        startPosition=lineCopySearch.find("content:",bodyStartPosition)+8;
        endPosition=lineCopySearch.find(";",startPosition);
        contentCounter++;
    }//while content loop
}

/**
* parses content modifiers from given line and writes it to given tempRule class in the corresponding vector
* Only nocase and http_content modifier are supported. rawbytes, depth, offset, distance, within, fast_pattern are ignored by the parser.
*/
void parseContentModifier(std::string* line, int* linecounter, SnortRuleParser::snortRule* tempRule){
    std::size_t startPosition;
    std::size_t endPosition;
    std::size_t contentEndPosition;
    std::size_t httpModifierStartPosition;
    std::size_t httpModifierEndPosition;
    std::string temp;
    std::string allModifiers;
    //we have to copy the line because we are messing around with it
    std::string lineCopy=*line;
    //this string is the same as lineCopy, only quotet text is replaces by X. length is the same. this way, searches dont trigger falsely on content found in quotes
    std::string lineCopySearch=replaceQuotedText(&lineCopy);

    //on the first check there should definitively be at least on content
    startPosition=lineCopySearch.find("content:",bodyStartPosition)+8;
    endPosition=lineCopySearch.find("content:",startPosition);
    //for last content in rule the end is marked by the closing bracket of the rule body
    if(endPosition==std::string::npos){
        //do we have a +1 error here because of semicolon AND parentheses? No, because rule requires sid and rev keywords, and they are places after modifiers
        endPosition=(lineCopySearch.find(";)",startPosition));
    }

    if(startPosition==(std::string::npos+8)||endPosition==std::string::npos){
        parsingError(*linecounter,"content (modifier)");
    }

    //loop to detect multiple content keywords, same check as above is repeated, will be true first time for sure, but we dont want to call parsingError the other times
    while(startPosition!=(std::string::npos+8)&&endPosition!=std::string::npos){
        temp=lineCopy.substr(startPosition,endPosition-startPosition);
        allModifiers=replaceEscapedChars(&temp);
        contentEndPosition=allModifiers.find(";");
        if(startPosition==(std::string::npos+8)||endPosition==std::string::npos){
            parsingError(*linecounter,"content (modifier), content string end position");
        }
        //erase content keyword and content pattern
        allModifiers.erase(0,contentEndPosition+1);

        //see if it contains the nocase modifier
        if(allModifiers.find("nocase;")==std::string::npos){
            tempRule->body.contentNocase.push_back(false);
        }else{
            tempRule->body.contentNocase.push_back(true);
            //if yes, than also transform the corresponding content to lowercase, for case insensitive comparison, so we dont have to do that during "flow check runtime"
          //  std::transform(tempRule->body.content[tempRule->body.contentNocase.size()-1].begin(),
          //  tempRule->body.content[tempRule->body.contentNocase.size()-1].end(),	tempRule->body.content[tempRule->body.contentNocase.size()-1].begin(), ::tolower);
        }

        //find http content modifier:
        httpModifierStartPosition=allModifiers.find("http_");
        if(httpModifierStartPosition==std::string::npos){
            tempRule->body.contentModifierHTTP.push_back("");
        }else{
            httpModifierEndPosition=allModifiers.find(";",httpModifierStartPosition);
            if(httpModifierEndPosition==std::string::npos){
                parsingError(*linecounter,"content (modifier), content httpModifier end position");
            }
            tempRule->body.contentModifierHTTP.push_back(allModifiers.substr(httpModifierStartPosition,(httpModifierEndPosition-httpModifierStartPosition)));
        }

        //erase content keyword and content string, so that next content can be found
        lineCopy.erase(startPosition-8,+8);
        lineCopySearch.erase(startPosition-8,+8);

        startPosition=lineCopySearch.find("content:",bodyStartPosition)+8;
        endPosition=lineCopySearch.find("content:",startPosition);
        //for last content in rule the end is marked by the closing bracket of the rule body
        if(endPosition==std::string::npos){
            endPosition=(lineCopy.find(";)",startPosition))+1;
        }
    }
}

/**
* parses pcre patterns in given line and writes it to given tempRule class in the corresponding vector
* TODO:at the moment pcre patterns are ignored during detection.
*/
void parsePcre(std::string* line, int* linecounter, SnortRuleParser::snortRule* tempRule){
    std::size_t startPosition;
    std::size_t endPosition;
    //we have to copy the line because we are messing around with it
    std::string lineCopy=*line;
    //this string is the same as line copy, only quotet text is replaces by X. length is the same!
    std::string lineCopySearch=replaceQuotedText(&lineCopy);
    std::string pcreString;

    //on the first check there should definitively be at least on content
    startPosition=lineCopySearch.find("pcre:",bodyStartPosition)+5;
    endPosition=lineCopySearch.find(";",startPosition);

    if(startPosition==(std::string::npos+5)||endPosition==std::string::npos){
        tempRule->body.pcre.push_back("");
        tempRule->body.negatedPcre.push_back(false);
        return;
    }

    //loop to detect multiple pcre keywords, same check as above is repeated, will be true first time for sure, but we dont want to call parsingError the other times
    while(startPosition!=(std::string::npos+5)&&endPosition!=std::string::npos){
        if(lineCopy.substr(startPosition,1)=="!"){
            tempRule->body.negatedPcre.push_back(true);
            //erase negation sign
            lineCopy.erase(startPosition,1);
            lineCopySearch.erase(startPosition,1);
            //adjust endPosition
            endPosition--;
        }else{
            tempRule->body.negatedPcre.push_back(false);
        }
        //copying pcre string and cutting off quotes
        pcreString=lineCopy.substr(startPosition+1,endPosition-startPosition-2);
        tempRule->body.pcre.push_back(pcreString);

        //erase pcre keyword from line so that we can move on to next line
        lineCopy.erase(startPosition-5,5);
        lineCopySearch.erase(startPosition-5,5);
        startPosition=lineCopySearch.find("pcre:",bodyStartPosition)+5;
        endPosition=lineCopySearch.find(";",startPosition);
    }

}
/**
* parses SID and SID rev. number from given line and writes it to given SnortRuleParser::snortRule struct
*/
void parseSid(std::string* line, int* linecounter, SnortRuleParser::snortRule* tempRule){
                std::string lineCopy=replaceQuotedText(line);
                std::size_t startPosition=lineCopy.find("sid:",bodyStartPosition)+4;
                std::size_t endPosition=lineCopy.find(';',startPosition);
                if(startPosition==3||endPosition==std::string::npos){
                    parsingError(*linecounter,"SID");
                }
                tempRule->body.sid=lineCopy.substr(startPosition,(endPosition-startPosition));

                //parse rev following SID
                startPosition=lineCopy.find("rev:",startPosition)+4;
                endPosition=lineCopy.find(';',startPosition);
                if(startPosition==3||endPosition==std::string::npos){
                    parsingError(*linecounter,"SID revision");
                }
                tempRule->body.rev=lineCopy.substr(startPosition,(endPosition-startPosition));
}

/**
*   start function to parse file in filenName (containing Snort rules)
*/
std::vector<SnortRuleParser::snortRule> SnortRuleParser::parseMe(const char* fileName) {
    std::vector<SnortRuleParser::snortRule> rulesFromFile;
    std::string line;
    int linecounter=0;
    std::size_t alertPosition;
    std::size_t contentPosition;
    std::size_t pcrePosition;
    std::ifstream ruleFile(fileName);

    if (ruleFile.is_open())
    {
        while(getline(ruleFile,line) )
        {
            SnortRuleParser::snortRule tempRule;

            tempRule.body.content.reserve(VECTORRESERVE);
            tempRule.body.contentOriginal.reserve(VECTORRESERVE);
            tempRule.body.containsHex.reserve(VECTORRESERVE);
            tempRule.body.negatedContent.reserve(VECTORRESERVE);
            tempRule.body.contentModifierHTTP.reserve(VECTORRESERVE);
            tempRule.body.pcre.reserve(VECTORRESERVE);
            tempRule.body.negatedPcre.reserve(VECTORRESERVE);
            linecounter++;
            //check if rule is a comment, if yes-> ignore
            if(line.substr(0,1)!="#"){
                //check if rule is alert and if it contains content keyword, almost all rules do and if not it is not interesting for us
                alertPosition=line.substr(0,6).find("alert");
                contentPosition=line.find("content:");
                pcrePosition=line.find("pcre:");
                if(alertPosition==std::string::npos||(contentPosition==std::string::npos&&pcrePosition==std::string::npos)){
                    msg(MSG_DEBUG, "SnortRuleParser: Rule in line number %d, does not contain alert or content/pcre keyword. Continuing with next line.",linecounter);
                }else{
                    parseHeader(&line,&linecounter,&tempRule);
                    parseMsg(&line,&linecounter,&tempRule);
                    if(contentPosition!=std::string::npos){
                        parseContent(&line, &linecounter,&tempRule);
                        parseContentModifier(&line, &linecounter,&tempRule);
                    }
                    if(pcrePosition!=std::string::npos){
                        parsePcre(&line, &linecounter,&tempRule);
                    }
                    parseSid(&line, &linecounter,&tempRule);
                    //printSnortRule(&tempRule);
                    rulesFromFile.push_back(tempRule);
                }
            }
    }
    }else{
        THROWEXCEPTION("snortRuleparser; Unable to open rules file");
    }
  return rulesFromFile;
}

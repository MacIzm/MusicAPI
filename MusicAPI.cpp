//
//  MusicAPI.cpp
//  MusicAPI
//
//  Created by Cedrick Ilo on 11/30/21.
//

#include "MusicAPI.hpp"

#include <cstdlib>
#include <cerrno>
#include <ctime>
#include <fstream>
#include <iostream>



#include <string.h>

#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>
#include <curlpp/Exception.hpp>
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>

//GETTER & SETTERS

std::string  MusicAPI::GetToken(){
    return token;
}

std::string MusicAPI::GetSpotifyToken(){
    return spotifyToken;
}

std::string MusicAPI::GetResponse(){
    return response;
}

void MusicAPI::SetToken(std::string t){
    this->token = t;
}

void MusicAPI::SetSpotifyToken(std::string t)
{
    this->spotifyToken = t;
}

void MusicAPI::SetResponse(std::string r){
    this->response = r;
}


//-----------------------------------


//UTILITY FUNC

const char PADDING_CHAR = '=';
const char* ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const uint8_t DECODED_ALPHBET[128]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,62,0,0,0,63,52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,0,0,0,0,0};

/**
 * Given a string, this function will encode it in 64b (with padding)
 */
std::string encodeBase64(const std::string& binaryText)
{
    std::string encoded((binaryText.size()/3 + (binaryText.size()%3 > 0)) << 2, PADDING_CHAR);

    const char* bytes = binaryText.data();
    union
    {
        uint32_t temp = 0;
        struct
        {
            uint32_t first : 6, second : 6, third : 6, fourth : 6;
        } tempBytes;
    };
    std::string::iterator currEncoding = encoded.begin();

    for(uint32_t i = 0, lim = binaryText.size() / 3; i < lim; ++i, bytes+=3)
    {
        temp = bytes[0] << 16 | bytes[1] << 8 | bytes[2];
        (*currEncoding++) = ALPHABET[tempBytes.fourth];
        (*currEncoding++) = ALPHABET[tempBytes.third];
        (*currEncoding++) = ALPHABET[tempBytes.second];
        (*currEncoding++) = ALPHABET[tempBytes.first];
    }

    switch(binaryText.size() % 3)
    {
    case 1:
        temp = bytes[0] << 16;
        (*currEncoding++) = ALPHABET[tempBytes.fourth];
        (*currEncoding++) = ALPHABET[tempBytes.third];
        break;
    case 2:
        temp = bytes[0] << 16 | bytes[1] << 8;
        (*currEncoding++) = ALPHABET[tempBytes.fourth];
        (*currEncoding++) = ALPHABET[tempBytes.third];
        (*currEncoding++) = ALPHABET[tempBytes.second];
        break;
    }

    return encoded;
}

/**
 * Given a 64b padding-encoded string, this function will decode it.
 */
std::string decodeBase64(const std::string& base64Text)
{
    if( base64Text.empty() )
        return "";

    assert((base64Text.size()&3) == 0 && "The base64 text to be decoded must have a length devisible by 4!");

    uint32_t numPadding =  (*std::prev(base64Text.end(),1) == PADDING_CHAR) + (*std::prev(base64Text.end(),2) == PADDING_CHAR);

    std::string decoded((base64Text.size()*3>>2) - numPadding, '.');

    union
    {
        uint32_t temp;
        char tempBytes[4];
    };
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(base64Text.data());

    std::string::iterator currDecoding = decoded.begin();

    for(uint32_t i = 0, lim = (base64Text.size() >> 2) - (numPadding!=0); i < lim; ++i, bytes+=4)
    {
        temp = DECODED_ALPHBET[bytes[0]] << 18 | DECODED_ALPHBET[bytes[1]] << 12 | DECODED_ALPHBET[bytes[2]] << 6 | DECODED_ALPHBET[bytes[3]];
        (*currDecoding++) = tempBytes[2];
        (*currDecoding++) = tempBytes[1];
        (*currDecoding++) = tempBytes[0];
    }

    switch (numPadding)
    {
    case 2:
        temp = DECODED_ALPHBET[bytes[0]] << 18 | DECODED_ALPHBET[bytes[1]] << 12;
        (*currDecoding++) = tempBytes[2];
        break;
    
    case 1:
        temp = DECODED_ALPHBET[bytes[0]] << 18 | DECODED_ALPHBET[bytes[1]] << 12 | DECODED_ALPHBET[bytes[2]] << 6;
        (*currDecoding++) = tempBytes[2];
        (*currDecoding++) = tempBytes[1];
        break;
    }

    return decoded;
}

std::string GetPrivateKey(){
    std::stringstream ss;
    
    std::ifstream file("AuthKey.p8", std::ios::binary);
    if(file)
        ss << file.rdbuf();
//    std::cout << "File str: " << ss.str() << "\n";
        
    return ss.str();
}

void MusicAPI::CreateJWToken()
{
    auto token = jwt::create()

        .set_algorithm("ES256")
        .set_key_id(kid_ID)
        .set_payload_claim("iss", jwt::claim((std::string)apple_TeamID))
        .set_issued_at(std::chrono::system_clock::now())
        .sign(jwt::algorithm::es256("",GetPrivateKey(),"",""));
    
    SetToken(token);
}

void MusicAPI::DecodeToken(std::string token){
    auto decoded = jwt::decode(token);

    for(auto& e : decoded.get_payload_claims())
        std::cout << e.first << " = " << e.second << std::endl;
    
    std::cout << std::endl;
}

void MusicAPI::VerifyToken()
{
    auto verifier = jwt::verify()
        .allow_algorithm(jwt::algorithm::es256("",GetPrivateKey(),"",""))
        .with_issuer(apple_TeamID);

    verifier.verify(jwt::decode(GetToken()));
    
}

void MusicAPI::PrintToken()
{
    std::cout<< "Token: " << GetToken() << std::endl;
}


// --------------------------------------------------


void MusicAPI::GetPlaylist() {
    
    SetResponse("");
    try{
        curlpp::Cleanup clean;
        curlpp::Easy request;
        
//        request.setOpt(new curlpp::options::Url((std::string)appleEndpoint + "/catalog/us/albums/310730204"));
//        request.setOpt(new curlpp::options::Url((std::string)appleEndpoint + "/me/library-albums"));
        request.setOpt(new curlpp::options::Url((std::string)appleEndpoint + "/catalog/us/artists/178834/albums"));
        request.setOpt(new curlpp::options::Verbose(true));
        
        CreateJWToken();
        PrintToken();
        VerifyToken();
        DecodeToken(GetToken());
        
        std::list<std::string> header;
        header.push_back("Content-Type: application/octet-stream");
        header.push_back("Authorization: Bearer " + GetToken());
        
        std::ostringstream r;
        request.setOpt(new curlpp::options::WriteStream(&r));
        
        request.perform();
        
//        auto j = nlohmann::json::parse(r.str());
        
        SetResponse(r.str());
        std::cout << "Resposne: " << GetResponse() << "\n";
//        std::cout << "Output: " << j["data"][0] << "\n";
        
    }
    catch(curlpp::LogicError & e)
    {
        std::cout << e.what() << std::endl;
    }
    catch(curlpp::RuntimeError & e){
        std::cout << e.what() << std::endl;
    }
    
}

void MusicAPI::GenerateSpotifyToken(){
    
    SetResponse("");
    try{
        curlpp::Cleanup clean;
        curlpp::Easy request;

        request.setOpt(new curlpp::options::Url((std::string)spotifyEndpoint + "/api/token"));
        request.setOpt(new curlpp::options::Verbose(true));
        
        std::list<std::string> header;
        std::string auth = (std::string)spotify_clientID + ':' + (std::string)spotify_secretID;
        header.push_back("Accept: application/json");
        header.push_back("Authorization: Basic " + encodeBase64(auth));
        header.push_back("Content-Type: application/x-www-form-urlencoded");
        request.setOpt(new curlpp::options::HttpHeader(header));
        
//        std::cout<< encodeBase64(auth) << "\n";
//        std::cout<< decodeBase64(encodeBase64(auth)) << "\n";
        
        curlpp::Forms postForm;
        postForm.push_back(new curlpp::FormParts::Content("grant_type","client_credentials"));
        request.setOpt(new curlpp::options::HttpPost(postForm));
        
        std::ostringstream r;
        request.setOpt(new curlpp::options::WriteStream(&r));
        
        request.perform();
        
//        auto j = nlohmann::json::parse(r.str());
        SetResponse(r.str());
        
        std::cout << "Response: " << GetResponse() << "\n";
//        std::cout << "Output: " << j["data"][0] << "\n";
    }
    catch(curlpp::LogicError & e)
    {
        std::cout << e.what() << std::endl;
    }
    catch(curlpp::RuntimeError & e){
        std::cout << e.what() << std::endl;
    }
}

//
//  AppleMusicAPI.hpp
//  MusicAPI
//
//  Created by Cedrick Ilo on 11/30/21.
//

#ifndef MusicAPI_hpp
#define MusicAPI_hpp

#include <stdio.h>
#include "SHA256.hpp"

#include <sstream>

using namespace std;

class MusicAPI {
    
    std::string token;
    std::string spotifyToken;
    std::string response;
    char const *kid_ID = "";
    char const  *apple_TeamID = "";
    
    char const *spotify_clientID = "";
    char const *spotify_secretID = "";
    
    
    char const *appleEndpoint = "https://api.music.apple.com/v1";
    char const *spotifyEndpoint = "https://accounts.spotify.com";
                                 
    
    char const *testURL = "https://api.music.apple.com/v1/storefronts/us";

    
    
    void CreateJWToken();
    void DecodeToken(std::string);
    void VerifyToken();
    void PrintToken();
    
public:
    
    void GetPlaylist();
    void GenerateSpotifyToken();
    
    
    std::string GetToken();
    std::string GetSpotifyToken();
    std::string GetResponse();
    void SetResponse(std::string);
    void SetToken(std::string);
    void SetSpotifyToken(std::string);
    
};

#endif /* AppleMusicAPI_hpp */
